package server

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"ezsni/internal/ghdl"
	"fmt"
	"io"
	"net/http"
	neturl "net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"encoding/base64"
	"ezsni/internal/desync"

	"github.com/skip2/go-qrcode"

	"ezsni/internal/edgetunnel"
	"ezsni/internal/gtunnel"
	"ezsni/internal/mitmdf"
	"ezsni/internal/netutil"
	"ezsni/internal/proxy"
	"ezsni/internal/psiphon"
	"ezsni/internal/singbox"
	"ezsni/internal/sni"
	"ezsni/internal/splus"
	"ezsni/internal/sysproxy"
	"ezsni/internal/tor"
	"ezsni/internal/tun2socks"
	"ezsni/internal/windivert"
	"ezsni/internal/xray"
)

// ---- URI parser -----------------------------------------------------------

func (s *Server) handleParseURI(body json.RawMessage) (any, error) {
	var req struct {
		URI string `json:"uri"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, err
	}
	res := sni.ParseURI(req.URI)
	if res.Valid {
		s.log("Parsed "+res.Protocol+" → "+res.Host+" (SNI "+res.SNI+")", "OK")
	} else {
		s.log("URI parse failed: "+res.Error, "ERROR")
	}
	return res, nil
}

// ---- single SNI scan ------------------------------------------------------

func (s *Server) handleSNIScan(body json.RawMessage) (any, error) {
	var req struct {
		Host    string `json:"host"`
		Port    int    `json:"port"`
		Timeout int    `json:"timeout"` // seconds
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, err
	}
	if req.Host == "" {
		return nil, errors.New("host required")
	}
	if req.Port == 0 {
		req.Port = 443
	}
	s.log("Testing SNI "+req.Host+"…", "ACCENT")
	res := sni.CheckSNI(req.Host, req.Port, timeoutOf(req.Timeout, 5))
	if res.OK {
		s.log("✓ "+req.Host+" reachable ("+strconv.Itoa(res.Latency)+" ms)", "OK")
	} else {
		s.log("✗ "+req.Host+" failed: "+res.Error, "ERROR")
	}
	return res, nil
}

// ---- relay test -----------------------------------------------------------

func (s *Server) handleRelayTest(body json.RawMessage) (any, error) {
	var req struct {
		ConnectIP   string `json:"connect_ip"`
		ConnectPort int    `json:"connect_port"`
		FakeSNI     string `json:"fake_sni"`
		Timeout     int    `json:"timeout"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, err
	}
	if req.ConnectIP == "" {
		return nil, errors.New("connect_ip required")
	}
	if req.ConnectPort == 0 {
		req.ConnectPort = 443
	}
	if req.FakeSNI == "" {
		req.FakeSNI = "www.google.com"
	}
	s.log("Relay test → "+req.ConnectIP+" (SNI "+req.FakeSNI+")", "ACCENT")
	res := sni.RelayTest(req.ConnectIP, req.ConnectPort, req.FakeSNI, timeoutOf(req.Timeout, 8))
	if res.OK {
		s.log("✓ relay ok (tcp "+strconv.Itoa(res.TCPMs)+" / tls "+strconv.Itoa(res.TLSMs)+" / relay "+strconv.Itoa(res.RelayMs)+" ms)", "OK")
	} else {
		s.log("✗ relay failed: "+res.Error, "ERROR")
	}
	return res, nil
}

// ---- mass SNI scan --------------------------------------------------------

func (s *Server) handleMassScan(body json.RawMessage) (any, error) {
	var req struct {
		ConnectIP   string `json:"connect_ip"`
		ConnectPort int    `json:"connect_port"`
		SNIs        string `json:"snis"` // newline-separated
		Timeout     int    `json:"timeout"`
		Workers     int    `json:"workers"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, err
	}
	if req.ConnectIP == "" {
		return nil, errors.New("connect_ip required")
	}
	if req.ConnectPort == 0 {
		req.ConnectPort = 443
	}
	names := splitLines(req.SNIs)
	if len(names) == 0 {
		return nil, errors.New("no SNI hostnames provided")
	}
	timeout := timeoutOf(req.Timeout, 5)
	workers := clampWorkers(req.Workers)

	s.log("Mass SNI scan: "+strconv.Itoa(len(names))+" hostnames via "+req.ConnectIP+" ("+strconv.Itoa(workers)+" workers)", "ACCENT")

	results := make([]sni.MassResult, len(names))
	var ok int64
	runPool(len(names), workers, func(i int) {
		results[i] = sni.MassTest(req.ConnectIP, req.ConnectPort, names[i], timeout)
		if results[i].OK {
			atomic.AddInt64(&ok, 1)
			s.log("✓ "+names[i]+" ("+strconv.Itoa(results[i].TotalMs)+" ms)", "OK")
		}
	})
	s.log("Mass scan complete: "+strconv.FormatInt(ok, 10)+"/"+strconv.Itoa(len(names))+" reachable", "ACCENT")
	return map[string]any{"results": results, "ok": ok, "total": len(names)}, nil
}

// ---- Cloudflare IP scan ---------------------------------------------------

func (s *Server) handleCFScan(body json.RawMessage) (any, error) {
	var req struct {
		Ranges  string `json:"ranges"` // newline-separated CIDRs / IPs
		Port    int    `json:"port"`
		SNI     string `json:"sni"`
		Limit   int    `json:"limit"`
		Timeout int    `json:"timeout"`
		Workers int    `json:"workers"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, err
	}
	text := req.Ranges
	if len(splitLines(text)) == 0 {
		text = strings.Join(sni.DefaultCloudflareRanges, "\n")
	}
	ips := sni.ParseIPList(text)
	if len(ips) == 0 {
		return nil, errors.New("no IPs parsed from ranges")
	}
	if req.Limit > 0 && len(ips) > req.Limit {
		ips = ips[:req.Limit]
	}
	if req.Port == 0 {
		req.Port = 443
	}
	if req.SNI == "" {
		req.SNI = "cloudflare.com"
	}
	timeout := timeoutOf(req.Timeout, 3)
	workers := clampWorkers(req.Workers)

	s.log("Cloudflare scan: "+strconv.Itoa(len(ips))+" IPs on :"+strconv.Itoa(req.Port)+" (SNI "+req.SNI+")", "ACCENT")

	results := make([]sni.CFResult, len(ips))
	var ok int64
	runPool(len(ips), workers, func(i int) {
		results[i] = sni.TestIP(ips[i], req.Port, req.SNI, timeout)
		if results[i].OK {
			atomic.AddInt64(&ok, 1)
			s.log("✓ "+ips[i]+" ("+strconv.Itoa(results[i].Latency)+" ms)", "OK")
		}
	})
	s.log("Cloudflare scan complete: "+strconv.FormatInt(ok, 10)+"/"+strconv.Itoa(len(ips))+" working", "ACCENT")
	return map[string]any{"results": results, "ok": ok, "total": len(ips)}, nil
}

// ---- proxy control --------------------------------------------------------

func (s *Server) handleProxyStart(body json.RawMessage) (any, error) {
	var req struct {
		ListenHost  string `json:"listen_host"`
		ListenPort  int    `json:"listen_port"`
		ConnectIP   string `json:"connect_ip"`
		ConnectPort int    `json:"connect_port"`
		FakeSNI     string `json:"fake_sni"`
		Mode        string `json:"mode"`
		RealHost    string `json:"real_host"`
		// DPI evasion
		BypassMode     string `json:"bypass_mode"`       // none | wrong_checksum | wrong_seq
		FakeRepeat     int    `json:"fake_repeat"`       // default 1
		FakeDelayMs    int    `json:"fake_delay_ms"`     // default 2
		AckTimeoutMs   int    `json:"ack_timeout_ms"`    // default 2000
		UTLS           string `json:"utls"`              // default firefox
		EnableFragment bool   `json:"enable_fragment"`   // default false
		FragDelayMs    int    `json:"fragment_delay_ms"` // default 500
		SNIChunk       *int   `json:"sni_chunk"`         // default 3; 0 = whole host
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, err
	}
	mode := proxy.Transparent
	switch proxy.Mode(req.Mode) {
	case proxy.Passthrough:
		mode = proxy.Passthrough
	case proxy.CDNFront:
		mode = proxy.CDNFront
	}
	if req.ListenHost == "" {
		req.ListenHost = "127.0.0.1"
	}
	if req.ListenPort == 0 {
		req.ListenPort = 40443
	}
	if req.ConnectPort == 0 {
		req.ConnectPort = 443
	}
	req.RealHost = strings.TrimSpace(req.RealHost)

	// SNI: required-ish for transparent (default it); optional for CDN fronting.
	if req.FakeSNI == "" && mode != proxy.CDNFront {
		req.FakeSNI = "www.google.com"
	}
	sniList := splitLines(req.FakeSNI) // multiple SNIs, one per line, rotated per connection

	// Connect IP: required for transparent/passthrough; optional for CDN
	// fronting, where we can fall back to the front SNI (resolved by DNS) or
	// the real host.
	if req.ConnectIP == "" {
		if mode == proxy.CDNFront {
			switch {
			case len(sniList) > 0:
				req.ConnectIP = sniList[0]
			case req.RealHost != "":
				req.ConnectIP = req.RealHost
			default:
				return nil, errors.New("for CDN fronting set at least one of: connect IP, front SNI, or real host")
			}
		} else {
			return nil, errors.New("connect_ip required")
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.proxy != nil && s.proxy.Running() {
		return nil, errors.New("proxy already running")
	}
	s.proxy = proxy.New(s.bus.Log)
	dc := s.desyncDefaults
	if req.UTLS != "" {
		if !desync.ValidPreset(req.UTLS) {
			return nil, errors.New("unknown -utls preset: " + req.UTLS)
		}
		dc.UTLS = req.UTLS
	}
	switch desync.BypassMode(req.BypassMode) {
	case desync.ModeWrongChecksum:
		dc.Mode = desync.ModeWrongChecksum
	case desync.ModeWrongSeq:
		dc.Mode = desync.ModeWrongSeq
	default:
		dc.Mode = desync.ModeNone
	}
	if req.FakeRepeat > 0 {
		dc.FakeRepeat = req.FakeRepeat
	}
	if req.FakeDelayMs > 0 {
		dc.FakeDelay = time.Duration(req.FakeDelayMs) * time.Millisecond
	}
	if req.AckTimeoutMs > 0 {
		dc.AckTimeout = time.Duration(req.AckTimeoutMs) * time.Millisecond
	}
	if req.FragDelayMs > 0 {
		dc.FragmentDelay = time.Duration(req.FragDelayMs) * time.Millisecond
	}
	if req.SNIChunk != nil {
		dc.SNIChunk = *req.SNIChunk
	}
	dc.EnableFragment = req.EnableFragment

	cfg := proxy.Config{
		ListenHost:  req.ListenHost,
		ListenPort:  req.ListenPort,
		ConnectIP:   req.ConnectIP,
		ConnectPort: req.ConnectPort,
		FakeSNI:     req.FakeSNI,
		SNIList:     sniList,
		RealHost:    strings.TrimSpace(req.RealHost),
		Desync:      dc,
	}
	if err := s.proxy.Start(cfg, mode); err != nil {
		s.log("Proxy start failed: "+err.Error(), "ERROR")
		return nil, err
	}
	return map[string]any{"running": true}, nil
}

func (s *Server) handleProxyStop(json.RawMessage) (any, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.proxy == nil || !s.proxy.Running() {
		return map[string]any{"running": false}, nil
	}
	s.proxy.Stop()
	return map[string]any{"running": false}, nil
}

func (s *Server) handleProxyStatus(json.RawMessage) (any, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	running := s.proxy != nil && s.proxy.Running()
	return map[string]any{"running": running}, nil
}

// ---- SPlus tunnel control -------------------------------------------------

func (s *Server) handleSplusStart(body json.RawMessage) (any, error) {
	var req struct {
		Role      string `json:"role"`
		Token     string `json:"token"`
		URL       string `json:"url"`
		SocksHost string `json:"socks_host"`
		SocksPort int    `json:"socks_port"`
		SocksUser string `json:"socks_user"`
		SocksPass string `json:"socks_pass"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, err
	}
	if strings.TrimSpace(req.Token) == "" {
		return nil, errors.New("token required (extract from the SoroushPlus call)")
	}
	role := splus.RoleClient
	if splus.Role(req.Role) == splus.RoleServer {
		role = splus.RoleServer
	}
	opts := splus.Options{
		Role:      role,
		Token:     strings.TrimSpace(req.Token),
		URL:       strings.TrimSpace(req.URL),
		SocksHost: req.SocksHost,
		SocksPort: req.SocksPort,
		SocksUser: strings.TrimSpace(req.SocksUser),
		SocksPass: req.SocksPass,
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tunnel != nil {
		return nil, errors.New("tunnel already running")
	}
	s.log("Starting SPlus tunnel ("+string(role)+")…", "ACCENT")
	t, err := splus.Start(opts, s.bus.Log)
	if err != nil {
		s.log("SPlus start failed: "+err.Error(), "ERROR")
		return nil, err
	}
	s.tunnel = t
	s.tunOpts = opts
	return map[string]any{"running": true, "role": string(role)}, nil
}

func (s *Server) handleSplusStop(json.RawMessage) (any, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tunnel == nil {
		return map[string]any{"running": false}, nil
	}
	s.tunnel.Stop()
	s.tunnel = nil
	s.log("SPlus tunnel stopped", "WARN")
	return map[string]any{"running": false}, nil
}

func (s *Server) handleSplusStatus(json.RawMessage) (any, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tunnel == nil {
		return map[string]any{"running": false}, nil
	}
	rx, tx := s.tunnel.Stats()
	return map[string]any{
		"running": true,
		"role":    string(s.tunOpts.Role),
		"rx":      rx,
		"tx":      tx,
	}, nil
}

// ---- xray test ------------------------------------------------------------

func (s *Server) handleXrayTest(body json.RawMessage) (any, error) {
	var req struct {
		URI       string `json:"uri"`
		BinPath   string `json:"bin_path"`
		ProxyHost string `json:"proxy_host"`
		ProxyPort int    `json:"proxy_port"`
		Direct    bool   `json:"direct"`
		SocksPort int    `json:"socks_port"`
		TestURL   string `json:"test_url"`
		Timeout   int    `json:"timeout"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, err
	}
	if strings.TrimSpace(req.URI) == "" {
		return nil, errors.New("uri required")
	}
	s.log("Xray test starting…", "ACCENT")
	res := xray.Test(xray.Options{
		URI:        req.URI,
		BinPath:    req.BinPath,
		ProxyHost:  req.ProxyHost,
		ProxyPort:  req.ProxyPort,
		Direct:     req.Direct,
		SocksPort:  req.SocksPort,
		TestURL:    req.TestURL,
		TimeoutSec: req.Timeout,
	}, s.bus.Log)
	if res.OK {
		s.log("✓ Xray test ok — HTTP "+strconv.Itoa(res.HTTPStatus)+" in "+strconv.Itoa(res.ResponseMs)+" ms", "OK")
	} else {
		s.log("✗ Xray test failed: "+res.Error, "ERROR")
	}
	return res, nil
}

func (s *Server) handleXrayMass(body json.RawMessage) (any, error) {
	var req struct {
		URIs          string `json:"uris"`
		BinPath       string `json:"bin_path"`
		TestURL       string `json:"test_url"`
		ProxyHost     string `json:"proxy_host"`
		ProxyPort     int    `json:"proxy_port"`
		Direct        bool   `json:"direct"`
		Timeout       int    `json:"timeout"`
		WithSpeeds    bool   `json:"with_speeds"`
		DownloadBytes int    `json:"download_bytes"`
		UploadBytes   int    `json:"upload_bytes"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, err
	}
	uris := splitLines(req.URIs)
	if len(uris) == 0 {
		return nil, errors.New("paste at least one vless/vmess/trojan/ss URI")
	}
	// When testing through the SNI Tunnel, auto-detect the running tunnel's
	// actual listen address so the user never has to re-type the port. An
	// explicit proxy_port in the request still wins if provided.
	if !req.Direct && req.ProxyPort == 0 {
		s.mu.Lock()
		p := s.proxy
		s.mu.Unlock()
		host, port := "", 0
		if p != nil {
			host, port = p.ListenHostPort()
		}
		if port == 0 {
			return nil, errors.New("SNI Tunnel isn't running — start it first, or tick Direct to test without it")
		}
		if req.ProxyHost == "" {
			req.ProxyHost = host
		}
		req.ProxyPort = port
	}
	via := "SNI tunnel " + req.ProxyHost + ":" + strconv.Itoa(req.ProxyPort)
	if req.Direct {
		via = "direct"
	}
	s.log("Mass URI test (xray, "+via+"): "+strconv.Itoa(len(uris))+" configs → "+req.TestURL, "ACCENT")
	rows, err := xray.MassXray(xray.MassXrayOptions{
		URIs:          uris,
		BinPath:       req.BinPath,
		TestURL:       strings.TrimSpace(req.TestURL),
		ProxyHost:     req.ProxyHost,
		ProxyPort:     req.ProxyPort,
		Direct:        req.Direct,
		TimeoutSec:    req.Timeout,
		WithSpeeds:    req.WithSpeeds,
		DownloadBytes: req.DownloadBytes,
		UploadBytes:   req.UploadBytes,
	}, s.bus.Log)
	if err != nil {
		s.log("✗ "+err.Error(), "ERROR")
		return nil, err
	}
	var ok int
	for _, r := range rows {
		if r.OK {
			ok++
		}
	}
	best := ""
	if len(rows) > 0 && rows[0].OK {
		best = rows[0].URI
		s.log("✓ best config "+rows[0].Name+" ("+strconv.Itoa(rows[0].RelayMs)+" ms)", "OK")
	}
	s.log("Mass URI test complete: "+strconv.Itoa(ok)+"/"+strconv.Itoa(len(rows))+" working", "ACCENT")
	return map[string]any{"results": rows, "ok": ok, "total": len(rows), "best": best}, nil
}

func (s *Server) handleXrayCDNConfigs(body json.RawMessage) (any, error) {
	var req struct {
		URI             string `json:"uri"`
		BinPath         string `json:"bin_path"`
		Ranges          string `json:"ranges"`
		PerRangeLimit   int    `json:"per_range_limit"`
		Ports           []int  `json:"ports"`
		TopForSpeed     int    `json:"top_for_speed"`
		FinalCount      int    `json:"final_count"`
		DownloadBytes   int    `json:"download_bytes"`
		UploadBytes     int    `json:"upload_bytes"`
		PingTimeoutSec  int    `json:"ping_timeout"`
		SpeedTimeoutSec int    `json:"speed_timeout"`
		PingConcurrency int    `json:"ping_concurrency"`
		SpeedConc       int    `json:"speed_concurrency"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, err
	}
	if strings.TrimSpace(req.URI) == "" {
		return nil, errors.New("uri required (a vless/vmess/trojan/ss share link backed by Cloudflare)")
	}

	s.cdnMu.Lock()
	if s.cdnCancel != nil {
		s.cdnMu.Unlock()
		return nil, errors.New("a CDN configs scan is already running — stop it first")
	}
	state := &xray.CDNScanState{StartedAt: time.Now(), Phase: 1}
	ctx, cancel := context.WithCancel(context.Background())
	s.cdn = state
	s.cdnCancel = cancel
	s.cdnMu.Unlock()

	s.log("CDN configs scan starting…", "ACCENT")
	go func() {
		defer func() {
			s.cdnMu.Lock()
			s.cdnCancel = nil
			s.cdnMu.Unlock()
		}()
		_ = xray.TestCDNConfigs(ctx, state, xray.CDNConfigsOptions{
			URI:             req.URI,
			BinPath:         req.BinPath,
			Ranges:          req.Ranges,
			PerRangeLimit:   req.PerRangeLimit,
			Ports:           req.Ports,
			TopForSpeed:     req.TopForSpeed,
			FinalCount:      req.FinalCount,
			DownloadBytes:   req.DownloadBytes,
			UploadBytes:     req.UploadBytes,
			PingTimeoutSec:  req.PingTimeoutSec,
			SpeedTimeoutSec: req.SpeedTimeoutSec,
			PingConcurrency: req.PingConcurrency,
			SpeedConc:       req.SpeedConc,
		}, s.bus.Log)
	}()
	return map[string]any{"ok": true, "running": true}, nil
}

func (s *Server) handleXrayCDNConfigsStatus(json.RawMessage) (any, error) {
	s.cdnMu.Lock()
	state := s.cdn
	s.cdnMu.Unlock()
	if state == nil {
		return map[string]any{"phase": 0, "finished": false, "rows": []any{}}, nil
	}
	return state.Snapshot(), nil
}

func (s *Server) handleXrayCDNConfigsStop(json.RawMessage) (any, error) {
	s.cdnMu.Lock()
	cancel := s.cdnCancel
	s.cdnMu.Unlock()
	if cancel == nil {
		return map[string]any{"running": false}, nil
	}
	cancel()
	s.log("CDN configs scan: stop requested", "WARN")
	return map[string]any{"stopping": true}, nil
}

func (s *Server) handleXrayCDNConfigsPause(json.RawMessage) (any, error) {
	s.cdnMu.Lock()
	state := s.cdn
	s.cdnMu.Unlock()
	if state == nil {
		return map[string]any{"paused": false}, nil
	}
	state.Pause()
	s.log("CDN configs scan: paused", "DIM")
	return map[string]any{"paused": true}, nil
}

func (s *Server) handleXrayCDNConfigsResume(json.RawMessage) (any, error) {
	s.cdnMu.Lock()
	state := s.cdn
	s.cdnMu.Unlock()
	if state == nil {
		return map[string]any{"paused": false}, nil
	}
	state.Resume()
	s.log("CDN configs scan: resumed", "DIM")
	return map[string]any{"paused": false}, nil
}

func (s *Server) handleXrayFind(json.RawMessage) (any, error) {
	p := xray.FindXray()
	return map[string]any{"found": p != "", "path": p}, nil
}

// siteScanState tracks an in-progress site scan for live progress polling.
type siteScanState struct {
	mu        sync.Mutex
	total     int
	done      int
	rows      []sni.CFSiteResult
	finished  bool
	cancelled bool
	reachable int
	cf        int
	started   time.Time
}

func (st *siteScanState) snapshot() map[string]any {
	st.mu.Lock()
	defer st.mu.Unlock()
	rows := make([]sni.CFSiteResult, len(st.rows))
	copy(rows, st.rows)
	return map[string]any{
		"total": st.total, "done": st.done, "rows": rows,
		"finished": st.finished, "cancelled": st.cancelled,
		"reachable": st.reachable, "cf": st.cf,
		"elapsed_ms": time.Since(st.started).Milliseconds(),
	}
}

// handleSitesScan starts an async scan: resolves each domain, measures TLS
// reachability + latency, and flags Cloudflare membership. Progress is polled
// via /api/sites/scan/status.
func (s *Server) handleSitesScan(body json.RawMessage) (any, error) {
	var req struct {
		Domains string `json:"domains"`
		Port    int    `json:"port"`
		Timeout int    `json:"timeout"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, err
	}
	domains := splitLines(req.Domains)
	if len(domains) == 0 {
		return nil, errors.New("paste at least one domain")
	}
	if len(domains) > 1000 {
		domains = domains[:1000]
	}
	port := req.Port
	if port == 0 {
		port = 443
	}
	timeout := timeoutOf(req.Timeout, 6)

	s.siteMu.Lock()
	if s.siteCancel != nil {
		s.siteCancel()
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.siteCancel = cancel
	st := &siteScanState{total: len(domains), started: time.Now()}
	s.site = st
	s.siteMu.Unlock()

	s.log("Site scan: "+strconv.Itoa(len(domains))+" domains (reachability + Cloudflare)", "ACCENT")
	go func() {
		sem := make(chan struct{}, 32)
		var wg sync.WaitGroup
		for _, d := range domains {
			if ctx.Err() != nil {
				break
			}
			wg.Add(1)
			sem <- struct{}{}
			go func(domain string) {
				defer wg.Done()
				defer func() { <-sem }()
				r := sni.CheckCloudflareSite(domain, port, timeout)
				st.mu.Lock()
				st.rows = append(st.rows, r)
				st.done++
				if r.Reachable {
					st.reachable++
				}
				if r.OnCloudflare {
					st.cf++
				}
				st.mu.Unlock()
			}(d)
		}
		wg.Wait()
		st.mu.Lock()
		st.finished = true
		st.cancelled = ctx.Err() != nil
		st.mu.Unlock()
		s.log("Site scan done.", "OK")
	}()
	return map[string]any{"started": true, "total": len(domains)}, nil
}

func (s *Server) handleSitesScanStatus(json.RawMessage) (any, error) {
	s.siteMu.Lock()
	st := s.site
	s.siteMu.Unlock()
	if st == nil {
		return map[string]any{"total": 0, "done": 0, "rows": []any{}, "finished": true}, nil
	}
	return st.snapshot(), nil
}

func (s *Server) handleSitesScanStop(json.RawMessage) (any, error) {
	s.siteMu.Lock()
	if s.siteCancel != nil {
		s.siteCancel()
	}
	s.siteMu.Unlock()
	return map[string]any{"ok": true}, nil
}

// Saved-SNI list persistence (the "Saved SNI list" card in SNI Tunnel).
func (s *Server) handleSavedSNISave(body json.RawMessage) (any, error) {
	if len(body) == 0 || !json.Valid(body) {
		return nil, errors.New("invalid data")
	}
	if err := writeSideFile("v2rayez-saved-sni.json", body); err != nil {
		return nil, err
	}
	return map[string]any{"ok": true}, nil
}

func (s *Server) handleSavedSNILoad(json.RawMessage) (any, error) {
	data, err := readSideFile("v2rayez-saved-sni.json")
	if err != nil || len(data) == 0 || !json.Valid(data) {
		return map[string]any{"found": false, "data": []any{}}, nil
	}
	return map[string]any{"found": true, "data": json.RawMessage(data)}, nil
}

// ---- Google Tunnel (domain-fronted GAS → Worker relay) --------------------

func (s *Server) handleGtunScripts(body json.RawMessage) (any, error) {
	var req struct {
		WorkerURL string `json:"worker_url"`
		AuthKey   string `json:"auth_key"`
	}
	_ = json.Unmarshal(body, &req)
	host := strings.TrimPrefix(strings.TrimPrefix(req.WorkerURL, "https://"), "http://")
	host = strings.TrimSuffix(host, "/")
	return map[string]any{
		"worker_js": gtunnel.GenWorkerJS(host),
		"code_gs":   gtunnel.GenCodeGS(req.AuthKey, req.WorkerURL),
	}, nil
}

func (s *Server) handleGtunStart(body json.RawMessage) (any, error) {
	var req struct {
		FrontIP    string `json:"front_ip"`
		FrontSNI   string `json:"front_sni"`
		FrontHost  string `json:"front_host"`
		ScriptID   string `json:"script_id"`
		AuthKey    string `json:"auth_key"`
		WorkerURL  string `json:"worker_url"`
		ListenHost string `json:"listen_host"`
		ListenPort int    `json:"listen_port"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, err
	}
	err := s.gtun.Start(gtunnel.Config{
		FrontIP: req.FrontIP, FrontSNI: req.FrontSNI, FrontHost: req.FrontHost,
		ScriptID: req.ScriptID, AuthKey: req.AuthKey, WorkerURL: req.WorkerURL,
		ListenHost: req.ListenHost, ListenPort: req.ListenPort,
	})
	if err != nil {
		s.log("✗ Google Tunnel: "+err.Error(), "ERROR")
		return nil, err
	}
	return s.gtun.Status(), nil
}

func (s *Server) handleGtunStop(json.RawMessage) (any, error) {
	s.gtun.Stop()
	return map[string]any{"running": false}, nil
}

func (s *Server) handleGtunStatus(json.RawMessage) (any, error) {
	return s.gtun.Status(), nil
}

// handleGtunCA serves the local MITM CA certificate for the user to install.
func (s *Server) handleGtunCA(w http.ResponseWriter, r *http.Request) {
	pemBytes := s.gtun.CAPEM()
	if len(pemBytes) == 0 {
		http.Error(w, "CA not generated yet — start the Google Tunnel once", http.StatusNotFound)
		return
	}
	// .crt installs with a double-click on Windows; .pem is the same content.
	if r.URL.Query().Get("fmt") == "crt" {
		w.Header().Set("Content-Type", "application/x-x509-ca-cert")
		w.Header().Set("Content-Disposition", "attachment; filename=v2rayez-google-tunnel-ca.crt")
		_, _ = w.Write(pemBytes)
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", "attachment; filename=v2rayez-google-tunnel-ca.pem")
	_, _ = w.Write(pemBytes)
}

// ---- MITM domain-fronting (client-side) -----------------------------------

func (s *Server) handleMitmdfDefaults(json.RawMessage) (any, error) {
	return map[string]any{"rules": mitmdf.DefaultRules()}, nil
}

func (s *Server) handleMitmdfStart(body json.RawMessage) (any, error) {
	var cfg mitmdf.Config
	if err := json.Unmarshal(body, &cfg); err != nil {
		return nil, err
	}
	s.log("Starting MITM domain-fronting proxy…", "ACCENT")
	if err := s.mitmdf.Start(cfg); err != nil {
		s.log("✗ MITM domain-fronting: "+err.Error(), "ERROR")
		return nil, err
	}
	return s.mitmdf.Status(), nil
}

func (s *Server) handleMitmdfStop(json.RawMessage) (any, error) {
	s.mitmdf.Stop()
	return s.mitmdf.Status(), nil
}

func (s *Server) handleMitmdfStatus(json.RawMessage) (any, error) {
	return s.mitmdf.Status(), nil
}

func (s *Server) handleMitmdfCA(w http.ResponseWriter, r *http.Request) {
	pemBytes := s.mitmdf.CAPEM()
	if len(pemBytes) == 0 {
		http.Error(w, "CA not generated yet — start the proxy once", http.StatusNotFound)
		return
	}
	if r.URL.Query().Get("fmt") == "crt" {
		w.Header().Set("Content-Type", "application/x-x509-ca-cert")
		w.Header().Set("Content-Disposition", "attachment; filename=v2rayez-domainfronting-ca.crt")
		_, _ = w.Write(pemBytes)
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", "attachment; filename=v2rayez-domainfronting-ca.pem")
	_, _ = w.Write(pemBytes)
}

func (s *Server) handleXrayUpdateConfigs(body json.RawMessage) (any, error) {
	var req struct {
		Limit int `json:"limit"`
	}
	_ = json.Unmarshal(body, &req)
	if req.Limit <= 0 {
		req.Limit = 300
	}
	s.log("Fetching fresh configs…", "ACCENT")
	cfgs, err := xray.FetchLatestConfigs(req.Limit, s.bus.Log)
	if err != nil {
		s.log("✗ "+err.Error(), "ERROR")
		return nil, err
	}
	return map[string]any{"count": len(cfgs), "configs": cfgs}, nil
}

// handleQR renders the given text as a QR PNG (base64 data URI) for sharing.
func (s *Server) handleQR(body json.RawMessage) (any, error) {
	var req struct {
		Text string `json:"text"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, err
	}
	if strings.TrimSpace(req.Text) == "" {
		return nil, errors.New("text required")
	}
	png, err := qrcode.Encode(req.Text, qrcode.Low, 600)
	if err != nil {
		return nil, err
	}
	return map[string]any{"png": "data:image/png;base64," + base64.StdEncoding.EncodeToString(png)}, nil
}

// ---- Edge Tunnel (Cloudflare Worker VLESS) --------------------------------

func (s *Server) handleEdgeUUID(json.RawMessage) (any, error) {
	return map[string]any{"uuid": edgetunnel.GenUUID()}, nil
}

func (s *Server) handleEdgeGenerate(body json.RawMessage) (any, error) {
	var req struct {
		UUID    string `json:"uuid"`
		Host    string `json:"host"`
		Address string `json:"address"`
		Path    string `json:"path"`
		Name    string `json:"name"`
		Ports   []int  `json:"ports"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, err
	}
	links, err := edgetunnel.Build(edgetunnel.Options{
		UUID: req.UUID, Host: req.Host, Address: req.Address,
		Path: req.Path, Name: req.Name, Ports: req.Ports,
	})
	if err != nil {
		return nil, err
	}
	s.log("Edge Tunnel: generated "+strconv.Itoa(len(links))+" VLESS configs for "+req.Host, "OK")
	return map[string]any{"configs": links, "count": len(links)}, nil
}

// handleSubscribe fetches any subscription URL and returns its share links.
func (s *Server) handleSubscribe(body json.RawMessage) (any, error) {
	var req struct {
		URL   string `json:"url"`
		Limit int    `json:"limit"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, err
	}
	if strings.TrimSpace(req.URL) == "" {
		return nil, errors.New("subscription URL required")
	}
	s.log("Fetching subscription "+req.URL+" …", "ACCENT")
	links, err := xray.FetchSubscription(req.URL, req.Limit)
	if err != nil {
		s.log("✗ "+err.Error(), "ERROR")
		return nil, err
	}
	s.log("Subscription: "+strconv.Itoa(len(links))+" configs", "OK")
	return map[string]any{"configs": links, "count": len(links)}, nil
}

// ---- Config manager persistence (groups of saved configs) -----------------

// handleConfigsFromJSON extracts share links from a pasted/dropped full Xray
// config (a single object or an array — e.g. a BPB "Best Ping" file with many
// proxy outbounds). Returns the convertible vless/trojan links.
func (s *Server) handleConfigsFromJSON(body json.RawMessage) (any, error) {
	var req struct {
		Text  string `json:"text"`
		Limit int    `json:"limit"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, err
	}
	links := xray.JSONConfigsToLinks(req.Text, req.Limit)
	return map[string]any{"configs": links, "count": len(links)}, nil
}

func (s *Server) handleConfigsStoreSave(body json.RawMessage) (any, error) {
	if len(body) == 0 || !json.Valid(body) {
		return nil, errors.New("invalid data")
	}
	dir := configsDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	// Combined store now lives inside the configs/ folder, alongside the
	// per-group files.
	if err := os.WriteFile(filepath.Join(dir, "v2rayez-configs.json"), body, 0o600); err != nil {
		return nil, err
	}
	n, ferr := syncConfigsFolder(body)
	out := map[string]any{"ok": true, "folder": dir, "files": n}
	if ferr != nil {
		out["folder_error"] = ferr.Error()
	}
	return out, nil
}

func (s *Server) handleConfigsStoreLoad(json.RawMessage) (any, error) {
	// Prefer the combined store inside configs/, then the legacy beside-exe
	// location (migration), then rebuild from the per-group files.
	if data, err := os.ReadFile(filepath.Join(configsDir(), "v2rayez-configs.json")); err == nil && len(data) > 0 && json.Valid(data) {
		return map[string]any{"found": true, "data": json.RawMessage(data)}, nil
	}
	if data, err := readSideFile("v2rayez-configs.json"); err == nil && len(data) > 0 && json.Valid(data) {
		return map[string]any{"found": true, "data": json.RawMessage(data), "source": "legacy"}, nil
	}
	if fd, ferr := loadConfigsFolder(); ferr == nil && len(fd) > 0 {
		return map[string]any{"found": true, "data": json.RawMessage(fd), "source": "folder"}, nil
	}
	return map[string]any{"found": false, "data": map[string]any{}}, nil
}

// handleConfigsFolderLoad explicitly rebuilds the config groups from the files
// in the configs/ folder (so a user can drop .json group files in and import).
func (s *Server) handleConfigsFolderLoad(json.RawMessage) (any, error) {
	fd, err := loadConfigsFolder()
	if err != nil || len(fd) == 0 {
		return map[string]any{"found": false, "data": map[string]any{}, "folder": configsDir()}, nil
	}
	return map[string]any{"found": true, "data": json.RawMessage(fd), "folder": configsDir()}, nil
}

func (s *Server) handleXrayDownload(body json.RawMessage) (any, error) {
	var req struct {
		Dir    string `json:"dir"`
		Mirror string `json:"mirror"`
	}
	_ = json.Unmarshal(body, &req)
	ghdl.SetMirror(req.Mirror)
	dir := strings.TrimSpace(req.Dir)
	if dir == "" {
		dir = appDir() // xray.Download extracts into <dir>/xray-core/
	}
	path, err := xray.Download(dir, s.bus.Log)
	if err != nil {
		s.log("✗ Xray download failed: "+err.Error(), "ERROR")
		return map[string]any{"ok": false, "error": err.Error()}, nil
	}
	return map[string]any{"ok": true, "path": path}, nil
}

func (s *Server) handleXrayStart(body json.RawMessage) (any, error) {
	var req struct {
		URI        string `json:"uri"`
		BinPath    string `json:"bin_path"`
		SocksPort  int    `json:"socks_port"`
		ListenHost string `json:"listen_host"`
		ProxyHost  string `json:"proxy_host"`
		ProxyPort  int    `json:"proxy_port"`
		Direct     bool   `json:"direct"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, err
	}
	if strings.TrimSpace(req.URI) == "" {
		return nil, errors.New("uri required")
	}
	s.log("Starting xray on device…", "ACCENT")
	err := s.xrayRunner.Start(xray.RunOptions{
		URI:        req.URI,
		BinPath:    req.BinPath,
		SocksPort:  req.SocksPort,
		ListenHost: req.ListenHost,
		ProxyHost:  req.ProxyHost,
		ProxyPort:  req.ProxyPort,
		Direct:     req.Direct,
	})
	if err != nil {
		s.log("✗ "+err.Error(), "ERROR")
		return nil, err
	}
	return s.xrayRunner.Status(), nil
}

// handleXrayStartRaw runs a full, user-supplied Xray config (e.g. an imported
// MITM-DomainFronting JSON file) directly, instead of building one from a URI.
func (s *Server) handleXrayStartRaw(body json.RawMessage) (any, error) {
	var req struct {
		Config  string `json:"config"`
		BinPath string `json:"bin_path"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, err
	}
	if strings.TrimSpace(req.Config) == "" {
		return nil, errors.New("config required")
	}
	s.log("Starting xray with imported config…", "ACCENT")
	if err := s.xrayRunner.StartRaw(req.BinPath, req.Config); err != nil {
		s.log("✗ "+err.Error(), "ERROR")
		return nil, err
	}
	return s.xrayRunner.Status(), nil
}

func (s *Server) handleXrayStop(json.RawMessage) (any, error) {
	s.xrayRunner.Stop()
	return map[string]any{"running": false}, nil
}

func (s *Server) handleXrayStatus(json.RawMessage) (any, error) {
	return s.xrayRunner.Status(), nil
}

// ---- Tor (pluggable transports + optional TUN) ----------------------------

func (s *Server) handleTorStart(body json.RawMessage) (any, error) {
	var req struct {
		tor.Options
		Tun bool `json:"tun"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, err
	}
	if err := s.torr.Start(req.Options); err != nil {
		s.log("✗ Tor: "+err.Error(), "ERROR")
		return map[string]any{"ok": false, "error": err.Error()}, nil
	}
	out := s.torr.Status()
	if req.Tun {
		port := req.SocksPort
		if port == 0 {
			port = 9050
		}
		if err := s.t2s.Start("", "127.0.0.1", port, bridgeExcludeIPs(req.Bridges)); err != nil {
			s.log("✗ tun2socks: "+err.Error(), "ERROR")
			out["tun_error"] = err.Error()
		} else {
			out["tun"] = true
		}
	}
	out["ok"] = true
	return out, nil
}

func (s *Server) handleTorStop(json.RawMessage) (any, error) {
	s.t2s.Stop()
	s.torr.Stop()
	return s.torr.Status(), nil
}

func (s *Server) handleTorStatus(json.RawMessage) (any, error) {
	st := s.torr.Status()
	st["tun_running"] = s.t2s.Running()
	return st, nil
}

// builtinBridges returns bridge lines per transport. For obfs4 a different
// random bridge is returned on each call so repeated "auto-get" presses rotate.
// bridgeExcludeIPs extracts the host IPs from bridge lines so the TUN router
// can keep those connections on the physical link (avoid routing Tor's own
// bridge traffic back into the tunnel).
func bridgeExcludeIPs(bridges string) []string {
	var ips []string
	for _, line := range strings.Split(bridges, "\n") {
		f := strings.Fields(strings.TrimSpace(line))
		// transport host:port fingerprint ...  → host:port is field[1]
		var hp string
		if len(f) >= 2 && (f[0] == "obfs4" || f[0] == "webtunnel" || f[0] == "meek_lite" || f[0] == "snowflake" || f[0] == "conjure") {
			hp = f[1]
		} else if len(f) >= 1 && strings.Contains(f[0], ":") {
			hp = f[0]
		}
		if hp == "" {
			continue
		}
		if strings.HasPrefix(hp, "[") { // [IPv6]:port
			if i := strings.Index(hp, "]"); i > 0 {
				ips = append(ips, hp[1:i])
				continue
			}
		}
		if i := strings.LastIndex(hp, ":"); i > 0 {
			ips = append(ips, hp[:i])
		}
	}
	return ips
}

var bridgeRotMu sync.Mutex
var bridgeRotIdx = map[string]int{}

// rotateBridges returns up to n bridges from pool, advancing a per-key cursor so
// successive "Auto-get" presses hand out different bridges (≥2 helps conflux).
func rotateBridges(key string, pool []string, n int) []string {
	bridgeRotMu.Lock()
	defer bridgeRotMu.Unlock()
	if len(pool) == 0 {
		return nil
	}
	if n > len(pool) {
		n = len(pool)
	}
	start := bridgeRotIdx[key] % len(pool)
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, pool[(start+i)%len(pool)])
	}
	bridgeRotIdx[key] = (start + n) % len(pool)
	return out
}

var obfs4Pool = []string{
	"obfs4 89.10.81.64:7624 7468882481663A1AAE6067D5C6FC3A8CFAC82129 cert=Bsfe/59QH2vNZtj1MXurtPbPGENyL0i6bzfi9mXqceTJKF9wzf5K9x7xx2SdH70R0sd5Mg iat-mode=2",
	"obfs4 108.50.202.242:46037 C26661629B7B8E05CB11D109360D02447EB9B5B5 cert=+A3dhOmzBR23iD4LoSgTO3fzTPsov91wbeA2c2D2FcQSlEV4H6ruI6ksxxsejqFsRbyDeQ iat-mode=0",
	"obfs4 167.235.78.36:40678 C8C01639C3333ED20799C69B149641A6568044BC cert=PWxWCoFmK8B+x8WYbgWmTjfXsmRFjL3P5ptPdvzqks7nzMLroLlXc+wG49hpBlF3UG20bA iat-mode=0",
	"obfs4 159.69.155.42:64255 99435AEB7614FCB425EF565856229E2E27A175F3 cert=Js2tgdMZvXSk2ogkWi+Mdtvi3LMX/6jv5MMqT7UVOdVklVfeGx7NXXwDeheFu1H5ORN6Zw iat-mode=0",
	"obfs4 51.38.220.224:30996 22494A012CFA8C88B1D907E2CCB8409AC35B537B cert=dOPijSCG6FD89fYv5N2F9QoeK1od3tpG6VBE/kMY0Bt1aW/7aXPIzsENDoLWZe43gI8efw iat-mode=0",
	"obfs4 51.79.88.193:45529 9A7BA1AE905FBE24FCEACCA09C42ED1B59340D6C cert=5TSiurscOytr5+TpcKG9qQry0UCMkq9eIlHr1ANxFJ0SWujMjUCOpWpDx30eUUIWHC0QSg iat-mode=0",
	"obfs4 125.24.161.125:9052 E78066C5436110F6F6D9F1734551F5FCC9C9B500 cert=NmFmMIKVT8sQ8Jk/UXFivXCFIGb7UIIakMcegcMbqm855TBcbWWQ9qwKNpuGBz/qN6gCQw iat-mode=0",
	"obfs4 217.217.243.39:8443 9E9968BFEAC4BB0A857400CBD83BD1BC77F64B4B cert=6iEWVvEBy3EaH5ESoimsujsHAhqll6kpJtPDJEJ8LAd9ZZqIzBom79R8mVsJPc8GiCuWCA iat-mode=2",
	"obfs4 95.217.11.29:22134 9859875C752128125D3179F90BA6351744B09040 cert=W+qSHr6JcFY6UyJiXR3Ec5I5bYHFwDAXNq8HRQU3C56h/aJB8PQqbr8Sq04zKvhEWGbxEw iat-mode=0",
	"obfs4 51.68.81.140:2098 F205CB5B969389061477609F8E03470B982F64C1 cert=6hFyrclX8Cg16jHGbtYqZxbGxj+p0flBn2EYZu+hvx/tGL4GROXSvBtwVQ1sRYFbi0++fQ iat-mode=0",
}

var webtunnelPool = []string{
	"webtunnel [2001:db8:4b0:feea:81d8:72b9:95c1:cd62]:443 A6A5AF5E8410EB76647925F66AB2B5810A2C3791 url=https://wolkewolkewolke.zip/xrCyxOQH6HOe952fVtzKMGDN ver=0.0.4",
	"webtunnel [2001:db8:f37a:49d9:c85f:3e7b:eb39:853e]:443 7E8CB9592C97B8ADD03D374A8E207CAAE5121336 url=https://gia.shallotfarm.org/3IMx3r7r1hKVsW136nx9vVMD ver=0.0.1",
	"webtunnel [2001:db8:9aec:17d4:7f1d:9583:2d3f:f007]:443 65A498C6166E7C0201A16841F33A7A7A300AD391 url=http://45.77.33.28/c5f89c09483ef1b1f741db9f1a34bd9d ver=0.0.3",
	"webtunnel [2001:db8:5d90:6cd2:fcac:ea1c:67b2:bee0]:443 D85733AB26E770DC4AB2ED44A0559504550D0925 url=https://qbxa1hay.xoomlia.com/k0tf6syz/ ver=0.0.3",
	"webtunnel [2001:db8:c151:8ea6:7ecb:78eb:97e9:e26a]:443 F6AC833BA7AE92AD01FA99195EA51BBC3265A6E2 url=https://cdn-133.triplebit.dev/6e7f8g9h0i1j2k3l4m5n6o7p ver=0.0.2",
	"webtunnel [2001:db8:4379:8b8c:f7e5:1baa:b4cc:a4e]:443 83A7EB300BF49150792D695CF4A15DF284492172 url=https://wt1.daslab.top/dasdaslablabwt1 ver=0.0.4",
	"webtunnel [2001:db8:3be7:5113:eddb:210d:291f:b52c]:443 B6CFDBD17618C147903429AB1C0CC759933DB50E url=https://adm.unicoridor.ru/rtASSYlOJgl1nKtH8njdZLbs ver=0.0.4",
	"webtunnel [2001:db8:ce90:3593:272e:4975:a031:55b]:443 12382A2F3912AD1983A97C8709CBAE47ADB60BE3 url=https://miranda.today/LWwxIXDHCyyScn7oDauPMTmX ver=0.0.3",
	"webtunnel [2001:db8:72cd:a490:2485:20b0:4987:35ec]:443 C0B90984E829C31BB316CCB8A89CB4F318891871 url=https://download-134.as401332.net/7f8g9h0i1j2k3l4m5n6o7p8q ver=0.0.2",
	"webtunnel [2001:db8:b1d5:4998:8150:f75b:988f:1f48]:443 216C8BB1C44FC2BFF7AF823B55AC38F113079B93 url=https://cdn-38.triplebit.dev/Bai8aXeiPhar5gai ver=0.0.2",
}

func builtinBridges(transport string) []string {
	switch transport {
	case "snowflake":
		return []string{
			"snowflake 192.0.2.3:80 2B280B23E1107BB62ABFC40DDCC8824814F80A72 fingerprint=2B280B23E1107BB62ABFC40DDCC8824814F80A72 url=https://1098762253.rsc.cdn77.org/ fronts=www.cdn77.com,www.phpmyadmin.net ice=stun:stun.l.google.com:19302,stun:stun.antisip.com:3478,stun:stun.bluesip.net:3478,stun:stun.dus.net:3478 utls-imitate=hellorandomizedalpn",
		}
	case "meek_lite":
		return []string{
			"meek_lite 192.0.2.20:80 97700DFE9F483596DDA6264C4D7DF7641E1E39CE url=https://meek.azureedge.net/ front=ajax.aspnetcdn.com utls=HelloRandomizedALPN",
		}
	case "conjure":
		return []string{
			"conjure 0.0.0.1:80 5E1062B0D9498D29A8C56DC5EB0FEFFB87DFAB7E url=https://registration.refraction.network/api fronts=cdn.sstatic.net,assets.tumblr.com transport=min",
		}
	case "webtunnel":
		return rotateBridges("webtunnel", webtunnelPool, 2)
	default: // obfs4 — rotate through the pool, 2 at a time
		return rotateBridges("obfs4", obfs4Pool, 2)
	}
}

func (s *Server) handleTorBridges(body json.RawMessage) (any, error) {
	var req struct {
		Transport string `json:"transport"`
	}
	_ = json.Unmarshal(body, &req)
	lines := builtinBridges(req.Transport)
	return map[string]any{"transport": req.Transport, "bridges": strings.Join(lines, "\n")}, nil
}

// moat (BridgeDB) protocol — request a captcha, then submit the solution to get
// fresh bridges. See bridges.torproject.org. Uses the JSON:API content type.
const moatBase = "https://bridges.torproject.org/moat"

func moatPost(path string, payload any, proxyURL string) (map[string]any, error) {
	b, _ := json.Marshal(payload)
	req, _ := http.NewRequest(http.MethodPost, moatBase+path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/vnd.api+json")
	req.Header.Set("Accept", "application/vnd.api+json")
	tr := &http.Transport{}
	if proxyURL != "" {
		if pu, err := neturl.Parse(proxyURL); err == nil {
			tr.Proxy = http.ProxyURL(pu)
			// the MITM re-signs TLS with its own CA
			tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		}
	}
	client := &http.Client{Timeout: 40 * time.Second, Transport: tr}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return nil, errors.New("moat HTTP " + resp.Status)
	}
	var out map[string]any
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// moatProxy returns the local MITM proxy URL if the domain-fronting proxy is
// running, so the moat request can ride over it (bridges.torproject.org is
// often censored directly).
func (s *Server) moatProxy() string {
	if s.mitmdf != nil && s.mitmdf.Running() {
		st := s.mitmdf.Status()
		if p, ok := st["port"].(int); ok && p > 0 {
			return fmt.Sprintf("http://127.0.0.1:%d", p)
		}
	}
	return ""
}

func moatFirst(out map[string]any) map[string]any {
	if arr, ok := out["data"].([]any); ok && len(arr) > 0 {
		if m, ok := arr[0].(map[string]any); ok {
			return m
		}
	}
	return nil
}

// handleTorMoatFetch requests a captcha challenge for the chosen transport.
func (s *Server) handleTorMoatFetch(body json.RawMessage) (any, error) {
	var req struct {
		Transport string `json:"transport"`
	}
	_ = json.Unmarshal(body, &req)
	tr := req.Transport
	if tr == "" || tr == "none" {
		tr = "obfs4"
	}
	out, err := moatPost("/fetch", map[string]any{
		"data": []map[string]any{{"version": "0.1.0", "type": "client-transports", "supported": []string{tr}}},
	}, s.moatProxy())
	if err != nil {
		s.log("✗ moat fetch: "+err.Error(), "ERROR")
		return map[string]any{"ok": false, "error": err.Error() + " — bridges.torproject.org is blocked here. Start Domain Fronting (MITM) first so this request can be fronted, or use Auto-get/Snowflake (built-in, no site needed)."}, nil
	}
	m := moatFirst(out)
	if m == nil {
		return map[string]any{"ok": false, "error": "unexpected moat response"}, nil
	}
	img, _ := m["image"].(string)
	return map[string]any{
		"ok": true, "transport": tr,
		"challenge": m["challenge"], "id": m["id"],
		"image": "data:image/jpeg;base64," + img,
	}, nil
}

// handleTorMoatCheck submits the captcha solution and returns the bridges.
func (s *Server) handleTorMoatCheck(body json.RawMessage) (any, error) {
	var req struct {
		Transport string `json:"transport"`
		Challenge string `json:"challenge"`
		ID        string `json:"id"`
		Solution  string `json:"solution"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, err
	}
	if req.ID == "" {
		req.ID = "2"
	}
	out, err := moatPost("/check", map[string]any{
		"data": []map[string]any{{
			"id": req.ID, "type": "moat-solution", "version": "0.1.0",
			"transport": req.Transport, "challenge": req.Challenge,
			"solution": strings.TrimSpace(req.Solution), "qrcode": "false",
		}},
	}, s.moatProxy())
	if err != nil {
		return map[string]any{"ok": false, "error": err.Error()}, nil
	}
	m := moatFirst(out)
	if m == nil {
		return map[string]any{"ok": false, "error": "wrong captcha or no bridges returned"}, nil
	}
	var lines []string
	if arr, ok := m["bridges"].([]any); ok {
		for _, b := range arr {
			if sline, ok := b.(string); ok {
				lines = append(lines, sline)
			}
		}
	}
	if len(lines) == 0 {
		return map[string]any{"ok": false, "error": "wrong captcha — try again"}, nil
	}
	s.log(fmt.Sprintf("✓ moat returned %d bridge(s)", len(lines)), "OK")
	return map[string]any{"ok": true, "bridges": strings.Join(lines, "\n")}, nil
}

// handleTorDownload fetches a Tor Expert Bundle (tor + pluggable transports) and
// extracts it into the app folder. Tor isn't published on a predictable GitHub
// release, so it's fetched from the EasySNI repo via raw.githubusercontent.com
// (reachable where api.github.com is blocked); a custom URL may be supplied.
func (s *Server) handleTorDownload(body json.RawMessage) (any, error) {
	var req struct {
		URL string `json:"url"`
	}
	_ = json.Unmarshal(body, &req)
	url := strings.TrimSpace(req.URL)
	if url == "" {
		switch runtime.GOOS {
		case "windows":
			url = "https://raw.githubusercontent.com/macan-dev/EasySNI/refs/heads/main/repo/tor-windows.zip"
		default:
			url = "https://raw.githubusercontent.com/macan-dev/EasySNI/refs/heads/main/repo/tor/tor-expert-bundle-" + runtime.GOOS + "-" + runtime.GOARCH + ".tar.gz"
		}
	}
	dest := filepath.Join(appDir(), "tor")
	if err := os.MkdirAll(dest, 0o755); err != nil {
		return map[string]any{"ok": false, "error": err.Error()}, nil
	}
	s.log("Downloading Tor + transports…", "ACCENT")
	data, err := ghdl.Download(url)
	if err != nil {
		s.log("✗ Tor download: "+err.Error(), "ERROR")
		return map[string]any{"ok": false, "error": err.Error() + " — host the bundle in your repo or set a custom URL"}, nil
	}
	var n int
	if strings.HasSuffix(strings.ToLower(url), ".zip") {
		n, err = extractZipTo(data, dest)
	} else {
		n, err = extractTarGz(data, dest)
	}
	if err != nil {
		return map[string]any{"ok": false, "error": err.Error()}, nil
	}
	s.log(fmt.Sprintf("✓ Tor bundle extracted (%d files) into %s — tor + lyrebird/conjure ready", n, dest), "OK")
	return map[string]any{"ok": true, "files": n, "dir": dest}, nil
}

// extractZipTo unpacks a .zip into dest (flattening to base names), returns count.
func extractZipTo(data []byte, dest string) (int, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return 0, err
	}
	count := 0
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		name := filepath.Base(f.Name)
		if name == "" {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return count, err
		}
		out, err := os.OpenFile(filepath.Join(dest, name), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
		if err != nil {
			rc.Close()
			return count, err
		}
		if _, err := io.Copy(out, rc); err != nil {
			out.Close()
			rc.Close()
			return count, err
		}
		out.Close()
		rc.Close()
		count++
	}
	return count, nil
}

// extractTarGz unpacks a .tar.gz into dest, preserving its internal directory
// layout (tor/ and pluggable_transports/), and returns the file count.
func extractTarGz(data []byte, dest string) (int, error) {
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return 0, err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	count := 0
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return count, err
		}
		clean := filepath.Clean(h.Name)
		if strings.HasPrefix(clean, "..") || filepath.IsAbs(clean) {
			continue // skip unsafe paths
		}
		target := filepath.Join(dest, clean)
		switch h.Typeflag {
		case tar.TypeDir:
			_ = os.MkdirAll(target, 0o755)
		case tar.TypeReg:
			_ = os.MkdirAll(filepath.Dir(target), 0o755)
			out, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
			if err != nil {
				return count, err
			}
			if _, err := io.Copy(out, tr); err != nil {
				out.Close()
				return count, err
			}
			out.Close()
			count++
		}
	}
	return count, nil
}

// ---- tun2socks (xray TUN without sing-box) --------------------------------

func (s *Server) handleTun2socksDownload(body json.RawMessage) (any, error) {
	var req struct {
		Mirror string `json:"mirror"`
	}
	_ = json.Unmarshal(body, &req)
	ghdl.SetMirror(req.Mirror)
	dir := filepath.Join(appDir(), "tun2socks")
	s.log("Downloading tun2socks…", "ACCENT")
	path, err := tun2socks.Download(dir, s.bus.Log)
	if err != nil {
		s.log("✗ "+err.Error(), "ERROR")
		return map[string]any{"ok": false, "error": err.Error()}, nil
	}
	// tun2socks needs wintun.dll on Windows; Xray's archive bundles it. If we
	// don't have it yet, fetch Xray-core (into xray-core/) and copy it beside
	// the tun2socks binary so TUN mode works out of the box.
	if runtime.GOOS == "windows" && !tun2socks.HasWintun() {
		s.log("Fetching Xray-core to obtain wintun.dll (needed for TUN)…", "ACCENT")
		if _, derr := xray.Download(appDir(), s.bus.Log); derr != nil {
			s.log("Could not auto-fetch wintun.dll: "+derr.Error(), "WARN")
		}
	}
	if runtime.GOOS == "windows" {
		tun2socks.EnsureWintunBeside(dir)
	}
	return map[string]any{"ok": true, "path": path}, nil
}

func (s *Server) handleTun2socksStart(body json.RawMessage) (any, error) {
	var req struct {
		BinPath   string `json:"bin_path"`
		SocksHost string `json:"socks_host"`
		SocksPort int    `json:"socks_port"`
	}
	_ = json.Unmarshal(body, &req)
	if req.SocksPort == 0 {
		req.SocksPort = 40808
	}
	if err := s.t2s.Start(req.BinPath, req.SocksHost, req.SocksPort, nil); err != nil {
		s.log("✗ tun2socks: "+err.Error(), "ERROR")
		return nil, err
	}
	return s.t2s.Status(), nil
}

func (s *Server) handleTun2socksStop(json.RawMessage) (any, error) {
	s.t2s.Stop()
	return s.t2s.Status(), nil
}

func (s *Server) handleTun2socksStatus(json.RawMessage) (any, error) {
	return s.t2s.Status(), nil
}

// ---- system proxy (point the OS at xray's local proxy) --------------------

func (s *Server) handleSysproxySet(body json.RawMessage) (any, error) {
	var req struct {
		Mode string `json:"mode"`
		Host string `json:"host"`
		Port int    `json:"port"`
	}
	_ = json.Unmarshal(body, &req)
	if !sysproxy.Supported() {
		return nil, errors.New("system-proxy control isn't supported on this OS — set it manually")
	}
	if strings.TrimSpace(req.Host) == "" {
		req.Host = "127.0.0.1"
	}
	if req.Port == 0 {
		// Fall back to the running xray SOCKS port if present.
		st := s.xrayRunner.Status()
		if p, ok := st["socks"].(int); ok && p > 0 {
			req.Port = p
		}
	}
	if req.Port == 0 {
		return nil, errors.New("no proxy port — start xray (SOCKS) first or pass a port")
	}
	var err error
	mode := "socks"
	if req.Mode == "http" {
		mode = "http"
		err = sysproxy.SetHTTP(req.Host, req.Port)
	} else {
		err = sysproxy.SetSOCKS(req.Host, req.Port)
	}
	if err != nil {
		s.log("✗ system proxy: "+err.Error(), "ERROR")
		return nil, err
	}
	s.log(fmt.Sprintf("System proxy set → %s %s:%d", mode, req.Host, req.Port), "OK")
	return map[string]any{"ok": true, "mode": mode, "host": req.Host, "port": req.Port}, nil
}

func (s *Server) handleSysproxyClear(json.RawMessage) (any, error) {
	if !sysproxy.Supported() {
		return nil, errors.New("system-proxy control isn't supported on this OS")
	}
	if err := sysproxy.Clear(); err != nil {
		return nil, err
	}
	s.log("System proxy cleared", "DIM")
	return map[string]any{"ok": true}, nil
}

// ---- sing-box (TUN / system-wide) -----------------------------------------

func (s *Server) handleSingboxFind(json.RawMessage) (any, error) {
	p := singbox.Find()
	return map[string]any{"found": p != "", "path": p}, nil
}

func (s *Server) handleSingboxDownload(body json.RawMessage) (any, error) {
	var req struct {
		Dir    string `json:"dir"`
		Mirror string `json:"mirror"`
	}
	_ = json.Unmarshal(body, &req)
	ghdl.SetMirror(req.Mirror)
	dir := strings.TrimSpace(req.Dir)
	if dir == "" {
		dir = filepath.Join(appDir(), "singbox")
	}
	s.log("Downloading sing-box…", "ACCENT")
	path, err := singbox.Download(dir, s.bus.Log)
	if err != nil {
		s.log("✗ sing-box download failed: "+err.Error(), "ERROR")
		return map[string]any{"ok": false, "error": err.Error()}, nil
	}
	return map[string]any{"ok": true, "path": path}, nil
}

func (s *Server) handleSingboxStart(body json.RawMessage) (any, error) {
	var req struct {
		URI       string `json:"uri"`
		BinPath   string `json:"bin_path"`
		TUN       bool   `json:"tun"`
		SocksPort int    `json:"socks_port"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, err
	}
	if strings.TrimSpace(req.URI) == "" {
		return nil, errors.New("connect a config first (use a Connect button in the Library)")
	}
	if req.SocksPort == 0 {
		req.SocksPort = 2080
	}
	if req.TUN {
		s.log("Starting sing-box in TUN mode (needs admin/root)…", "ACCENT")
	} else {
		s.log("Starting sing-box (SOCKS)…", "ACCENT")
	}
	if err := s.singboxRunner.Start(req.BinPath, req.URI, req.TUN, req.SocksPort); err != nil {
		s.log("✗ "+err.Error(), "ERROR")
		return nil, err
	}
	return s.singboxRunner.Status(), nil
}

func (s *Server) handleSingboxStop(json.RawMessage) (any, error) {
	s.singboxRunner.Stop()
	return map[string]any{"running": false}, nil
}

func (s *Server) handleSingboxStatus(json.RawMessage) (any, error) {
	return s.singboxRunner.Status(), nil
}

// ---- WinDivert ------------------------------------------------------------

// handleWinDivertDownload fetches WinDivert64.sys + WinDivert.dll from the
// EasySNI repo (raw.githubusercontent.com, reachable where api.github.com is
// blocked) into a windivert/ folder.
func (s *Server) handleWinDivertDownload(json.RawMessage) (any, error) {
	dir := filepath.Join(appDir(), "windivert")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return map[string]any{"ok": false, "error": err.Error()}, nil
	}
	files := []struct{ name, url string }{
		{"WinDivert64.sys", "https://raw.githubusercontent.com/macan-dev/EasySNI/refs/heads/main/WinDivert64.sys"},
		{"WinDivert.dll", "https://raw.githubusercontent.com/macan-dev/EasySNI/refs/heads/main/WinDivert.dll"},
	}
	s.log("Downloading WinDivert driver…", "ACCENT")
	n := 0
	for _, f := range files {
		data, err := ghdl.Download(f.url)
		if err != nil {
			s.log("✗ "+f.name+": "+err.Error(), "ERROR")
			return map[string]any{"ok": false, "error": f.name + ": " + err.Error()}, nil
		}
		if err := os.WriteFile(filepath.Join(dir, f.name), data, 0o755); err != nil {
			return map[string]any{"ok": false, "error": err.Error()}, nil
		}
		n++
	}
	s.log("✓ WinDivert downloaded to "+dir, "OK")
	return map[string]any{"ok": true, "dir": dir, "files": n}, nil
}

func (s *Server) handleWinDivertStatus(json.RawMessage) (any, error) {
	return windivert.Check(), nil
}

func (s *Server) handleWinDivertInstall(body json.RawMessage) (any, error) {
	var req struct {
		Path string `json:"path"`
	}
	_ = json.Unmarshal(body, &req)
	s.log("Installing WinDivert…", "ACCENT")
	r := windivert.Install(strings.TrimSpace(req.Path))
	if r.OK {
		s.log("✓ "+r.Message, "OK")
	} else {
		s.log("✗ "+r.Message, "ERROR")
	}
	return r, nil
}

func (s *Server) handleWinDivertUninstall(json.RawMessage) (any, error) {
	s.log("Removing WinDivert…", "WARN")
	r := windivert.Uninstall()
	if r.OK {
		s.log("✓ "+r.Message, "OK")
	} else {
		s.log("✗ "+r.Message, "ERROR")
	}
	return r, nil
}

// ---- port check & LAN info ------------------------------------------------

func (s *Server) handlePortCheck(body json.RawMessage) (any, error) {
	var req struct {
		Host    string `json:"host"`
		Port    int    `json:"port"`
		Timeout int    `json:"timeout"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, err
	}
	if req.Host == "" {
		req.Host = "127.0.0.1"
	}
	if req.Port == 0 {
		return nil, errors.New("port required")
	}
	r := netutil.CheckPort(req.Host, req.Port, timeoutOf(req.Timeout, 4))
	if r.Open {
		s.log("✓ port "+req.Host+":"+strconv.Itoa(req.Port)+" open ("+strconv.Itoa(r.Latency)+" ms)", "OK")
	} else {
		s.log("✗ port "+req.Host+":"+strconv.Itoa(req.Port)+" closed", "WARN")
	}
	return r, nil
}

func (s *Server) handleLANInfo(json.RawMessage) (any, error) {
	return map[string]any{"addrs": netutil.LANAddrs()}, nil
}

// ---- Psiphon device tunnel ------------------------------------------------

func (s *Server) handlePsiphonStart(body json.RawMessage) (any, error) {
	var req struct {
		UpstreamProxyURL string `json:"upstream_proxy_url"`
		SocksPort        int    `json:"socks_port"`
		HTTPPort         int    `json:"http_port"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, err
	}
	s.log("Starting Psiphon (upstream "+req.UpstreamProxyURL+")…", "ACCENT")
	err := s.psi.Start(psiphon.Options{
		UpstreamProxyURL: strings.TrimSpace(req.UpstreamProxyURL),
		LocalSocksPort:   req.SocksPort,
		LocalHTTPPort:    req.HTTPPort,
	}, s.bus.Log)
	if err != nil {
		s.log("✗ "+err.Error(), "ERROR")
		return nil, err
	}
	return s.psi.Status(), nil
}

func (s *Server) handlePsiphonStop(json.RawMessage) (any, error) {
	s.psi.Stop()
	s.log("Psiphon stopped", "WARN")
	return map[string]any{"running": false}, nil
}

func (s *Server) handlePsiphonStatus(json.RawMessage) (any, error) {
	return s.psi.Status(), nil
}

// handlePsiphonDownload fetches the prebuilt Psiphon Windows client into the app
// directory so the user can run it and point its upstream proxy at the MITM.
func (s *Server) handlePsiphonDownload(json.RawMessage) (any, error) {
	const url = "https://raw.githubusercontent.com/macan-dev/EasySNI/refs/heads/main/repo/psiphon3.exe"
	dir := filepath.Join(appDir(), "psiphon")
	_ = os.MkdirAll(dir, 0o755)
	dest := filepath.Join(dir, "psiphon3.exe")
	s.log("Downloading Psiphon (psiphon3.exe)…", "ACCENT")
	client := &http.Client{Timeout: 120 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		s.log("✗ "+err.Error(), "ERROR")
		return map[string]any{"ok": false, "error": err.Error()}, nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return map[string]any{"ok": false, "error": "HTTP " + resp.Status}, nil
	}
	f, err := os.OpenFile(dest, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		return map[string]any{"ok": false, "error": err.Error()}, nil
	}
	n, err := io.Copy(f, resp.Body)
	f.Close()
	if err != nil {
		return map[string]any{"ok": false, "error": err.Error()}, nil
	}
	s.log("✓ Psiphon saved to "+dest+" ("+fmt.Sprintf("%.1f", float64(n)/1e6)+" MB)", "OK")
	return map[string]any{"ok": true, "path": dest, "bytes": n}, nil
}

// handlePsiphonOpen launches the downloaded Psiphon client.
func (s *Server) handlePsiphonOpen(json.RawMessage) (any, error) {
	a := appDir()
	candidates := []string{
		filepath.Join(a, "psiphon", "psiphon3.exe"), filepath.Join(a, "psiphon", "psiphon3"),
		filepath.Join(a, "psiphon3.exe"), filepath.Join(a, "psiphon3"),
	}
	var bin string
	for _, c := range candidates {
		if st, err := os.Stat(c); err == nil && !st.IsDir() {
			bin = c
			break
		}
	}
	if bin == "" {
		return map[string]any{"ok": false, "error": "Psiphon not found — click Download Psiphon first"}, nil
	}
	if err := launchDetached(bin); err != nil {
		s.log("✗ open Psiphon: "+err.Error(), "ERROR")
		return map[string]any{"ok": false, "error": err.Error()}, nil
	}
	s.log("Launched Psiphon: "+bin, "OK")
	return map[string]any{"ok": true, "path": bin}, nil
}

// handlePsiphonOverMitm chains Psiphon through the client-side domain-fronting
// MITM proxy: it starts the MITM proxy (if needed) and then launches Psiphon with
// its upstream proxy pointed at it. Mirrors the "PsiphonOverMITM" architecture
// (Psiphon → local MITM/domain-fronting → Psiphon network).
func (s *Server) handlePsiphonOverMitm(body json.RawMessage) (any, error) {
	var req struct {
		MitmPort  int `json:"mitm_port"`
		SocksPort int `json:"socks_port"`
		HTTPPort  int `json:"http_port"`
	}
	_ = json.Unmarshal(body, &req)
	if req.MitmPort == 0 {
		req.MitmPort = 8087
	}
	// 1) bring up the domain-fronting MITM proxy if it isn't already running
	if !s.mitmdf.Running() {
		s.log("Psiphon-over-MITM: starting domain-fronting proxy…", "ACCENT")
		if err := s.mitmdf.Start(mitmdf.Config{ListenHost: "127.0.0.1", ListenPort: req.MitmPort}); err != nil {
			return nil, fmt.Errorf("MITM proxy: %w", err)
		}
	} else if st := s.mitmdf.Status(); st["port"] != nil {
		if p, ok := st["port"].(int); ok && p > 0 {
			req.MitmPort = p
		}
	}
	// 2) start Psiphon with its upstream proxy pointed at the MITM proxy
	upstream := fmt.Sprintf("http://127.0.0.1:%d", req.MitmPort)
	s.log("Psiphon-over-MITM: MITM ready. Upstream proxy = "+upstream, "OK")
	if err := s.psi.Start(psiphon.Options{
		UpstreamProxyURL: upstream,
		LocalSocksPort:   req.SocksPort,
		LocalHTTPPort:    req.HTTPPort,
	}, s.bus.Log); err != nil {
		// The embedded Psiphon engine isn't compiled in (it can't be `go get`-ed
		// cleanly). That's fine — use the same model as the upstream project:
		// keep the MITM running and tell the user to point their Psiphon app's
		// upstream proxy at it.
		s.log("Set your Psiphon app's Upstream Proxy to "+upstream+" (HTTP).", "ACCENT")
		return map[string]any{
			"running":   false,
			"external":  true,
			"mitm_port": req.MitmPort,
			"upstream":  upstream,
			"note":      "MITM proxy is running. In the Psiphon app, set Settings → Proxy → Upstream Proxy to " + upstream + " (HTTP).",
		}, nil
	}
	out := s.psi.Status()
	out["mitm_port"] = req.MitmPort
	out["upstream"] = upstream
	return out, nil
}

// ---- CDN fronting edge scan ----------------------------------------------

func (s *Server) handleCDNScan(body json.RawMessage) (any, error) {
	var req struct {
		Ranges   string `json:"ranges"` // newline CIDRs / IPs
		Port     int    `json:"port"`
		FrontSNI string `json:"front_sni"`
		RealHost string `json:"real_host"`
		Limit    int    `json:"limit"`
		Timeout  int    `json:"timeout"`
		Workers  int    `json:"workers"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, err
	}
	text := req.Ranges
	if len(splitLines(text)) == 0 {
		text = strings.Join(sni.DefaultCloudflareRanges, "\n")
	}
	ips := sni.ParseIPList(text)
	if len(ips) == 0 {
		return nil, errors.New("no IPs parsed from ranges")
	}
	if req.Limit > 0 && len(ips) > req.Limit {
		ips = ips[:req.Limit]
	}
	if req.Port == 0 {
		req.Port = 443
	}
	timeout := timeoutOf(req.Timeout, 4)
	workers := clampWorkers(req.Workers)

	s.log("CDN edge scan: "+strconv.Itoa(len(ips))+" IPs on :"+strconv.Itoa(req.Port)+" (front "+req.FrontSNI+" → host "+req.RealHost+")", "ACCENT")

	results := make([]sni.FrontResult, len(ips))
	var ok int64
	runPool(len(ips), workers, func(i int) {
		results[i] = sni.FrontTest(ips[i], req.Port, req.FrontSNI, req.RealHost, timeout)
		if results[i].OK {
			atomic.AddInt64(&ok, 1)
		}
	})

	// Rank: working edges first, then by lowest ping (TTFB).
	sort.SliceStable(results, func(a, b int) bool {
		if results[a].OK != results[b].OK {
			return results[a].OK
		}
		pa, pb := results[a].PingMs, results[b].PingMs
		if pa < 0 {
			pa = 1 << 30
		}
		if pb < 0 {
			pb = 1 << 30
		}
		return pa < pb
	})
	best := ""
	if len(results) > 0 && results[0].OK {
		best = results[0].IP
		s.log("✓ best edge "+best+" ("+strconv.Itoa(results[0].PingMs)+" ms)", "OK")
	}
	s.log("CDN edge scan complete: "+strconv.FormatInt(ok, 10)+"/"+strconv.Itoa(len(ips))+" reachable", "ACCENT")
	return map[string]any{"results": results, "ok": ok, "total": len(ips), "best": best}, nil
}

// ---- small helpers --------------------------------------------------------

func timeoutOf(seconds, def int) time.Duration {
	if seconds <= 0 {
		seconds = def
	}
	return time.Duration(seconds) * time.Second
}

func clampWorkers(n int) int {
	if n <= 0 {
		return 50
	}
	if n > 200 {
		return 200
	}
	return n
}

// runPool runs fn(0..n-1) across at most `workers` goroutines and blocks until
// every index has completed.
func runPool(n, workers int, fn func(i int)) {
	if n == 0 {
		return
	}
	if workers > n {
		workers = n
	}
	jobs := make(chan int)
	var wg sync.WaitGroup
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go func() {
			defer wg.Done()
			for i := range jobs {
				fn(i)
			}
		}()
	}
	for i := 0; i < n; i++ {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
}

func splitLines(s string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		if t := strings.TrimSpace(line); t != "" && !strings.HasPrefix(t, "#") {
			out = append(out, t)
		}
	}
	return out
}

// launchDetached starts an external program without blocking.
func launchDetached(bin string) error {
	cmd := exec.Command(bin)
	if d := filepath.Dir(bin); d != "" {
		cmd.Dir = d
	}
	return cmd.Start()
}

// appDir returns the directory of the running executable (or cwd as fallback),
// the base under which per-tool download folders (xray-core/, singbox/,
// tun2socks/, psiphon/, tor/) are created.
func appDir() string {
	if exe, err := os.Executable(); err == nil {
		return filepath.Dir(exe)
	}
	if wd, err := os.Getwd(); err == nil {
		return wd
	}
	return "."
}
