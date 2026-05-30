package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
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
	"ezsni/internal/netutil"
	"ezsni/internal/proxy"
	"ezsni/internal/psiphon"
	"ezsni/internal/singbox"
	"ezsni/internal/sni"
	"ezsni/internal/splus"
	"ezsni/internal/sysproxy"
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
	png, err := qrcode.Encode(req.Text, qrcode.Medium, 320)
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

func (s *Server) handleConfigsStoreSave(body json.RawMessage) (any, error) {
	if len(body) == 0 || !json.Valid(body) {
		return nil, errors.New("invalid data")
	}
	if err := writeSideFile("v2rayez-configs.json", body); err != nil {
		return nil, err
	}
	return map[string]any{"ok": true}, nil
}

func (s *Server) handleConfigsStoreLoad(json.RawMessage) (any, error) {
	data, err := readSideFile("v2rayez-configs.json")
	if err != nil || len(data) == 0 || !json.Valid(data) {
		return map[string]any{"found": false, "data": map[string]any{}}, nil
	}
	return map[string]any{"found": true, "data": json.RawMessage(data)}, nil
}

func (s *Server) handleXrayDownload(body json.RawMessage) (any, error) {
	var req struct {
		Dir string `json:"dir"`
	}
	_ = json.Unmarshal(body, &req)
	path, err := xray.Download(strings.TrimSpace(req.Dir), s.bus.Log)
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

func (s *Server) handleXrayStop(json.RawMessage) (any, error) {
	s.xrayRunner.Stop()
	return map[string]any{"running": false}, nil
}

func (s *Server) handleXrayStatus(json.RawMessage) (any, error) {
	return s.xrayRunner.Status(), nil
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
		Dir string `json:"dir"`
	}
	_ = json.Unmarshal(body, &req)
	s.log("Downloading sing-box…", "ACCENT")
	path, err := singbox.Download(strings.TrimSpace(req.Dir), s.bus.Log)
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
