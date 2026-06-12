package xray

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"ezsni/internal/ghdl"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"ezsni/internal/sni"
)

// ---- mass URI test (real xray run) ----------------------------------------

// MassRow is one config's result from a real xray run.
type MassRow struct {
	URI        string `json:"uri"`
	Name       string `json:"name"` // protocol@host:port
	Protocol   string `json:"protocol"`
	OK         bool   `json:"ok"`
	PingMs     int    `json:"ping_ms"`     // TCP connect to the server, -1 on failure
	RelayMs    int    `json:"relay_ms"`    // full request through xray, -1 on failure
	HTTPStatus int    `json:"http_status"` // status of the fetched test host
	DownKbps   int    `json:"down_kbps"`   // download throughput when WithSpeeds, -1 otherwise
	UpKbps     int    `json:"up_kbps"`     // upload throughput when WithSpeeds, -1 otherwise
	Host       string `json:"host"`
	Port       int    `json:"port"`
	SNI        string `json:"sni"`
	Error      string `json:"error"`
}

// MassXrayOptions configures a real-xray mass test.
type MassXrayOptions struct {
	URIs          []string
	BinPath       string
	ProxyHost     string // SNI tunnel host (used when !Direct)
	ProxyPort     int    // SNI tunnel port
	Direct        bool   // connect straight to each config server instead of via the tunnel
	TestURL       string // host to fetch through each config, e.g. https://instagram.com
	TimeoutSec    int    // per-config timeout (default 10)
	BasePort      int    // first SOCKS port; each config uses BasePort+index (default 11400)
	Concurrency   int    // simultaneous xray processes (default 3)
	WithSpeeds    bool   // also measure download + upload via Cloudflare speedtest
	DownloadBytes int    // bytes to download per config (default 2 MB)
	UploadBytes   int    // bytes to upload per config (default 1 MB)
}

// MassXray runs xray once per URI — through the SNI tunnel unless Direct — and
// fetches TestURL through each, measuring TCP ping to the server and the full
// relay time through the tunnel. Results are sorted reachable-first by relay.
func MassXray(opts MassXrayOptions, log LogFunc) ([]MassRow, error) {
	if log == nil {
		log = func(string, string) {}
	}
	bin := ResolveBin(opts.BinPath)
	if bin == "" {
		return nil, errors.New("xray binary not found — set its path or use Download")
	}
	if opts.TestURL == "" {
		opts.TestURL = "http://cp.cloudflare.com/generate_204"
	}
	if opts.TimeoutSec == 0 {
		opts.TimeoutSec = 10
	}
	if opts.BasePort == 0 {
		opts.BasePort = 11400
	}
	if opts.Concurrency <= 0 {
		opts.Concurrency = 3
	}
	if opts.ProxyHost == "" {
		opts.ProxyHost = "127.0.0.1"
	}
	// If routing through the tunnel, make sure it is actually up.
	if !opts.Direct {
		paddr := net.JoinHostPort(opts.ProxyHost, strconv.Itoa(opts.ProxyPort))
		if c, e := net.DialTimeout("tcp", paddr, 1500*time.Millisecond); e != nil {
			return nil, errors.New("no SNI Tunnel proxy listening on " + paddr +
				" — start it in PASSTHROUGH mode first, or enable Direct")
		} else {
			_ = c.Close()
		}
	}

	rows := make([]MassRow, len(opts.URIs))
	var wg sync.WaitGroup
	sem := make(chan struct{}, opts.Concurrency)
	for i, u := range opts.URIs {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, u string) {
			defer wg.Done()
			defer func() { <-sem }()
			rows[i] = massXrayOne(bin, u, opts.BasePort+i, opts, log)
		}(i, u)
	}
	wg.Wait()

	sort.SliceStable(rows, func(a, b int) bool {
		if rows[a].OK != rows[b].OK {
			return rows[a].OK
		}
		ra, rb := rows[a].RelayMs, rows[b].RelayMs
		if ra < 0 {
			ra = 1 << 30
		}
		if rb < 0 {
			rb = 1 << 30
		}
		return ra < rb
	})
	return rows, nil
}

func massXrayOne(bin, uri string, socksPort int, opts MassXrayOptions, log LogFunc) MassRow {
	p := sni.ParseURI(uri)
	row := MassRow{URI: uri, PingMs: -1, RelayMs: -1}
	if !p.Valid {
		row.Error = "parse: " + p.Error
		return row
	}
	row.Protocol, row.Host, row.Port, row.SNI = p.Protocol, p.Host, p.Port, p.SNI
	row.Name = p.Protocol + "@" + p.Host + ":" + strconv.Itoa(p.Port)

	// Quick TCP ping to the server (connect to host).
	t0 := time.Now()
	if c, e := net.DialTimeout("tcp", net.JoinHostPort(p.Host, strconv.Itoa(p.Port)), 3*time.Second); e == nil {
		row.PingMs = int(time.Since(t0).Milliseconds())
		_ = c.Close()
	}

	outHost, outPort := p.Host, p.Port
	if !opts.Direct {
		outHost, outPort = opts.ProxyHost, opts.ProxyPort
	}
	cfgPath, err := buildConfig(p, outHost, outPort, "127.0.0.1", socksPort)
	if err != nil {
		row.Error = "config: " + err.Error()
		return row
	}
	defer os.Remove(cfgPath)

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(opts.TimeoutSec+6)*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "-c", cfgPath)
	var out lockBuf
	cmd.Stdout, cmd.Stderr = &out, &out
	hideWindow(cmd)
	if err := cmd.Start(); err != nil {
		row.Error = "start xray: " + err.Error()
		return row
	}
	waitErr := make(chan error, 1)
	go func() { waitErr <- cmd.Wait() }()
	defer func() { _ = cmd.Process.Kill() }()

	socksAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(socksPort))
	ready := false
	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case e := <-waitErr:
			row.Error = "xray exited: " + procDetail(e, out.String())
			return row
		default:
		}
		if c, e := net.DialTimeout("tcp", socksAddr, 250*time.Millisecond); e == nil {
			_ = c.Close()
			ready = true
			break
		}
		time.Sleep(120 * time.Millisecond)
	}
	if !ready {
		row.Error = "xray not ready: " + procDetail(nil, out.String())
		return row
	}
	// The SOCKS listener accepts immediately, but the WS+TLS outbound needs a
	// moment to warm up. Give it a brief grace period, then try the probe with
	// one retry so a cold-start handshake doesn't show up as a false timeout.
	time.Sleep(250 * time.Millisecond)
	fetchTimeout := time.Duration(opts.TimeoutSec) * time.Second
	start := time.Now()
	status, _, err := fetchThroughSocks("127.0.0.1", socksPort, opts.TestURL, fetchTimeout)
	if err != nil {
		time.Sleep(400 * time.Millisecond)
		start = time.Now()
		status, _, err = fetchThroughSocks("127.0.0.1", socksPort, opts.TestURL, fetchTimeout)
	}
	if err != nil {
		row.Error = "fetch: " + truncate(err.Error(), 90)
		return row
	}
	row.RelayMs = int(time.Since(start).Milliseconds())
	row.HTTPStatus = status
	row.OK = status > 0 && status < 500
	if !row.OK {
		row.Error = "HTTP " + strconv.Itoa(status)
		return row
	}
	row.DownKbps, row.UpKbps = -1, -1
	if opts.WithSpeeds {
		spTimeout := time.Duration(opts.TimeoutSec) * time.Second
		if down, derr := MeasureDownload("127.0.0.1", socksPort, opts.DownloadBytes, spTimeout); derr == nil {
			row.DownKbps = down
		} else {
			row.Error = "download: " + truncateErr(derr, 80)
		}
		if up, uerr := MeasureUpload("127.0.0.1", socksPort, opts.UploadBytes, spTimeout); uerr == nil {
			row.UpKbps = up
		} else if row.Error == "" {
			row.Error = "upload: " + truncateErr(uerr, 80)
		}
	}
	return row
}

// ---- persistent on-device runner ------------------------------------------

// RunOptions configures a long-running xray instance the device can use.
type RunOptions struct {
	URI        string
	BinPath    string
	SocksPort  int    // local SOCKS inbound (default 10808)
	ListenHost string // 127.0.0.1, or 0.0.0.0 to share on the LAN
	ProxyHost  string // when !Direct, route the outbound through this local proxy
	ProxyPort  int
	Direct     bool // connect straight to the config server (default behaviour)
}

// Runner supervises a persistent xray process exposing a local SOCKS proxy.
type Runner struct {
	mu      sync.Mutex
	cmd     *exec.Cmd
	cfgPath string
	bin     string
	uri     string
	listen  string
	port    int
	log     LogFunc
}

// NewRunner creates a Runner. log may be nil.
func NewRunner(log LogFunc) *Runner {
	if log == nil {
		log = func(string, string) {}
	}
	return &Runner{log: log}
}

// Running reports whether xray is currently supervised.
func (r *Runner) Running() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.cmd != nil
}

// Status returns a snapshot for the UI.
func (r *Runner) Status() map[string]any {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cmd == nil {
		return map[string]any{"running": false}
	}
	server := ""
	if p := sni.ParseURI(r.uri); p.Valid {
		server = net.JoinHostPort(p.Host, strconv.Itoa(p.Port))
	}
	socks := ""
	if r.port > 0 {
		socks = net.JoinHostPort(r.listen, strconv.Itoa(r.port))
	}
	return map[string]any{
		"running": true,
		"socks":   socks,
		"uri":     r.uri,
		"server":  server,
		"bin":     r.bin,
	}
}

// Start launches xray with a SOCKS inbound for device-wide use. If an instance
// is already running, it is stopped first so Start always switches to the new
// config (e.g. clicking Connect on a different IP).
func (r *Runner) Start(opts RunOptions) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cmd != nil {
		r.log("Switching connection — stopping current xray…", "DIM")
		r.stopLocked()
	}
	bin := ResolveBin(opts.BinPath)
	if bin == "" {
		return errors.New("xray binary not found — set its path or use Download")
	}
	p := sni.ParseURI(opts.URI)
	if !p.Valid {
		return errors.New("invalid URI: " + p.Error)
	}
	if opts.SocksPort == 0 {
		opts.SocksPort = 10808
	}
	if opts.ListenHost == "" {
		opts.ListenHost = "127.0.0.1"
	}
	outHost, outPort := p.Host, p.Port
	if !opts.Direct && opts.ProxyHost != "" {
		outHost, outPort = opts.ProxyHost, opts.ProxyPort
	}
	cfgPath, err := buildConfig(p, outHost, outPort, opts.ListenHost, opts.SocksPort)
	if err != nil {
		return err
	}

	cmd := exec.Command(bin, "-c", cfgPath)
	var out lockBuf
	cmd.Stdout, cmd.Stderr = &out, &out
	hideWindow(cmd)
	if err := cmd.Start(); err != nil {
		_ = os.Remove(cfgPath)
		return errors.New("failed to start xray: " + err.Error())
	}
	waitErr := make(chan error, 1)
	go func() { waitErr <- cmd.Wait() }()

	// Wait until the SOCKS inbound accepts, or xray exits.
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(opts.SocksPort))
	ready := false
	deadline := time.Now().Add(7 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case e := <-waitErr:
			_ = os.Remove(cfgPath)
			return errors.New("xray exited before it was ready" + procDetail(e, out.String()))
		default:
		}
		if c, e := net.DialTimeout("tcp", addr, 300*time.Millisecond); e == nil {
			_ = c.Close()
			ready = true
			break
		}
		time.Sleep(150 * time.Millisecond)
	}
	if !ready {
		_ = cmd.Process.Kill()
		_ = os.Remove(cfgPath)
		return errors.New("xray did not open its SOCKS port" + procDetail(nil, out.String()))
	}

	r.cmd, r.cfgPath, r.bin = cmd, cfgPath, bin
	r.uri, r.listen, r.port = opts.URI, opts.ListenHost, opts.SocksPort
	r.log("xray running — SOCKS5 on "+net.JoinHostPort(opts.ListenHost, strconv.Itoa(opts.SocksPort)), "OK")
	return nil
}

// stopLocked kills the running process; callers must hold r.mu.
// StartRaw launches xray with a full, user-supplied config (e.g. an imported
// MITM-DomainFronting JSON). The config brings its own inbounds, so we don't
// build one or assume a SOCKS port — we run it and confirm it stays up.
func (r *Runner) StartRaw(binPath, rawConfig string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cmd != nil {
		r.log("Switching connection — stopping current xray…", "DIM")
		r.stopLocked()
	}
	bin := ResolveBin(binPath)
	if bin == "" {
		return errors.New("xray binary not found — set its path or use Download")
	}
	if strings.TrimSpace(rawConfig) == "" {
		return errors.New("empty config")
	}
	var probe map[string]any
	if err := json.Unmarshal([]byte(rawConfig), &probe); err != nil {
		return errors.New("not a valid Xray JSON config: " + err.Error())
	}
	if _, ok := probe["outbounds"]; !ok {
		return errors.New("this JSON is not an Xray config (no outbounds)")
	}
	f, err := os.CreateTemp("", "v2rayez-raw-*.json")
	if err != nil {
		return err
	}
	cfgPath := f.Name()
	_, _ = f.WriteString(rawConfig)
	_ = f.Close()

	cmd := exec.Command(bin, "-c", cfgPath)
	var out lockBuf
	cmd.Stdout, cmd.Stderr = &out, &out
	hideWindow(cmd)
	if err := cmd.Start(); err != nil {
		_ = os.Remove(cfgPath)
		return errors.New("failed to start xray: " + err.Error())
	}
	waitErr := make(chan error, 1)
	go func() { waitErr <- cmd.Wait() }()
	// Raw config controls its own ports, so just confirm it doesn't exit early.
	select {
	case e := <-waitErr:
		_ = os.Remove(cfgPath)
		return errors.New("xray exited before it was ready" + procDetail(e, out.String()))
	case <-time.After(2500 * time.Millisecond):
	}
	r.cmd = cmd
	r.cfgPath = cfgPath
	r.bin = bin
	r.uri = ""
	r.listen = "127.0.0.1"
	r.port = firstInboundPort(probe)
	go func() {
		<-waitErr
		r.mu.Lock()
		if r.cmd == cmd {
			r.cmd, r.cfgPath = nil, ""
		}
		r.mu.Unlock()
	}()
	r.log("xray started with imported config.", "OK")
	return nil
}

// firstInboundPort returns the port of the first inbound in a parsed config (so
// the UI can show "SOCKS5: 127.0.0.1:<port>"), or 0.
func firstInboundPort(cfg map[string]any) int {
	ins, _ := cfg["inbounds"].([]any)
	for _, in := range ins {
		m, ok := in.(map[string]any)
		if !ok {
			continue
		}
		proto, _ := m["protocol"].(string)
		if proto == "tunnel" || proto == "dokodemo-door" || proto == "dns" {
			continue // skip helper inbounds; we want the SOCKS/HTTP/mixed one
		}
		if p, ok := m["port"].(float64); ok {
			return int(p)
		}
	}
	return 0
}

func (r *Runner) stopLocked() {
	if r.cmd == nil {
		return
	}
	_ = r.cmd.Process.Kill()
	_, _ = r.cmd.Process.Wait()
	if r.cfgPath != "" {
		_ = os.Remove(r.cfgPath)
	}
	r.cmd, r.cfgPath = nil, ""
	// Give the OS a moment to release the SOCKS listening port before a restart.
	time.Sleep(120 * time.Millisecond)
}

// Stop terminates the supervised xray process.
func (r *Runner) Stop() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cmd == nil {
		return
	}
	r.stopLocked()
	r.log("xray stopped", "WARN")
}

// ---- download from GitHub releases ----------------------------------------

func assetName() (string, error) {
	osName := map[string]string{"windows": "windows", "linux": "linux", "darwin": "macos"}[runtime.GOOS]
	if osName == "" {
		return "", errors.New("unsupported OS: " + runtime.GOOS)
	}
	arch := map[string]string{"amd64": "64", "386": "32", "arm64": "arm64-v8a"}[runtime.GOARCH]
	if arch == "" {
		return "", errors.New("unsupported arch: " + runtime.GOARCH)
	}
	return "Xray-" + osName + "-" + arch + ".zip", nil
}

// Download fetches the latest Xray-core release for this OS/arch from GitHub and
// extracts the binary into destDir. Returns the binary path.
func Download(destDir string, log LogFunc) (string, error) {
	if log == nil {
		log = func(string, string) {}
	}
	if destDir == "" {
		destDir, _ = os.Getwd()
	}
	want, err := assetName()
	if err != nil {
		return "", err
	}
	log("Resolving latest Xray-core release…", "ACCENT")
	tag, err := ghdl.LatestTag("XTLS/Xray-core")
	if err != nil {
		return "", err
	}
	url := ghdl.AssetURL("XTLS/Xray-core", tag, want)
	log("Downloading "+want+" ("+tag+")…", "ACCENT")
	data, err := ghdl.Download(url)
	if err != nil {
		return "", err
	}
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return "", err
	}
	binName := "xray"
	if runtime.GOOS == "windows" {
		binName = "xray.exe"
	}
	// Extract the WHOLE archive (xray + geoip.dat + geosite.dat + wintun.dll on
	// Windows) into a dedicated xray-core/ folder so TUN mode and routing data
	// files are all present together.
	coreDir := filepath.Join(destDir, "xray-core")
	if err := os.MkdirAll(coreDir, 0o755); err != nil {
		return "", err
	}
	binPath := ""
	for _, f := range zr.File {
		name := filepath.Base(f.Name)
		if name == "" || f.FileInfo().IsDir() {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return "", err
		}
		outPath := filepath.Join(coreDir, name)
		out, err := os.OpenFile(outPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
		if err != nil {
			rc.Close()
			return "", err
		}
		if _, err := io.Copy(out, rc); err != nil {
			out.Close()
			rc.Close()
			return "", err
		}
		out.Close()
		rc.Close()
		if name == binName {
			binPath = outPath
		}
	}
	if binPath == "" {
		return "", errors.New(binName + " not found inside the release archive")
	}
	log("✓ Xray-core extracted to "+coreDir+" (binary, geoip/geosite, wintun.dll)", "OK")
	return binPath, nil
}
