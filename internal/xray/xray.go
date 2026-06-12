// Package xray ports the original app's XrayTester. It locates an xray/v2ray
// binary, writes a temporary config whose outbound points at the locally
// running SNI-spoofing proxy, launches xray, and measures an HTTPS request made
// through xray's local SOCKS inbound. The SOCKS client is stdlib-only.
package xray

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"ezsni/internal/sni"
)

// lockBuf is a tiny concurrency-safe buffer for capturing a child process's
// combined output while another goroutine reads it.
type lockBuf struct {
	mu sync.Mutex
	b  strings.Builder
}

func (l *lockBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// LogFunc receives status lines.
type LogFunc func(msg, level string)

// FindXray returns the path to an xray/v2ray binary, or "" if none is found.
// Search order: the running executable's own directory, the current working
// directory, then PATH, then common install locations.
func FindXray() string {
	names := []string{"xray", "v2ray"}
	if runtime.GOOS == "windows" {
		names = []string{"xray.exe", "v2ray.exe"}
	}

	// 1) Next to this executable (e.g. xray.exe beside project.exe), the
	// xray-core/ subfolder we extract into, then cwd.
	var localDirs []string
	if exe, err := os.Executable(); err == nil {
		if rp, err := filepath.EvalSymlinks(exe); err == nil {
			exe = rp
		}
		localDirs = append(localDirs, filepath.Dir(exe), filepath.Join(filepath.Dir(exe), "xray-core"))
	}
	if cwd, err := os.Getwd(); err == nil {
		localDirs = append(localDirs, cwd, filepath.Join(cwd, "xray-core"))
	}
	for _, d := range localDirs {
		for _, n := range names {
			p := filepath.Join(d, n)
			if st, err := os.Stat(p); err == nil && !st.IsDir() {
				return p
			}
		}
	}

	// 2) PATH.
	for _, n := range names {
		if p, err := exec.LookPath(n); err == nil {
			return p
		}
	}

	// 3) Common install locations.
	home, _ := os.UserHomeDir()
	var candidates []string
	if runtime.GOOS == "windows" {
		candidates = []string{
			`C:\Program Files\xray\xray.exe`,
			`C:\Program Files\v2ray\v2ray.exe`,
			filepath.Join(home, "xray", "xray.exe"),
			filepath.Join(home, "v2ray", "v2ray.exe"),
		}
	} else {
		candidates = []string{
			"/usr/local/bin/xray", "/usr/bin/xray", "/usr/local/bin/v2ray", "/usr/bin/v2ray",
			filepath.Join(home, "xray", "xray"), filepath.Join(home, "v2ray", "v2ray"),
		}
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return ""
}

// Options configures a test run.
type Options struct {
	URI        string // vless:// or vmess:// share link
	BinPath    string // explicit xray/v2ray path; auto-detected when empty
	ProxyHost  string // local SNI-spoof proxy host the outbound dials (default 127.0.0.1)
	ProxyPort  int    // local SNI-spoof proxy port (default 10808)
	Direct     bool   // if true, xray connects straight to the config server (no local proxy)
	SocksPort  int    // local SOCKS inbound xray opens for the test (default 10809)
	TestURL    string // URL to fetch through the tunnel (default https://www.google.com/generate_204)
	TimeoutSec int    // overall request timeout (default 12)
}

// ResolveBin returns the xray path to use: the explicit path if set and present,
// otherwise the auto-detected one ("" if none).
func ResolveBin(explicit string) string {
	explicit = strings.TrimSpace(explicit)
	if explicit != "" {
		if st, err := os.Stat(explicit); err == nil && !st.IsDir() {
			return explicit
		}
	}
	return FindXray()
}

// Result is the outcome of a test run.
type Result struct {
	OK            bool   `json:"ok"`
	Error         string `json:"error"`
	XrayPath      string `json:"xray_path"`
	ResponseMs    int    `json:"response_ms"`
	TotalMs       int    `json:"total_ms"`
	BytesReceived int    `json:"bytes_received"`
	HTTPStatus    int    `json:"http_status"`
	Server        string `json:"server"`
	SNI           string `json:"sni"`
}

// buildConfig writes a temp xray config and returns its path. The outbound dials
// proxyHost:proxyPort (the locally running SNI-spoof proxy); xray's own TLS uses
// the parsed SNI.
func buildConfig(p sni.ParsedURI, outHost string, outPort int, listenHost string, socksPort int) (string, error) {
	if !p.Valid {
		return "", errors.New("invalid URI")
	}
	if listenHost == "" {
		listenHost = "127.0.0.1"
	}
	security := "none"
	if p.TLS {
		security = "tls"
	}
	tlsSettings := map[string]any{
		"serverName": p.SNI,
	}
	if p.ALPN != "" {
		var alpns []any
		for _, a := range strings.Split(p.ALPN, ",") {
			if a = strings.TrimSpace(a); a != "" {
				alpns = append(alpns, a)
			}
		}
		if len(alpns) > 0 {
			tlsSettings["alpn"] = alpns
		}
	}
	if p.Fingerprint != "" {
		tlsSettings["fingerprint"] = p.Fingerprint
	}
	if p.AllowInsecure {
		// Only emit when explicitly enabled. Newer xray cores have removed the
		// field, so the default (false) must omit it entirely.
		tlsSettings["allowInsecure"] = true
	}
	stream := map[string]any{
		"network":     p.Type,
		"security":    security,
		"tlsSettings": tlsSettings,
	}
	if p.Type == "ws" {
		// The WebSocket Host header is the host= value when present (CDN configs
		// connect to one address but set a different Host), else the SNI.
		wsHost := p.WSHost
		if wsHost == "" {
			wsHost = p.SNI
		}
		stream["wsSettings"] = map[string]any{
			"path":    p.Path,
			"headers": map[string]any{"Host": wsHost},
		}
	}

	var outbound map[string]any
	switch p.Protocol {
	case "trojan":
		outbound = map[string]any{
			"protocol": "trojan",
			"settings": map[string]any{"servers": []any{map[string]any{
				"address":  outHost,
				"port":     outPort,
				"password": p.Password,
			}}},
			"streamSettings": stream,
		}
	case "shadowsocks":
		outbound = map[string]any{
			"protocol": "shadowsocks",
			"settings": map[string]any{"servers": []any{map[string]any{
				"address":  outHost,
				"port":     outPort,
				"method":   p.Method,
				"password": p.Password,
			}}},
		}
	default: // vless / vmess
		user := map[string]any{"id": p.UUID}
		if p.Protocol == "vless" {
			user["encryption"] = "none"
		} else {
			user["alterId"] = 0
			user["security"] = "auto"
		}
		outbound = map[string]any{
			"protocol": p.Protocol,
			"settings": map[string]any{"vnext": []any{map[string]any{
				"address": outHost,
				"port":    outPort,
				"users":   []any{user},
			}}},
			"streamSettings": stream,
		}
	}

	cfg := map[string]any{
		"log": map[string]any{"loglevel": "warning"},
		"inbounds": []any{map[string]any{
			"listen":   listenHost,
			"port":     socksPort,
			"protocol": "socks",
			"settings": map[string]any{"auth": "noauth", "udp": true},
		}},
		"outbounds": []any{outbound},
	}
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return "", err
	}
	f, err := os.CreateTemp("", "xray_test_*.json")
	if err != nil {
		return "", err
	}
	defer f.Close()
	if _, err := f.Write(b); err != nil {
		return "", err
	}
	return f.Name(), nil
}

// Test runs the full test and returns timings.
func Test(opts Options, log LogFunc) Result {
	if log == nil {
		log = func(string, string) {}
	}
	if opts.ProxyHost == "" {
		opts.ProxyHost = "127.0.0.1"
	}
	if opts.ProxyPort == 0 {
		opts.ProxyPort = 10808
	}
	if opts.SocksPort == 0 {
		opts.SocksPort = 10809
	}
	if opts.TestURL == "" {
		opts.TestURL = "http://cp.cloudflare.com/generate_204"
	}
	if opts.TimeoutSec == 0 {
		opts.TimeoutSec = 12
	}

	parsed := sni.ParseURI(opts.URI)
	res := Result{Server: parsed.Host, SNI: parsed.SNI, ResponseMs: -1, TotalMs: -1}
	if !parsed.Valid {
		res.Error = "failed to parse URI: " + parsed.Error
		return res
	}

	xrayPath := ResolveBin(opts.BinPath)
	if xrayPath == "" {
		res.Error = "xray/v2ray binary not found — set its path or use Download"
		return res
	}
	res.XrayPath = xrayPath
	log("Using "+xrayPath, "DIM")

	// Determine the outbound target: straight to the config server (Direct) or
	// through the local SNI-spoof proxy.
	outHost, outPort := opts.ProxyHost, opts.ProxyPort
	if opts.Direct {
		outHost, outPort = parsed.Host, parsed.Port
	} else {
		// Pre-flight: the outbound dials the local SNI-spoof proxy. If nothing is
		// listening there, fail fast rather than letting xray emit "closed pipe".
		paddr := net.JoinHostPort(opts.ProxyHost, strconv.Itoa(opts.ProxyPort))
		if c, e := net.DialTimeout("tcp", paddr, 1500*time.Millisecond); e != nil {
			res.Error = "no proxy is listening on " + paddr +
				" — start the SNI Tunnel proxy in PASSTHROUGH mode first, or enable Direct"
			return res
		} else {
			_ = c.Close()
		}
	}

	cfgPath, err := buildConfig(parsed, outHost, outPort, "127.0.0.1", opts.SocksPort)
	if err != nil {
		res.Error = "config: " + err.Error()
		return res
	}
	defer os.Remove(cfgPath)

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(opts.TimeoutSec+8)*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, xrayPath, "-c", cfgPath)
	var out lockBuf
	cmd.Stdout = &out
	cmd.Stderr = &out
	hideWindow(cmd) // no console flash on Windows
	if err := cmd.Start(); err != nil {
		res.Error = "failed to start xray: " + err.Error()
		return res
	}
	// Own the single Wait() here; cleanup only kills.
	waitErr := make(chan error, 1)
	go func() { waitErr <- cmd.Wait() }()
	defer func() { _ = cmd.Process.Kill() }()
	log("xray started, routing through "+opts.ProxyHost+":"+strconv.Itoa(opts.ProxyPort), "ACCENT")

	// Wait until xray's SOCKS inbound is accepting, or it exits, or we time out.
	socksAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(opts.SocksPort))
	ready := false
	deadline := time.Now().Add(7 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case e := <-waitErr:
			res.Error = "xray exited before it was ready" + procDetail(e, out.String())
			return res
		default:
		}
		if c, e := net.DialTimeout("tcp", socksAddr, 300*time.Millisecond); e == nil {
			_ = c.Close()
			ready = true
			break
		}
		time.Sleep(150 * time.Millisecond)
	}
	if !ready {
		res.Error = "xray did not open its SOCKS port " + socksAddr + procDetail(nil, out.String())
		return res
	}

	start := time.Now()
	status, n, err := fetchThroughSocks("127.0.0.1", opts.SocksPort, opts.TestURL, time.Duration(opts.TimeoutSec)*time.Second)
	if err != nil {
		// Surface xray's own log — "EOF" alone is rarely actionable.
		res.Error = "request through tunnel failed: " + truncate(err.Error(), 140) + procDetail(nil, out.String())
		res.TotalMs = int(time.Since(start).Milliseconds())
		return res
	}
	res.ResponseMs = int(time.Since(start).Milliseconds())
	res.TotalMs = res.ResponseMs
	res.HTTPStatus = status
	res.BytesReceived = n
	res.OK = status > 0 && status < 500
	return res
}

// procDetail appends the process exit cause and a trimmed tail of xray's output.
func procDetail(exit error, output string) string {
	var s string
	if exit != nil {
		s += " (" + exit.Error() + ")"
	}
	output = strings.TrimSpace(output)
	if output != "" {
		// keep the last line or two — that is where xray prints the cause
		if len(output) > 300 {
			output = output[len(output)-300:]
		}
		s += " — xray: " + strings.ReplaceAll(output, "\n", " | ")
	} else if exit == nil {
		s += " (no output from xray)"
	}
	return s
}

// fetchThroughSocks performs an HTTP GET to url via a SOCKS5 proxy and returns
// the status code and body length.
func fetchThroughSocks(socksHost string, socksPort int, url string, timeout time.Duration) (int, int, error) {
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return socks5Dial(net.JoinHostPort(socksHost, strconv.Itoa(socksPort)), addr, timeout)
	}
	tr := &http.Transport{DialContext: dial, DisableKeepAlives: true}
	client := &http.Client{Transport: tr, Timeout: timeout}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return 0, 0, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0")
	resp, err := client.Do(req)
	if err != nil {
		return 0, 0, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, len(body), nil
}

// socks5Dial opens a SOCKS5 CONNECT to target ("host:port") via proxyAddr.
func socks5Dial(proxyAddr, target string, timeout time.Duration) (net.Conn, error) {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, err
	}
	c, err := net.DialTimeout("tcp", proxyAddr, timeout)
	if err != nil {
		return nil, err
	}
	_ = c.SetDeadline(time.Now().Add(timeout))

	// Greeting: VER=5, one method (0 = no auth).
	if _, err := c.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		c.Close()
		return nil, err
	}
	rep := make([]byte, 2)
	if _, err := io.ReadFull(c, rep); err != nil {
		c.Close()
		return nil, err
	}
	if rep[0] != 0x05 || rep[1] != 0x00 {
		c.Close()
		return nil, fmt.Errorf("socks5: method rejected (%v)", rep)
	}

	// CONNECT request with a domain-name address type.
	if len(host) > 255 {
		c.Close()
		return nil, errors.New("socks5: host too long")
	}
	buf := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	buf = append(buf, host...)
	var pb [2]byte
	binary.BigEndian.PutUint16(pb[:], uint16(port))
	buf = append(buf, pb[:]...)
	if _, err := c.Write(buf); err != nil {
		c.Close()
		return nil, err
	}

	// Reply: VER, REP, RSV, ATYP, BND.ADDR, BND.PORT.
	head := make([]byte, 4)
	if _, err := io.ReadFull(c, head); err != nil {
		c.Close()
		return nil, err
	}
	if head[1] != 0x00 {
		c.Close()
		return nil, fmt.Errorf("socks5: connect failed (code %d)", head[1])
	}
	var skip int
	switch head[3] {
	case 0x01:
		skip = 4
	case 0x04:
		skip = 16
	case 0x03:
		ln := make([]byte, 1)
		if _, err := io.ReadFull(c, ln); err != nil {
			c.Close()
			return nil, err
		}
		skip = int(ln[0])
	default:
		c.Close()
		return nil, errors.New("socks5: bad reply atyp")
	}
	if _, err := io.ReadFull(c, make([]byte, skip+2)); err != nil {
		c.Close()
		return nil, err
	}
	_ = c.SetDeadline(time.Time{}) // clear deadline for the relayed conn
	return c, nil
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
