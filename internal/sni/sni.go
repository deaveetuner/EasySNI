// Package sni ports the SNI-spoofing diagnostics from the original Python app:
// the V2Ray/VLESS/VMess URI parser, single + relay SNI reachability tests, the
// mass SNI scanner, and the Cloudflare CDN IP scanner.
package sni

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var portRe = regexp.MustCompile(`\d+`)

// SafePort extracts a valid TCP port from raw, falling back to def.
// truthy reports whether a query/JSON value means "on" (1/true/yes).
func truthy(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

func SafePort(raw string, def int) int {
	m := portRe.FindString(raw)
	if m == "" {
		return def
	}
	v, err := strconv.Atoi(m)
	if err != nil || v < 1 || v > 65535 {
		return def
	}
	return v
}

// ParsedURI is the decoded form of a vless:// or vmess:// link.
type ParsedURI struct {
	Raw           string `json:"raw"`
	Protocol      string `json:"protocol"`
	Host          string `json:"host"`
	Port          int    `json:"port"`
	UUID          string `json:"uuid"`
	Password      string `json:"password"` // trojan / shadowsocks
	Method        string `json:"method"`   // shadowsocks cipher
	SNI           string `json:"sni"`
	Type          string `json:"type"`
	Path          string `json:"path"`
	WSHost        string `json:"ws_host"`     // ws/h2 Host header (host=), may differ from server host
	ALPN          string `json:"alpn"`        // comma-separated, e.g. h2,http/1.1
	Fingerprint   string `json:"fingerprint"` // uTLS fingerprint (fp=), e.g. chrome
	TLS           bool   `json:"tls"`
	AllowInsecure bool   `json:"allow_insecure"`
	Valid         bool   `json:"valid"`
	Error         string `json:"error"`
}

// ParseURI parses a vless:// or vmess:// share link. Mirrors parse_v2ray_uri.
func ParseURI(uri string) ParsedURI {
	r := ParsedURI{Raw: uri, Type: "tcp"}
	uri = strings.TrimSpace(uri)
	uri = strings.Trim(uri, `'"`)
	if uri == "" {
		r.Error = "Empty URI"
		return r
	}

	switch {
	case strings.HasPrefix(uri, "vless://"):
		u, err := url.Parse(uri)
		if err != nil {
			r.Error = err.Error()
			return r
		}
		qs := u.Query()
		host := u.Hostname()
		sni := qs.Get("sni")
		if sni == "" {
			sni = host
		}
		typ := qs.Get("type")
		if typ == "" {
			typ = "tcp"
		}
		path := qs.Get("path")
		if path == "" {
			path = "/"
		}
		security := qs.Get("security")
		uuid := ""
		if u.User != nil {
			uuid = u.User.Username()
		}
		r.Protocol = "vless"
		r.Host = host
		r.Port = SafePort(u.Port(), 443)
		r.UUID = uuid
		r.SNI = sni
		r.Type = typ
		r.Path = path
		r.WSHost = qs.Get("host")
		r.ALPN = qs.Get("alpn")
		r.Fingerprint = qs.Get("fp")
		r.TLS = security == "tls" || security == "reality" || security == "xtls"
		r.AllowInsecure = truthy(qs.Get("allowInsecure")) || truthy(qs.Get("allowinsecure"))
		r.Valid = true

	case strings.HasPrefix(uri, "vmess://"):
		b64 := uri[len("vmess://"):]
		if pad := len(b64) % 4; pad != 0 {
			b64 += strings.Repeat("=", 4-pad)
		}
		decoded, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			r.Error = err.Error()
			return r
		}
		var d struct {
			Add  string      `json:"add"`
			Port interface{} `json:"port"`
			ID   string      `json:"id"`
			SNI  string      `json:"sni"`
			Host string      `json:"host"`
			Net  string      `json:"net"`
			Path string      `json:"path"`
			TLS  string      `json:"tls"`
			AI   interface{} `json:"allowInsecure"`
			Vfy  interface{} `json:"verify_cert"`
		}
		if err := json.Unmarshal(decoded, &d); err != nil {
			r.Error = err.Error()
			return r
		}
		sni := d.SNI
		if sni == "" {
			sni = d.Host
		}
		if sni == "" {
			sni = d.Add
		}
		typ := d.Net
		if typ == "" {
			typ = "tcp"
		}
		r.Protocol = "vmess"
		r.Host = d.Add
		r.Port = SafePort(fmt.Sprintf("%v", d.Port), 443)
		r.UUID = d.ID
		r.SNI = sni
		r.Type = typ
		r.Path = d.Path
		r.WSHost = d.Host
		r.TLS = strings.ToLower(d.TLS) == "tls"
		r.AllowInsecure = truthy(fmt.Sprintf("%v", d.AI)) || (d.Vfy != nil && !truthy(fmt.Sprintf("%v", d.Vfy)))
		r.Valid = true

	case strings.HasPrefix(uri, "trojan://"):
		u, err := url.Parse(uri)
		if err != nil {
			r.Error = err.Error()
			return r
		}
		qs := u.Query()
		host := u.Hostname()
		sni := qs.Get("sni")
		if sni == "" {
			sni = qs.Get("peer")
		}
		if sni == "" {
			sni = host
		}
		typ := qs.Get("type")
		if typ == "" {
			typ = "tcp"
		}
		path := qs.Get("path")
		if path == "" {
			path = "/"
		}
		pw := ""
		if u.User != nil {
			pw = u.User.Username()
		}
		r.Protocol = "trojan"
		r.Host = host
		r.Port = SafePort(u.Port(), 443)
		r.Password = pw
		r.SNI = sni
		r.Type = typ
		r.Path = path
		r.WSHost = qs.Get("host")
		r.ALPN = qs.Get("alpn")
		r.Fingerprint = qs.Get("fp")
		r.TLS = qs.Get("security") != "none" // trojan defaults to TLS
		r.AllowInsecure = truthy(qs.Get("allowInsecure")) || truthy(qs.Get("allowinsecure"))
		r.Valid = host != "" && pw != ""
		if !r.Valid && r.Error == "" {
			r.Error = "trojan: missing host or password"
		}

	case strings.HasPrefix(uri, "ss://"):
		method, password, host, port, perr := parseShadowsocks(uri)
		if perr != "" {
			r.Error = perr
			return r
		}
		r.Protocol = "shadowsocks"
		r.Host = host
		r.Port = port
		r.Method = method
		r.Password = password
		r.SNI = host
		r.Type = "tcp"
		r.TLS = false
		r.Valid = host != "" && method != "" && port > 0

	default:
		r.Error = "Unknown protocol"
	}
	return r
}

// decodeB64Loose tries the common base64 variants used in share links.
func decodeB64Loose(s string) (string, bool) {
	s = strings.TrimSpace(s)
	for _, enc := range []*base64.Encoding{
		base64.RawURLEncoding, base64.URLEncoding,
		base64.RawStdEncoding, base64.StdEncoding,
	} {
		if b, err := enc.DecodeString(s); err == nil {
			return string(b), true
		}
	}
	// try with padding fixed for std
	if pad := len(s) % 4; pad != 0 {
		s2 := s + strings.Repeat("=", 4-pad)
		if b, err := base64.StdEncoding.DecodeString(s2); err == nil {
			return string(b), true
		}
	}
	return "", false
}

func splitHostPortLoose(hp string) (string, int) {
	hp = strings.TrimSpace(hp)
	if h, p, err := net.SplitHostPort(hp); err == nil {
		return h, SafePort(p, 0)
	}
	if i := strings.LastIndexByte(hp, ':'); i >= 0 {
		return hp[:i], SafePort(hp[i+1:], 0)
	}
	return hp, 0
}

// parseShadowsocks handles SIP002 (ss://b64(method:pass)@host:port) and the
// legacy fully-base64 form (ss://b64(method:pass@host:port)).
func parseShadowsocks(uri string) (method, password, host string, port int, errStr string) {
	body := strings.TrimPrefix(uri, "ss://")
	if i := strings.IndexByte(body, '#'); i >= 0 { // strip name
		body = body[:i]
	}
	if i := strings.IndexByte(body, '?'); i >= 0 { // strip plugin/query
		body = body[:i]
	}
	body = strings.TrimSpace(body)
	if body == "" {
		return "", "", "", 0, "ss: empty"
	}
	if at := strings.LastIndexByte(body, '@'); at >= 0 {
		userinfo := body[:at]
		host, port = splitHostPortLoose(body[at+1:])
		mp := userinfo
		if dec, ok := decodeB64Loose(userinfo); ok && strings.Contains(dec, ":") {
			mp = dec
		}
		if c := strings.IndexByte(mp, ':'); c >= 0 {
			method, password = mp[:c], mp[c+1:]
		} else {
			return "", "", "", 0, "ss: bad method:password"
		}
	} else {
		dec, ok := decodeB64Loose(body)
		if !ok {
			return "", "", "", 0, "ss: cannot decode"
		}
		at := strings.LastIndexByte(dec, '@')
		if at < 0 {
			return "", "", "", 0, "ss: missing @host:port"
		}
		mp := dec[:at]
		host, port = splitHostPortLoose(dec[at+1:])
		if c := strings.IndexByte(mp, ':'); c >= 0 {
			method, password = mp[:c], mp[c+1:]
		} else {
			return "", "", "", 0, "ss: bad method:password"
		}
	}
	if host == "" || port == 0 {
		return "", "", "", 0, "ss: missing host/port"
	}
	return method, password, host, port, ""
}

func tlsConfig(serverName string) *tls.Config {
	return &tls.Config{ServerName: serverName, InsecureSkipVerify: true} //nolint:gosec // SNI-spoofing tool intentionally skips verification
}

// SNIResult is the outcome of a single SNI reachability check.
type SNIResult struct {
	Host    string `json:"host"`
	IP      string `json:"ip"` // resolved address actually connected to
	OK      bool   `json:"ok"`
	Latency int    `json:"latency"` // ms, -1 on failure
	Error   string `json:"error"`
}

// CheckSNI dials host:port and completes a TLS handshake using host as SNI.
// Mirrors check_sni_reachable. It also reports the resolved peer IP.
func CheckSNI(host string, port int, timeout time.Duration) SNIResult {
	start := time.Now()
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return SNIResult{Host: host, OK: false, Latency: -1, Error: trunc(err.Error(), 60)}
	}
	defer conn.Close()
	ip := ""
	if ra, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		ip = ra.IP.String()
	}
	tc := tls.Client(conn, tlsConfig(host))
	_ = tc.SetDeadline(time.Now().Add(timeout))
	if err := tc.Handshake(); err != nil {
		return SNIResult{Host: host, IP: ip, OK: false, Latency: -1, Error: trunc(err.Error(), 60)}
	}
	return SNIResult{Host: host, IP: ip, OK: true, Latency: int(time.Since(start).Milliseconds())}
}

// RelayResult reports timings for the connect/handshake/relay stages.
type RelayResult struct {
	TCPMs   int    `json:"tcp_ms"`
	TLSMs   int    `json:"tls_ms"`
	RelayMs int    `json:"relay_ms"`
	OK      bool   `json:"ok"`
	Error   string `json:"error"`
}

// RelayTest dials connectIP:connectPort, handshakes with fakeSNI, then sends a
// minimal HEAD request and waits for any response. Mirrors relay_test.
func RelayTest(connectIP string, connectPort int, fakeSNI string, timeout time.Duration) RelayResult {
	res := RelayResult{TCPMs: -1, TLSMs: -1, RelayMs: -1}
	addr := net.JoinHostPort(connectIP, strconv.Itoa(connectPort))

	t0 := time.Now()
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		res.Error = trunc(err.Error(), 80)
		return res
	}
	defer conn.Close()
	res.TCPMs = int(time.Since(t0).Milliseconds())

	t1 := time.Now()
	tc := tls.Client(conn, tlsConfig(fakeSNI))
	_ = tc.SetDeadline(time.Now().Add(timeout))
	if err := tc.Handshake(); err != nil {
		res.Error = trunc(err.Error(), 80)
		return res
	}
	res.TLSMs = int(time.Since(t1).Milliseconds())

	t2 := time.Now()
	req := fmt.Sprintf("HEAD / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\nUser-Agent: SNI-Probe/1.0\r\n\r\n", fakeSNI)
	if _, err := tc.Write([]byte(req)); err != nil {
		res.Error = trunc(err.Error(), 80)
		return res
	}
	buf := make([]byte, 256)
	n, _ := tc.Read(buf)
	res.RelayMs = int(time.Since(t2).Milliseconds())
	res.OK = n > 0
	return res
}

// MassResult is one row of a mass SNI scan.
type MassResult struct {
	SNI     string `json:"sni"`
	OK      bool   `json:"ok"`
	TCPMs   int    `json:"tcp_ms"`
	TLSMs   int    `json:"tls_ms"`
	TotalMs int    `json:"total_ms"`
	HTTPOK  bool   `json:"http_ok"`
	Error   string `json:"error"`
}

// MassTest is the per-SNI probe used by the mass scanner. Mirrors
// MassSNIScanner.test_sni_via_ip.
func MassTest(connectIP string, connectPort int, sniName string, timeout time.Duration) MassResult {
	res := MassResult{SNI: sniName, TCPMs: -1, TLSMs: -1, TotalMs: -1}
	addr := net.JoinHostPort(connectIP, strconv.Itoa(connectPort))

	t0 := time.Now()
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		res.Error = trunc(err.Error(), 40)
		return res
	}
	defer conn.Close()
	res.TCPMs = int(time.Since(t0).Milliseconds())

	t1 := time.Now()
	tc := tls.Client(conn, tlsConfig(sniName))
	_ = tc.SetDeadline(time.Now().Add(timeout))
	if err := tc.Handshake(); err != nil {
		res.Error = "SSL: " + trunc(err.Error(), 40)
		return res
	}
	res.TLSMs = int(time.Since(t1).Milliseconds())

	t2 := time.Now()
	req := fmt.Sprintf("HEAD / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", sniName)
	if _, err := tc.Write([]byte(req)); err != nil {
		res.Error = trunc(err.Error(), 40)
		return res
	}
	buf := make([]byte, 512)
	n, _ := tc.Read(buf)
	res.HTTPOK = n > 0
	res.OK = res.HTTPOK
	res.TotalMs = int(time.Since(t2).Milliseconds())
	return res
}

func trunc(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
