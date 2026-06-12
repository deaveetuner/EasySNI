// Package mitmdf implements fully client-side domain fronting.
//
// It runs a local HTTP/HTTPS proxy that MITMs the browser's TLS using a local
// CA the user installs once. For every request it reads the real Host, then
// re-opens the outbound connection to the target's CDN edge presenting an
// *allowed* front SNI (e.g. www.google.com) while carrying the real Host inside
// the now-re-encrypted request. The censor only ever sees an ordinary TLS
// session to the front domain; the CDN routes by Host to the real site.
//
//	browser ──TLS(local CA)──► V2RayEz MITM ──TLS(SNI=front, Host=real)──► CDN edge ──► real site
//
// This is an original, self-contained implementation of that idea — no upstream
// project is contacted or required. Which front to use per host is a simple,
// fully editable suffix→front map. Thanks to patterniha for documenting the
// technique.
package mitmdf

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"sync"
	"time"
)

// LogFunc receives log lines.
type LogFunc func(msg, level string)

// Rule maps a host suffix to the front SNI used when reaching it. By default the
// connection still goes to the real destination IP (only the TLS SNI is swapped
// to Front); set Dial to also redirect the TCP connection to a specific front
// host (needed for CDNs like Fastly that refuse a mismatched SNI/Host pair).
type Rule struct {
	Match string `json:"match"`          // e.g. "google.com" (matches host or *.host)
	Front string `json:"front"`          // TLS SNI to present, e.g. "www.google.com"
	Dial  string `json:"dial,omitempty"` // optional host to connect to instead of the real host
}

// Config holds the proxy settings.
type Config struct {
	ListenHost string `json:"listen_host"`
	ListenPort int    `json:"listen_port"`
	Rules      []Rule `json:"rules"`
	Default    string `json:"default"` // front for unmatched hosts ("" = pass through)
	// DoH resolver (fronted) — used so real hosts aren't resolved via the
	// censor's poisoned DNS. Defaults to Cloudflare 1.1.1.1 fronted by an
	// allowed SNI, mirroring the reference config's tls-repack-dns.
	DoHIP   string `json:"doh_ip"`   // IP literal to dial (no DNS needed), e.g. 1.1.1.1; blank = resolve DoHHost via OS DNS
	DoHSNI  string `json:"doh_sni"`  // SNI to present for the DoH connection (blank = use DoHHost)
	DoHHost string `json:"doh_host"` // HTTP Host / DoH server name, e.g. cloudflare-dns.com
	DoHPath string `json:"doh_path"` // DoH query path, e.g. /dns-query
}

// DefaultRules is a starting, fully-editable mapping of common CDN-hosted
// services to a front domain that lives on the same CDN edge. The groupings and
// front domains mirror the patterniha MITM-DomainFronting v22 config
// (tls-repack-google / -fastly / -meta), expanded from its geosite categories
// into concrete host suffixes.
func DefaultRules() []Rule {
	g := "www.google.com"               // tls-repack-google (SNI swap on real IP)
	fastly := "github.githubassets.com" // tls-repack-fastly (redirect to this front)
	meta := "www.microsoft.com"         // tls-repack-meta   (SNI swap on real IP)
	gr := func(m string) Rule { return Rule{Match: m, Front: g} }
	mr := func(m string) Rule { return Rule{Match: m, Front: meta} }
	fr := func(m string) Rule { return Rule{Match: m, Front: fastly, Dial: fastly} }
	return []Rule{
		// --- Google family → www.google.com (connect to the real IP, spoof SNI) ---
		gr("google.com"), gr("youtube.com"), gr("youtu.be"), gr("googlevideo.com"),
		gr("ytimg.com"), gr("ggpht.com"), gr("gstatic.com"), gr("googleusercontent.com"),
		gr("googleapis.com"), gr("withgoogle.com"), gr("google.dev"), gr("gvt1.com"),
		gr("android.com"), gr("dns.google"), gr("g.co"), gr("goo.gl"),
		// --- Fastly + GitHub + Reddit + CNN + BuzzFeed → dial github.githubassets.com ---
		fr("python.org"), fr("pypi.org"), fr("pythonhosted.org"),
		fr("fastly.com"), fr("fastly.net"), fr("developer.fastly.com"),
		fr("reddit.com"), fr("redd.it"), fr("redditstatic.com"), fr("redditmedia.com"),
		fr("githubassets.com"), fr("githubusercontent.com"),
		fr("cnn.com"), fr("buzzfeed.com"),
		// --- Meta family → www.microsoft.com (connect to the real IP, spoof SNI) ---
		mr("facebook.com"), mr("fb.com"), mr("fbcdn.net"), mr("fbsbx.com"),
		mr("instagram.com"), mr("cdninstagram.com"),
		mr("whatsapp.com"), mr("whatsapp.net"), mr("messenger.com"),
		mr("meta.com"), mr("oculus.com"), mr("internet.org"), mr("wit.ai"),
		// --- Akamai CDN → www.microsoft.com (Microsoft is Akamai-hosted; SNI swap on real IP) ---
		mr("akamai.net"), mr("akamaiedge.net"), mr("akamaihd.net"),
		mr("akamaized.net"), mr("edgesuite.net"), mr("edgekey.net"),
		// --- Tor Project (Fastly) → front so moat/bridges work when blocked ---
		{Match: "torproject.org", Front: "github.githubassets.com", Dial: "github.githubassets.com"},
		{Match: "bridges.torproject.org", Front: "github.githubassets.com", Dial: "github.githubassets.com"},
	}
}

var hopHeaders = map[string]bool{
	"connection": true, "proxy-connection": true, "keep-alive": true,
	"transfer-encoding": true, "te": true, "trailer": true, "upgrade": true,
	"proxy-authorization": true, "proxy-authenticate": true,
}

// Runner supervises the local proxy.
type Runner struct {
	mu      sync.Mutex
	ln      net.Listener
	running bool
	cfg     Config
	log     LogFunc

	caCert    *x509.Certificate
	caKey     *ecdsa.PrivateKey
	caPEM     []byte
	leafMu    sync.Mutex
	leafCache map[string]*tls.Certificate

	trMu  sync.Mutex
	trans map[string]*http.Transport
	proxy *httputil.ReverseProxy

	dohClient *http.Client
	dnsMu     sync.Mutex
	dnsCache  map[string]dnsEntry

	logMu  sync.Mutex
	logged map[string]bool // dedupe console lines (per host / per host+error)

	reqs int64
	errs int64
}

type dnsEntry struct {
	ip  string
	exp time.Time
}

// NewRunner builds a runner logging via log.
func NewRunner(log LogFunc) *Runner {
	if log == nil {
		log = func(string, string) {}
	}
	return &Runner{log: log, leafCache: map[string]*tls.Certificate{}, trans: map[string]*http.Transport{}, dnsCache: map[string]dnsEntry{}, logged: map[string]bool{}}
}

// ---- persistence hooks (shared CA store) ----------------------------------

type caStore struct {
	load func(name string) ([]byte, error)
	save func(name string, data []byte) error
}

var store caStore

// SetStore wires CA persistence callbacks.
func SetStore(load func(string) ([]byte, error), save func(string, []byte) error) {
	store = caStore{load: load, save: save}
}

// ---- DoH resolver (fronted, bypasses poisoned OS DNS) ---------------------

func (r *Runner) buildDoHClient() *http.Client {
	ip, sni, host := r.cfg.DoHIP, r.cfg.DoHSNI, r.cfg.DoHHost
	if sni == "" {
		sni = host // present the DoH host's real name when no front is given
	}
	tr := &http.Transport{
		ForceAttemptHTTP2: true,
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			d := net.Dialer{Timeout: 12 * time.Second}
			dialTarget := ip
			if dialTarget == "" {
				dialTarget = host // no IP given: resolve the DoH host via the OS
			}
			raw, err := d.DialContext(ctx, "tcp", net.JoinHostPort(dialTarget, "443"))
			if err != nil {
				return nil, err
			}
			tc := tls.Client(raw, &tls.Config{ServerName: sni, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
			if err := tc.HandshakeContext(ctx); err != nil {
				raw.Close()
				return nil, err
			}
			return tc, nil
		},
		TLSHandshakeTimeout: 12 * time.Second,
	}
	return &http.Client{Transport: tr, Timeout: 15 * time.Second}
}

// resolve returns an IP for host using the fronted DoH server, with a cache.
// IP literals are returned as-is.
func (r *Runner) resolve(ctx context.Context, host string) (string, error) {
	if ip := net.ParseIP(host); ip != nil {
		return host, nil
	}
	r.dnsMu.Lock()
	if e, ok := r.dnsCache[host]; ok && time.Now().Before(e.exp) {
		r.dnsMu.Unlock()
		return e.ip, nil
	}
	r.dnsMu.Unlock()

	path := r.cfg.DoHPath
	if path == "" {
		path = "/dns-query"
	}
	sep := "?"
	if strings.Contains(path, "?") {
		sep = "&"
	}
	url := "https://" + r.cfg.DoHHost + path + sep + "type=A&name=" + host
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	req.Host = r.cfg.DoHHost
	req.Header.Set("Accept", "application/dns-json")
	resp, err := r.dohClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	var out struct {
		Answer []struct {
			Type int    `json:"type"`
			Data string `json:"data"`
		} `json:"Answer"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", err
	}
	for _, a := range out.Answer {
		if a.Type == 1 && net.ParseIP(a.Data) != nil { // A record
			r.dnsMu.Lock()
			r.dnsCache[host] = dnsEntry{ip: a.Data, exp: time.Now().Add(5 * time.Minute)}
			r.dnsMu.Unlock()
			return a.Data, nil
		}
	}
	return "", errors.New("no A record for " + host)
}

// ---- front selection + fronting transports --------------------------------

func (r *Runner) frontDialFor(host string) (front, dial string) {
	host = strings.ToLower(host)
	for _, rule := range r.cfg.Rules {
		m := strings.ToLower(strings.TrimSpace(rule.Match))
		if m == "" {
			continue
		}
		if host == m || strings.HasSuffix(host, "."+m) {
			return rule.Front, rule.Dial
		}
	}
	return r.cfg.Default, ""
}

// frontFor is kept for tests/back-compat (front SNI only).
func (r *Runner) frontFor(host string) string {
	f, _ := r.frontDialFor(host)
	return f
}

// transportFor returns a cached transport. front=="" is a normal direct
// connection (SNI = real host). Otherwise the TLS SNI is swapped to front; the
// TCP connection still goes to the real destination IP unless dial is set, in
// which case it connects to dial:443 instead (classic redirect-style fronting).
func (r *Runner) transportFor(front, dial string) *http.Transport {
	key := front + "\x00" + dial
	r.trMu.Lock()
	defer r.trMu.Unlock()
	if t, ok := r.trans[key]; ok {
		return t
	}
	var t *http.Transport
	if front == "" {
		t = &http.Transport{
			ForceAttemptHTTP2:   true,
			MaxIdleConns:        50,
			IdleConnTimeout:     60 * time.Second,
			TLSHandshakeTimeout: 15 * time.Second,
		}
	} else {
		t = &http.Transport{
			ForceAttemptHTTP2: true,
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				target := dial
				if target == "" {
					// keep the real destination, but resolve it ourselves (the
					// OS resolver may be poisoned to a blackhole like 10.10.34.x)
					if h, _, err := net.SplitHostPort(addr); err == nil {
						target = h
					} else {
						target = addr
					}
				}
				ip, err := r.resolve(ctx, target)
				if err != nil {
					return nil, errors.New("DoH resolve " + target + ": " + err.Error())
				}
				d := net.Dialer{Timeout: 15 * time.Second}
				raw, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip, "443"))
				if err != nil {
					return nil, err
				}
				tc := tls.Client(raw, &tls.Config{
					ServerName:         front, // allowed/front SNI on the wire
					InsecureSkipVerify: true,  // upstream cert won't match the real Host
					MinVersion:         tls.VersionTLS12,
				})
				if err := tc.HandshakeContext(ctx); err != nil {
					raw.Close()
					return nil, err
				}
				return tc, nil
			},
			MaxIdleConns:        50,
			IdleConnTimeout:     60 * time.Second,
			TLSHandshakeTimeout: 15 * time.Second,
		}
	}
	r.trans[key] = t
	return t
}

// frontRT is the reverse-proxy transport: it picks the front per request host.
type frontRT struct{ r *Runner }

func (f frontRT) RoundTrip(req *http.Request) (*http.Response, error) {
	f.r.bump(true)
	host := req.URL.Hostname()
	front, dial := f.r.frontDialFor(host)
	resp, err := f.r.transportFor(front, dial).RoundTrip(req)
	if err != nil {
		f.r.bump(false)
		f.r.noteErr(host, front, err)
	} else {
		f.r.noteReq(host, front, false)
	}
	return resp, err
}

// noteReq logs the first request to each host (so the console shows activity
// without flooding on every request).
func (r *Runner) noteReq(host, front string, blind bool) {
	key := "r:" + host
	r.logMu.Lock()
	if r.logged[key] {
		r.logMu.Unlock()
		return
	}
	r.logged[key] = true
	r.logMu.Unlock()
	if blind || front == "" {
		r.log("▸ "+host+" — direct (no front)", "DIM")
	} else {
		r.log("▸ "+host+" → front "+front, "ACCENT")
	}
}

// noteErr logs each distinct host+reason once so the console explains failures.
func (r *Runner) noteErr(host, front string, err error) {
	msg := err.Error()
	short := msg
	if i := strings.LastIndex(short, ": "); i >= 0 && len(short)-i < 80 {
		short = short[i+2:]
	}
	if len(short) > 90 {
		short = short[:90]
	}
	key := "e:" + host + "|" + short
	r.logMu.Lock()
	if r.logged[key] {
		r.logMu.Unlock()
		return
	}
	r.logged[key] = true
	r.logMu.Unlock()
	r.log("✗ "+host+" (front "+front+"): "+short, "ERROR")
}

func (r *Runner) buildProxy() *httputil.ReverseProxy {
	return &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			for h := range hopHeaders {
				req.Header.Del(h)
			}
		},
		Transport: frontRT{r},
		ErrorHandler: func(w http.ResponseWriter, req *http.Request, err error) {
			http.Error(w, "fronting failed: "+err.Error(), http.StatusBadGateway)
		},
		FlushInterval: 100 * time.Millisecond,
	}
}

// ---- listener / proxy loop ------------------------------------------------

// Start brings up the proxy.
func (r *Runner) Start(cfg Config) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.running {
		r.stopLocked()
	}
	if cfg.ListenHost == "" {
		cfg.ListenHost = "127.0.0.1"
	}
	if cfg.ListenPort == 0 {
		cfg.ListenPort = 8087
	}
	if len(cfg.Rules) == 0 {
		cfg.Rules = DefaultRules()
	}
	if cfg.DoHIP == "" {
		cfg.DoHIP = "1.1.1.1"
	}
	if cfg.DoHSNI == "" {
		cfg.DoHSNI = "www.microsoft.com"
	}
	if cfg.DoHHost == "" {
		cfg.DoHHost = "cloudflare-dns.com"
	}
	r.cfg = cfg
	r.dohClient = r.buildDoHClient()
	r.dnsCache = map[string]dnsEntry{}
	r.logged = map[string]bool{}
	if err := r.ensureCA(); err != nil {
		return err
	}
	r.proxy = r.buildProxy()
	ln, err := net.Listen("tcp", net.JoinHostPort(cfg.ListenHost, itoa(cfg.ListenPort)))
	if err != nil {
		return err
	}
	r.ln = ln
	r.running = true
	r.reqs, r.errs = 0, 0
	go r.serve(ln)
	r.log("MITM domain-fronting proxy on "+ln.Addr().String()+" ("+itoa(len(cfg.Rules))+" front rules)", "OK")
	return nil
}

func (r *Runner) serve(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go r.handle(conn)
	}
}

func (r *Runner) handle(conn net.Conn) {
	br := newBufReader(conn)
	peek, _ := br.Peek(8)
	if strings.HasPrefix(strings.ToUpper(string(peek)), "CONNECT") {
		req, err := http.ReadRequest(br)
		if err != nil {
			conn.Close()
			return
		}
		// No rule and no default front → pass straight through, untouched
		// (no MITM, no CA, no fronting): a plain CONNECT tunnel.
		if front, _ := r.frontDialFor(req.URL.Hostname()); front == "" {
			r.blindTunnel(conn, req)
			return
		}
		r.handleConnect(conn, req)
		return
	}
	// Plain HTTP proxy request (absolute-form URL): serve through the buffer.
	pc := &peekConn{Conn: conn, r: br}
	srv := &http.Server{Handler: r.connHandler("", false)}
	_ = srv.Serve(&oneConnListener{conn: pc, addr: conn.LocalAddr()})
}

// blindTunnel relays a CONNECT straight to the real host with no interception,
// so unmatched traffic behaves exactly like a normal (direct) connection.
func (r *Runner) blindTunnel(conn net.Conn, req *http.Request) {
	hostport := req.URL.Host
	if hostport == "" {
		hostport = req.Host
	}
	if _, _, err := net.SplitHostPort(hostport); err != nil {
		hostport = net.JoinHostPort(hostport, "443")
	}
	up, err := net.DialTimeout("tcp", hostport, 15*time.Second)
	if err != nil {
		host, _, _ := net.SplitHostPort(hostport)
		r.noteErr(host, "direct", err)
		_, _ = io.WriteString(conn, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
		conn.Close()
		return
	}
	if host, _, e := net.SplitHostPort(hostport); e == nil {
		r.noteReq(host, "", true)
	}
	if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		up.Close()
		conn.Close()
		return
	}
	go func() { _, _ = io.Copy(up, conn); up.Close() }()
	_, _ = io.Copy(conn, up)
	conn.Close()
}

// handleConnect answers CONNECT, MITMs the TLS with a leaf cert for the host,
// then serves HTTP over the decrypted connection (keep-alive supported).
func (r *Runner) handleConnect(conn net.Conn, req *http.Request) {
	host := req.URL.Hostname()
	if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		conn.Close()
		return
	}
	leaf, err := r.leafFor(host)
	if err != nil {
		conn.Close()
		return
	}
	tconn := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{*leaf}, MinVersion: tls.VersionTLS12})
	if err := tconn.Handshake(); err != nil {
		conn.Close()
		return
	}
	srv := &http.Server{
		Handler:      r.connHandler(host, true),
		ReadTimeout:  90 * time.Second,
		WriteTimeout: 90 * time.Second,
	}
	_ = srv.Serve(&oneConnListener{conn: tconn, addr: tconn.LocalAddr()})
}

func (r *Runner) connHandler(host string, secure bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Host == "" {
			req.URL.Host = req.Host
		}
		if req.URL.Host == "" {
			req.URL.Host = host
		}
		req.Host = req.URL.Host
		if secure {
			req.URL.Scheme = "https"
		} else if req.URL.Scheme == "" {
			req.URL.Scheme = "http"
		}
		r.proxy.ServeHTTP(w, req)
	})
}

func (r *Runner) bump(req bool) {
	r.mu.Lock()
	if req {
		r.reqs++
	} else {
		r.errs++
	}
	r.mu.Unlock()
}

func (r *Runner) stopLocked() {
	if r.ln != nil {
		r.ln.Close()
		r.ln = nil
	}
	r.running = false
}

// Stop shuts the proxy down.
func (r *Runner) Stop() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.running {
		r.log("MITM domain-fronting proxy stopped", "DIM")
	}
	r.stopLocked()
}

// Running reports whether the proxy is up.
func (r *Runner) Running() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.running
}

// Status returns a UI snapshot.
func (r *Runner) Status() map[string]any {
	r.mu.Lock()
	defer r.mu.Unlock()
	port := r.cfg.ListenPort
	addr := ""
	if r.ln != nil {
		addr = r.ln.Addr().String()
	}
	return map[string]any{
		"running": r.running, "port": port, "addr": addr,
		"requests": r.reqs, "errors": r.errs, "rules": len(r.cfg.Rules),
		"has_ca": r.caCert != nil,
	}
}

// CAPEM returns the CA certificate (PEM) for the user to trust.
func (r *Runner) CAPEM() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.caCert == nil {
		_ = r.ensureCA()
	}
	return r.caPEM
}

// CAKeyPEM returns the CA private key in PEM (EC PRIVATE KEY). Needed to build a
// self-contained Xray MITM config that issues per-host leaf certs on-device.
func (r *Runner) CAKeyPEM() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.caCert == nil {
		_ = r.ensureCA()
	}
	if r.caKey == nil {
		return nil
	}
	keyDER, err := x509.MarshalECPrivateKey(r.caKey)
	if err != nil {
		return nil
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}

// ---- local CA + per-host leaf certs ---------------------------------------

func (r *Runner) ensureCA() error {
	if r.caCert != nil {
		return nil
	}
	if store.load != nil {
		certPEM, e1 := store.load("v2rayez-mitmdf-ca.pem")
		keyPEM, e2 := store.load("v2rayez-mitmdf-ca.key")
		if e1 == nil && e2 == nil && len(certPEM) > 0 && len(keyPEM) > 0 {
			if err := r.loadCA(certPEM, keyPEM); err == nil {
				return nil
			}
		}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "V2RayEz Domain-Fronting CA", Organization: []string{"V2RayEz"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	cert, _ := x509.ParseCertificate(der)
	r.caCert = cert
	r.caKey = key
	r.caPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, _ := x509.MarshalECPrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if store.save != nil {
		_ = store.save("v2rayez-mitmdf-ca.pem", r.caPEM)
		_ = store.save("v2rayez-mitmdf-ca.key", keyPEM)
	}
	return nil
}

func (r *Runner) loadCA(certPEM, keyPEM []byte) error {
	cb, _ := pem.Decode(certPEM)
	kb, _ := pem.Decode(keyPEM)
	if cb == nil || kb == nil {
		return errors.New("bad CA pem")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return err
	}
	key, err := x509.ParseECPrivateKey(kb.Bytes)
	if err != nil {
		return err
	}
	r.caCert, r.caKey, r.caPEM = cert, key, certPEM
	return nil
}

func (r *Runner) leafFor(host string) (*tls.Certificate, error) {
	r.leafMu.Lock()
	defer r.leafMu.Unlock()
	if c, ok := r.leafCache[host]; ok {
		return c, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(2, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, r.caCert, &key.PublicKey, r.caKey)
	if err != nil {
		return nil, err
	}
	leaf := &tls.Certificate{Certificate: [][]byte{der, r.caCert.Raw}, PrivateKey: key}
	r.leafCache[host] = leaf
	return leaf, nil
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
