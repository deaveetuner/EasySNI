// Package server exposes the suite over a local web UI: an embedded single-page
// control panel, a Server-Sent-Events log stream, and JSON endpoints backing
// each tab (proxy control, SNI/relay/mass scans, Cloudflare scan, URI parsing,
// and the SPlus tunnel).
package server

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"ezsni/internal/desync"
	"ezsni/internal/gtunnel"
	"ezsni/internal/logbus"
	"ezsni/internal/mitmdf"
	"ezsni/internal/proxy"
	"ezsni/internal/psiphon"
	"ezsni/internal/singbox"
	"ezsni/internal/splus"
	"ezsni/internal/tor"
	"ezsni/internal/tun2socks"
	"ezsni/internal/xray"
)

//go:embed web/index.html web/favicon.ico web/favicon.png
var webFS embed.FS

// Server holds the shared application state.
type Server struct {
	bus *logbus.Bus

	mu             sync.Mutex
	proxy          *proxy.Proxy
	tunnel         *splus.Tunnel
	tunOpts        splus.Options
	desyncDefaults desync.Config
	xrayRunner     *xray.Runner
	singboxRunner  *singbox.Runner
	t2s            *tun2socks.Runner
	torr           *tor.Runner
	gtun           *gtunnel.Runner
	mitmdf         *mitmdf.Runner
	psi            *psiphon.Controller
	cdnMu          sync.Mutex
	cdn            *xray.CDNScanState
	cdnCancel      context.CancelFunc
	siteMu         sync.Mutex
	site           *siteScanState
	siteCancel     context.CancelFunc
}

// New returns a Server with a fresh log bus.
func New() *Server {
	s := &Server{bus: logbus.New(), desyncDefaults: desync.DefaultConfig()}
	s.xrayRunner = xray.NewRunner(s.bus.Log)
	s.singboxRunner = singbox.NewRunner(s.bus.Log)
	s.t2s = tun2socks.NewRunner(s.bus.Log)
	s.torr = tor.NewRunner(s.bus.Log)
	s.gtun = gtunnel.NewRunner(s.bus.Log)
	gtunnel.SetStore(readSideFile, writeSideFile)
	s.mitmdf = mitmdf.NewRunner(s.bus.Log)
	mitmdf.SetStore(readSideFile, writeSideFile)
	s.psi = psiphon.New()
	return s
}

// SetDesyncDefaults sets the baseline DPI-evasion config (from CLI flags) used
// for the proxy when the UI request leaves fields unset.
func (s *Server) SetDesyncDefaults(d desync.Config) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.desyncDefaults = d
}

func (s *Server) log(msg, level string) { s.bus.Log(msg, level) }

// Handler builds the HTTP routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/favicon.ico", s.handleFavicon)
	mux.HandleFunc("/favicon.png", s.handleFavicon)
	mux.HandleFunc("/api/events", s.handleEvents)
	mux.HandleFunc("/api/uri/parse", s.jsonPOST(s.handleParseURI))
	mux.HandleFunc("/api/sni/scan", s.jsonPOST(s.handleSNIScan))
	mux.HandleFunc("/api/sni/relay-test", s.jsonPOST(s.handleRelayTest))
	mux.HandleFunc("/api/sni/mass-scan", s.jsonPOST(s.handleMassScan))
	mux.HandleFunc("/api/sites/scan", s.jsonPOST(s.handleSitesScan))
	mux.HandleFunc("/api/sites/scan/status", s.jsonPOST(s.handleSitesScanStatus))
	mux.HandleFunc("/api/sites/scan/stop", s.jsonPOST(s.handleSitesScanStop))
	mux.HandleFunc("/api/sni/saved/save", s.jsonPOST(s.handleSavedSNISave))
	mux.HandleFunc("/api/sni/saved/load", s.jsonPOST(s.handleSavedSNILoad))
	mux.HandleFunc("/api/cf/scan", s.jsonPOST(s.handleCFScan))
	mux.HandleFunc("/api/proxy/start", s.jsonPOST(s.handleProxyStart))
	mux.HandleFunc("/api/proxy/stop", s.jsonPOST(s.handleProxyStop))
	mux.HandleFunc("/api/proxy/status", s.jsonPOST(s.handleProxyStatus))
	mux.HandleFunc("/api/splus/start", s.jsonPOST(s.handleSplusStart))
	mux.HandleFunc("/api/splus/stop", s.jsonPOST(s.handleSplusStop))
	mux.HandleFunc("/api/splus/status", s.jsonPOST(s.handleSplusStatus))
	mux.HandleFunc("/api/xray/test", s.jsonPOST(s.handleXrayTest))
	mux.HandleFunc("/api/xray/mass", s.jsonPOST(s.handleXrayMass))
	mux.HandleFunc("/api/xray/cdnconfigs", s.jsonPOST(s.handleXrayCDNConfigs))
	mux.HandleFunc("/api/xray/cdnconfigs/status", s.jsonPOST(s.handleXrayCDNConfigsStatus))
	mux.HandleFunc("/api/xray/cdnconfigs/stop", s.jsonPOST(s.handleXrayCDNConfigsStop))
	mux.HandleFunc("/api/xray/cdnconfigs/pause", s.jsonPOST(s.handleXrayCDNConfigsPause))
	mux.HandleFunc("/api/xray/cdnconfigs/resume", s.jsonPOST(s.handleXrayCDNConfigsResume))
	mux.HandleFunc("/api/xray/find", s.jsonPOST(s.handleXrayFind))
	mux.HandleFunc("/api/xray/update-configs", s.jsonPOST(s.handleXrayUpdateConfigs))
	mux.HandleFunc("/api/edge/uuid", s.jsonPOST(s.handleEdgeUUID))
	mux.HandleFunc("/api/edge/generate", s.jsonPOST(s.handleEdgeGenerate))
	mux.HandleFunc("/api/qr", s.jsonPOST(s.handleQR))
	mux.HandleFunc("/api/subscribe", s.jsonPOST(s.handleSubscribe))
	mux.HandleFunc("/api/configs/store/save", s.jsonPOST(s.handleConfigsStoreSave))
	mux.HandleFunc("/api/configs/fromjson", s.jsonPOST(s.handleConfigsFromJSON))
	mux.HandleFunc("/api/bpb/gen", s.jsonPOST(s.handleBPBGen))
	mux.HandleFunc("/api/bpb/verify", s.jsonPOST(s.handleBPBVerify))
	mux.HandleFunc("/api/bpb/workerjs", s.jsonPOST(s.handleBPBWorkerJS))
	mux.HandleFunc("/api/bpb/deploy", s.jsonPOST(s.handleBPBDeploy))
	mux.HandleFunc("/api/configs/store/load", s.jsonPOST(s.handleConfigsStoreLoad))
	mux.HandleFunc("/api/configs/folder/load", s.jsonPOST(s.handleConfigsFolderLoad))
	mux.HandleFunc("/api/app/version", s.jsonPOST(s.handleAppVersion))
	mux.HandleFunc("/api/app/update/check", s.jsonPOST(s.handleAppUpdateCheck))
	mux.HandleFunc("/api/app/update/download", s.jsonPOST(s.handleAppUpdateDownload))
	mux.HandleFunc("/api/xray/download", s.jsonPOST(s.handleXrayDownload))
	mux.HandleFunc("/api/xray/start", s.jsonPOST(s.handleXrayStart))
	mux.HandleFunc("/api/xray/startraw", s.jsonPOST(s.handleXrayStartRaw))
	mux.HandleFunc("/api/xray/stop", s.jsonPOST(s.handleXrayStop))
	mux.HandleFunc("/api/xray/status", s.jsonPOST(s.handleXrayStatus))
	mux.HandleFunc("/api/sysproxy/set", s.jsonPOST(s.handleSysproxySet))
	mux.HandleFunc("/api/sysproxy/clear", s.jsonPOST(s.handleSysproxyClear))
	mux.HandleFunc("/api/singbox/find", s.jsonPOST(s.handleSingboxFind))
	mux.HandleFunc("/api/singbox/download", s.jsonPOST(s.handleSingboxDownload))
	mux.HandleFunc("/api/singbox/start", s.jsonPOST(s.handleSingboxStart))
	mux.HandleFunc("/api/singbox/stop", s.jsonPOST(s.handleSingboxStop))
	mux.HandleFunc("/api/singbox/status", s.jsonPOST(s.handleSingboxStatus))
	mux.HandleFunc("/api/tun2socks/download", s.jsonPOST(s.handleTun2socksDownload))
	mux.HandleFunc("/api/tun2socks/start", s.jsonPOST(s.handleTun2socksStart))
	mux.HandleFunc("/api/tun2socks/stop", s.jsonPOST(s.handleTun2socksStop))
	mux.HandleFunc("/api/tun2socks/status", s.jsonPOST(s.handleTun2socksStatus))
	mux.HandleFunc("/api/tor/start", s.jsonPOST(s.handleTorStart))
	mux.HandleFunc("/api/tor/stop", s.jsonPOST(s.handleTorStop))
	mux.HandleFunc("/api/tor/status", s.jsonPOST(s.handleTorStatus))
	mux.HandleFunc("/api/tor/bridges", s.jsonPOST(s.handleTorBridges))
	mux.HandleFunc("/api/tor/moat/fetch", s.jsonPOST(s.handleTorMoatFetch))
	mux.HandleFunc("/api/tor/moat/check", s.jsonPOST(s.handleTorMoatCheck))
	mux.HandleFunc("/api/tor/download", s.jsonPOST(s.handleTorDownload))
	mux.HandleFunc("/api/gtun/scripts", s.jsonPOST(s.handleGtunScripts))
	mux.HandleFunc("/api/gtun/start", s.jsonPOST(s.handleGtunStart))
	mux.HandleFunc("/api/gtun/stop", s.jsonPOST(s.handleGtunStop))
	mux.HandleFunc("/api/gtun/status", s.jsonPOST(s.handleGtunStatus))
	mux.HandleFunc("/api/gtun/ca", s.handleGtunCA)
	mux.HandleFunc("/api/mitmdf/start", s.jsonPOST(s.handleMitmdfStart))
	mux.HandleFunc("/api/mitmdf/stop", s.jsonPOST(s.handleMitmdfStop))
	mux.HandleFunc("/api/mitmdf/status", s.jsonPOST(s.handleMitmdfStatus))
	mux.HandleFunc("/api/mitmdf/defaults", s.jsonPOST(s.handleMitmdfDefaults))
	mux.HandleFunc("/api/mitmdf/ca", s.handleMitmdfCA)
	mux.HandleFunc("/api/mitmdf/phone", s.jsonPOST(s.handleMitmdfPhone))
	mux.HandleFunc("/api/mitmdf/phoneconfig", s.handleMitmdfPhoneConfig)
	mux.HandleFunc("/api/mitmdf/mobileconfig", s.handleMitmdfMobileconfig)
	mux.HandleFunc("/api/windivert/download", s.jsonPOST(s.handleWinDivertDownload))
	mux.HandleFunc("/api/windivert/status", s.jsonPOST(s.handleWinDivertStatus))
	mux.HandleFunc("/api/windivert/install", s.jsonPOST(s.handleWinDivertInstall))
	mux.HandleFunc("/api/windivert/uninstall", s.jsonPOST(s.handleWinDivertUninstall))
	mux.HandleFunc("/api/port/check", s.jsonPOST(s.handlePortCheck))
	mux.HandleFunc("/api/lan/info", s.jsonPOST(s.handleLANInfo))
	mux.HandleFunc("/api/cdn/scan", s.jsonPOST(s.handleCDNScan))
	mux.HandleFunc("/api/psiphon/start", s.jsonPOST(s.handlePsiphonStart))
	mux.HandleFunc("/api/psiphon/stop", s.jsonPOST(s.handlePsiphonStop))
	mux.HandleFunc("/api/psiphon/status", s.jsonPOST(s.handlePsiphonStatus))
	mux.HandleFunc("/api/psiphon/over-mitm", s.jsonPOST(s.handlePsiphonOverMitm))
	mux.HandleFunc("/api/psiphon/download", s.jsonPOST(s.handlePsiphonDownload))
	mux.HandleFunc("/api/psiphon/open", s.jsonPOST(s.handlePsiphonOpen))
	mux.HandleFunc("/api/config/save", s.jsonPOST(s.handleConfigSave))
	mux.HandleFunc("/api/config/load", s.jsonPOST(s.handleConfigLoad))
	return mux
}

// Bus exposes the log bus so main can print a welcome banner.
func (s *Server) Bus() *logbus.Bus { return s.bus }

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	data, err := webFS.ReadFile("web/index.html")
	if err != nil {
		http.Error(w, "ui missing", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(data)
}

// handleFavicon serves the app icon. Chrome's --app window uses the page
// favicon for its window / taskbar icon, so a real .ico here replaces the
// generic browser globe with the V2RayEz logo.
func (s *Server) handleFavicon(w http.ResponseWriter, r *http.Request) {
	name, ctype := "web/favicon.ico", "image/x-icon"
	if strings.HasSuffix(r.URL.Path, ".png") {
		name, ctype = "web/favicon.png", "image/png"
	}
	data, err := webFS.ReadFile(name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("Cache-Control", "public, max-age=86400")
	_, _ = w.Write(data)
}

// handleEvents streams log entries to the browser via SSE.
func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ch, backlog, cancel := s.bus.Subscribe()
	defer cancel()
	for _, e := range backlog {
		writeSSE(w, e)
	}
	flusher.Flush()

	ctx := r.Context()
	keepalive := time.NewTicker(20 * time.Second)
	defer keepalive.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case e, ok := <-ch:
			if !ok {
				return
			}
			writeSSE(w, e)
			flusher.Flush()
		case <-keepalive.C:
			fmt.Fprint(w, ": keepalive\n\n")
			flusher.Flush()
		}
	}
}

func writeSSE(w http.ResponseWriter, e logbus.Entry) {
	b, _ := json.Marshal(e)
	fmt.Fprintf(w, "data: %s\n\n", b)
}

// jsonPOST wraps a handler that decodes JSON and returns a value to encode.
func (s *Server) jsonPOST(fn func(body json.RawMessage) (any, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		var raw json.RawMessage
		if r.ContentLength != 0 {
			if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
				writeJSON(w, map[string]any{"error": "bad json: " + err.Error()})
				return
			}
		}
		out, err := fn(raw)
		if err != nil {
			writeJSON(w, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, out)
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
