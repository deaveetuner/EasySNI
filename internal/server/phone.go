package server

import (
	"encoding/json"
	"fmt"
	"net/http"

	"ezsni/internal/netutil"
)

// buildPhoneV2RayConfig returns a v2ray-core JSON config that routes the
// phone's traffic through this machine's domain-fronting MITM proxy. Import it
// in v2rayNG / v2rayN / Shadowrocket as a "custom config".
func buildPhoneV2RayConfig(lanIP string, mitmPort int) string {
	if lanIP == "" {
		lanIP = "192.168.1.100"
	}
	if mitmPort == 0 {
		mitmPort = 8087
	}
	cfg := map[string]any{
		"log": map[string]any{"loglevel": "warning"},
		"inbounds": []any{
			map[string]any{
				"tag": "socks-in", "port": 10808, "listen": "127.0.0.1", "protocol": "socks",
				"settings": map[string]any{"udp": true, "auth": "noauth"},
				"sniffing": map[string]any{"enabled": true, "destOverride": []string{"http", "tls"}},
			},
			map[string]any{
				"tag": "http-in", "port": 10809, "listen": "127.0.0.1", "protocol": "http",
			},
		},
		"outbounds": []any{
			map[string]any{
				"tag": "proxy", "protocol": "http",
				"settings": map[string]any{
					"servers": []any{map[string]any{"address": lanIP, "port": mitmPort}},
				},
			},
			map[string]any{"tag": "direct", "protocol": "freedom"},
			map[string]any{"tag": "block", "protocol": "blackhole"},
		},
		"routing": map[string]any{
			"domainStrategy": "AsIs",
			"rules": []any{
				map[string]any{"type": "field", "ip": []string{"geoip:private"}, "outboundTag": "direct"},
			},
		},
	}
	b, _ := json.MarshalIndent(cfg, "", "  ")
	return string(b)
}

func (s *Server) handleMitmdfPhone(json.RawMessage) (any, error) {
	st := s.mitmdf.Status()
	port := 8087
	if p, ok := st["port"].(int); ok && p > 0 {
		port = p
	}
	addr, _ := st["addr"].(string)
	lan := netutil.LANAddrs()
	primary := ""
	if len(lan) > 0 {
		primary = lan[0]
	}
	return map[string]any{
		"ok":         true,
		"running":    st["running"],
		"addr":       addr,
		"port":       port,
		"lan_ips":    lan,
		"primary_ip": primary,
		"has_ca":     st["has_ca"],
		"config":     buildPhoneV2RayConfig(primary, port),
	}, nil
}

// handleMitmdfPhoneConfig serves the v2ray config as a downloadable file so a
// phone on the same LAN can fetch it directly (e.g. via a QR-code URL).
func (s *Server) handleMitmdfPhoneConfig(w http.ResponseWriter, r *http.Request) {
	ip := r.URL.Query().Get("ip")
	if ip == "" {
		if l := netutil.LANAddrs(); len(l) > 0 {
			ip = l[0]
		}
	}
	port := 8087
	if p, ok := s.mitmdf.Status()["port"].(int); ok && p > 0 {
		port = p
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", "attachment; filename=v2ray-phone.json")
	fmt.Fprint(w, buildPhoneV2RayConfig(ip, port))
}
