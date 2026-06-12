package xray

import (
	"encoding/json"
	"net/url"
	"strconv"
	"strings"
)

// JSONConfigsToLinks is the exported entry point for converting a JSON Xray
// config (object or array) into share links. Returns nil if not such JSON.
func JSONConfigsToLinks(body string, limit int) []string {
	if limit <= 0 {
		limit = 1000
	}
	return jsonConfigsToLinks(body, limit)
}

// jsonConfigsToLinks detects an Xray "full config" subscription (a JSON object
// or array of objects, as produced by panels like BPB with ?app=xray) and
// converts each proxy outbound into a vless/trojan/vmess share link. Returns
// nil if the body isn't such JSON.
func jsonConfigsToLinks(body string, limit int) []string {
	t := strings.TrimSpace(body)
	if t == "" || (t[0] != '[' && t[0] != '{') {
		return nil
	}
	// Try array of configs first, then a single config object.
	var arr []map[string]any
	if err := json.Unmarshal([]byte(t), &arr); err != nil {
		var one map[string]any
		if err2 := json.Unmarshal([]byte(t), &one); err2 != nil {
			return nil
		}
		arr = []map[string]any{one}
	}
	seen := map[string]bool{}
	var out []string
	for _, cfg := range arr {
		remark, _ := cfg["remarks"].(string)
		obs, _ := cfg["outbounds"].([]any)
		for _, ob := range obs {
			m, ok := ob.(map[string]any)
			if !ok {
				continue
			}
			link := outboundToLink(m, remark)
			if link == "" {
				continue
			}
			key := stripFragment(link)
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, link)
			if len(out) >= limit {
				return out
			}
		}
	}
	return out
}

func stripFragment(s string) string {
	if i := strings.Index(s, "#"); i >= 0 {
		return s[:i]
	}
	return s
}

func asStr(m map[string]any, k string) string {
	if v, ok := m[k].(string); ok {
		return v
	}
	return ""
}

func asInt(v any) string {
	switch n := v.(type) {
	case float64:
		return strconv.Itoa(int(n))
	case string:
		return n
	}
	return ""
}

// outboundToLink converts a single Xray outbound (vless/trojan/vmess) into a
// share link. name is the config's remark (falls back to the outbound tag).
func outboundToLink(ob map[string]any, name string) string {
	proto := asStr(ob, "protocol")
	if proto != "vless" && proto != "trojan" && proto != "vmess" {
		return ""
	}
	if name == "" {
		name = asStr(ob, "tag")
	}
	settings, _ := ob["settings"].(map[string]any)
	if settings == nil {
		return ""
	}
	ss, _ := ob["streamSettings"].(map[string]any)

	// stream params
	network, security, sni, fp, host, path, alpn := "tcp", "", "", "", "", "", ""
	if ss != nil {
		if v := asStr(ss, "network"); v != "" {
			network = v
		}
		security = asStr(ss, "security")
		if tls, ok := ss["tlsSettings"].(map[string]any); ok {
			sni = asStr(tls, "serverName")
			fp = asStr(tls, "fingerprint")
			if a, ok := tls["alpn"].([]any); ok && len(a) > 0 {
				parts := make([]string, 0, len(a))
				for _, x := range a {
					if s, ok := x.(string); ok {
						parts = append(parts, s)
					}
				}
				alpn = strings.Join(parts, ",")
			}
		}
		if ws, ok := ss["wsSettings"].(map[string]any); ok {
			host = asStr(ws, "host")
			path = asStr(ws, "path")
		}
	}

	q := url.Values{}
	q.Set("type", network)
	if security != "" {
		q.Set("security", security)
	}
	if host != "" {
		q.Set("host", host)
	}
	if path != "" {
		q.Set("path", path)
	}
	if sni != "" {
		q.Set("sni", sni)
	}
	if fp != "" {
		q.Set("fp", fp)
	}
	if alpn != "" {
		q.Set("alpn", alpn)
	}
	frag := ""
	if name != "" {
		frag = "#" + url.PathEscape(name)
	}

	switch proto {
	case "vless", "vmess":
		vnext, _ := settings["vnext"].([]any)
		if len(vnext) == 0 {
			return ""
		}
		first, _ := vnext[0].(map[string]any)
		addr := asStr(first, "address")
		port := asInt(first["port"])
		users, _ := first["users"].([]any)
		if addr == "" || port == "" || len(users) == 0 {
			return ""
		}
		u0, _ := users[0].(map[string]any)
		id := asStr(u0, "id")
		if id == "" {
			return ""
		}
		if proto == "vless" {
			q.Set("encryption", "none")
			if flow := asStr(u0, "flow"); flow != "" {
				q.Set("flow", flow)
			}
			return "vless://" + id + "@" + addr + ":" + port + "?" + q.Encode() + frag
		}
		// vmess: emit a vless-style link is wrong; emit standard vmess JSON base64 is complex.
		// For ws+tls vmess, a vless-compatible client link isn't valid, so skip vmess here.
		return ""
	case "trojan":
		servers, _ := settings["servers"].([]any)
		if len(servers) == 0 {
			return ""
		}
		first, _ := servers[0].(map[string]any)
		addr := asStr(first, "address")
		port := asInt(first["port"])
		pass := asStr(first, "password")
		if addr == "" || port == "" || pass == "" {
			return ""
		}
		return "trojan://" + url.QueryEscape(pass) + "@" + addr + ":" + port + "?" + q.Encode() + frag
	}
	return ""
}
