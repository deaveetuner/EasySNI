package xray

import (
	"bufio"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
)

// configFeeds are aggregated public subscription sources, newest-first. Each is
// tried in order until one returns usable share links.
var configFeeds = []string{
	"https://raw.githubusercontent.com/barry-far/V2ray-Config/main/All_Configs_Sub.txt",
	"https://raw.githubusercontent.com/barry-far/V2ray-Config/main/Sub1.txt",
}

// schemes recognised as share links when sifting feed contents.
var shareSchemes = []string{"vless://", "vmess://", "trojan://", "ss://"}

// FetchSubscription fetches a single subscription URL and returns the share
// links it contains. The body may be plain text (one link per line) or a single
// base64 blob; both are handled. De-duplicated, capped at limit.
func FetchSubscription(subURL string, limit int) ([]string, error) {
	if limit <= 0 {
		limit = 1000
	}
	client := &http.Client{Timeout: 20 * time.Second}
	req, err := http.NewRequest("GET", subURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "v2rayN/6.0")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	resp.Body.Close()
	// Panels like BPB return a JSON array of full Xray configs when ?app=xray.
	// Convert those to share links; otherwise treat the body as a link list.
	if links := jsonConfigsToLinks(string(body), limit); len(links) > 0 {
		return links, nil
	}
	return parseShareLinks(string(body), limit), nil
}

// parseShareLinks sifts share links from text, decoding a base64 wrapper first
// when the raw text contains none.
func parseShareLinks(text string, limit int) []string {
	if !containsAnyScheme(text) {
		if dec, ok := decodeMaybeBase64(text); ok {
			text = dec
		}
	}
	seen := map[string]bool{}
	out := []string{}
	sc := bufio.NewScanner(strings.NewReader(text))
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || !hasShareScheme(line) || seen[line] {
			continue
		}
		seen[line] = true
		out = append(out, line)
		if len(out) >= limit {
			break
		}
	}
	return out
}

// FetchLatestConfigs pulls a fresh batch of public share links from the feeds,
// de-duplicates them, and returns up to limit entries. A feed may be plain text
// or base64-wrapped; both are handled.
func FetchLatestConfigs(limit int, log LogFunc) ([]string, error) {
	if log == nil {
		log = func(string, string) {}
	}
	if limit <= 0 {
		limit = 500
	}
	for _, url := range configFeeds {
		links, err := FetchSubscription(url, limit)
		if err != nil {
			log("config update: feed unreachable, trying next", "DIM")
			continue
		}
		if len(links) > 0 {
			log("config update: fetched "+itoa(len(links))+" configs", "OK")
			return links, nil
		}
	}
	return nil, errors.New("no configs found in the update feeds (network blocked?)")
}

func hasShareScheme(s string) bool {
	for _, sc := range shareSchemes {
		if strings.HasPrefix(s, sc) {
			return true
		}
	}
	return false
}

func containsAnyScheme(s string) bool {
	for _, sc := range shareSchemes {
		if strings.Contains(s, sc) {
			return true
		}
	}
	return false
}

// decodeMaybeBase64 attempts to base64-decode a blob (standard or URL-safe,
// with or without padding). Returns (decoded, true) only when the result looks
// like it contains share links.
func decodeMaybeBase64(s string) (string, bool) {
	clean := strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == ' ' || r == '\t' {
			return -1
		}
		return r
	}, s)
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if dec, err := enc.DecodeString(clean); err == nil && containsAnyScheme(string(dec)) {
			return string(dec), true
		}
	}
	return "", false
}

// itoa avoids pulling strconv just for logging here.
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
