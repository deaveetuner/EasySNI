// Package bpb deploys the BPB Worker Panel (github.com/bia-pain-bache/
// BPB-Worker-Panel) to a user's Cloudflare account, mirroring what BPB-Wizard
// does — create a KV namespace, upload worker.js with the kv binding and the
// UUID / TR_PASS / PROXY_IP / FALLBACK / SUB_PATH variables, enable the
// workers.dev subdomain, and return the panel + subscription URLs.
//
// Auth uses a Cloudflare API token (Workers Scripts:Edit, Workers KV:Edit,
// Account Settings:Read) rather than the OAuth PKCE flow, which is simpler and
// keeps the secret on the user's machine.
package bpb

import (
	"bytes"
	"crypto/rand"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"strings"
	"time"
)

// embeddedWorker is our own pre-built BPB panel (built from the bundled source).
// EzBPB deploys this to the client's Cloudflare Worker — no runtime download
// from any external repo.
//
//go:embed assets/worker.js
var embeddedWorker []byte

// PanelVersion is the bundled panel's version.
const PanelVersion = "4.7.5"

const (
	cfAPI      = "https://api.cloudflare.com/client/v4"
	compatDate = "2024-09-23"
	// No proxy default: when PROXY_IP is left empty the panel uses its own
	// rotating clean IPs. Fallback is Cloudflare's neutral speed-test host.
	defaultFallbk = "hcaptcha.com"
)

// LogFunc receives progress lines (msg, level).
type LogFunc func(string, string)

// Options configures a deployment.
type Options struct {
	Token     string // Cloudflare API token
	AccountID string // optional; if empty, the first account on the token is used
	Name      string // worker/project name (avoid "bpb","vpn","proxy")
	UUID      string // VLESS UUID + default panel password
	TrojanPwd string // Trojan password
	ProxyIP   string // PROXY_IP (comma-separated allowed); empty = panel's own rotating IPs
	Fallback  string // FALLBACK domain
	SubPath   string // SUB_PATH (subscription URI segment)
	PanelPwd  string // password to log into the panel (set on first /panel visit)
	Script    string // optional edited worker.js; empty = use SourceURL or bundled
	SourceURL string // optional URL (your own mirror) to fetch worker.js from
	Mode      string // "worker" (default) or "pages"
}

// FetchFromURL downloads a worker.js from an arbitrary URL (a mirror you
// control), following redirects.
func FetchFromURL(url string) ([]byte, error) {
	if strings.TrimSpace(url) == "" {
		return nil, errors.New("empty URL")
	}
	hc := &http.Client{Timeout: 60 * time.Second}
	resp, err := hc.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("download failed (HTTP %d)", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	if len(b) < 1000 {
		return nil, errors.New("downloaded file looks too small to be worker.js")
	}
	return b, nil
}

// Result is returned after a successful deploy.
type Result struct {
	Name      string `json:"name"`
	Subdomain string `json:"subdomain"`
	PanelURL  string `json:"panel_url"`
	SubURL    string `json:"sub_url"`
	UUID      string `json:"uuid"`
	TrojanPwd string `json:"trojan_password"`
	SubPath   string `json:"sub_path"`
	PanelPwd  string `json:"panel_password"`
}

type client struct {
	token string
	hc    *http.Client
}

func newClient(token string) *client {
	// Cloudflare's worker/pages upload can take well over a minute to return
	// headers; a short timeout was causing "context deadline exceeded".
	return &client{token: token, hc: &http.Client{Timeout: 4 * time.Minute}}
}

// cfEnvelope is Cloudflare's standard response wrapper.
type cfEnvelope struct {
	Success bool              `json:"success"`
	Errors  []json.RawMessage `json:"errors"`
	Result  json.RawMessage   `json:"result"`
}

func (c *client) do(method, path, contentType string, body io.Reader) (json.RawMessage, error) {
	req, err := http.NewRequest(method, cfAPI+path, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	var env cfEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("cloudflare returned non-JSON (HTTP %d)", resp.StatusCode)
	}
	if !env.Success {
		return nil, errors.New(cfErr(env.Errors, resp.StatusCode))
	}
	return env.Result, nil
}

func cfErr(errs []json.RawMessage, status int) string {
	var msgs []string
	for _, e := range errs {
		var m struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		}
		if json.Unmarshal(e, &m) == nil && m.Message != "" {
			msgs = append(msgs, fmt.Sprintf("%s (code %d)", m.Message, m.Code))
		}
	}
	if len(msgs) == 0 {
		return fmt.Sprintf("Cloudflare API error (HTTP %d)", status)
	}
	return strings.Join(msgs, "; ")
}

// VerifyToken checks the token and returns the first account (id, name).
func VerifyToken(token string) (accountID, accountName string, err error) {
	c := newClient(token)
	if _, err = c.do("GET", "/user/tokens/verify", "", nil); err != nil {
		return "", "", errors.New("token verification failed: " + err.Error())
	}
	res, err := c.do("GET", "/accounts", "", nil)
	if err != nil {
		return "", "", err
	}
	var accts []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if err := json.Unmarshal(res, &accts); err != nil || len(accts) == 0 {
		return "", "", errors.New("no Cloudflare accounts found for this token")
	}
	return accts[0].ID, accts[0].Name, nil
}

// ListAccounts returns all accounts available to the token.
func ListAccounts(token string) ([]map[string]string, error) {
	c := newClient(token)
	res, err := c.do("GET", "/accounts", "", nil)
	if err != nil {
		return nil, err
	}
	var accts []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if err := json.Unmarshal(res, &accts); err != nil {
		return nil, err
	}
	out := make([]map[string]string, 0, len(accts))
	for _, a := range accts {
		out = append(out, map[string]string{"id": a.ID, "name": a.Name})
	}
	return out, nil
}

// kvPut writes a plaintext value to a KV namespace key.
func (c *client) kvPut(acct, nsID, key, value string) error {
	_, err := c.do("PUT", "/accounts/"+acct+"/storage/kv/namespaces/"+nsID+"/values/"+key, "text/plain", strings.NewReader(value))
	return err
}

func (c *client) createKV(acct, title string) (string, error) {
	body, _ := json.Marshal(map[string]string{"title": title})
	res, err := c.do("POST", "/accounts/"+acct+"/storage/kv/namespaces", "application/json", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	var ns struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(res, &ns); err != nil || ns.ID == "" {
		return "", errors.New("could not read KV namespace id")
	}
	return ns.ID, nil
}

// uploadWorker uploads worker.js as an ES-module worker with the kv binding and
// plain-text variables.
func (c *client) uploadWorker(acct, name string, script []byte, kvID string, vars map[string]string) error {
	var bindings []map[string]any
	bindings = append(bindings, map[string]any{
		"type": "kv_namespace", "name": "kv", "namespace_id": kvID,
	})
	for k, v := range vars {
		bindings = append(bindings, map[string]any{"type": "plain_text", "name": k, "text": v})
	}
	metadata := map[string]any{
		"main_module":         "worker.js",
		"compatibility_date":  compatDate,
		"compatibility_flags": []string{"nodejs_compat"},
		"bindings":            bindings,
	}
	metaJSON, _ := json.Marshal(metadata)

	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	mh := textproto.MIMEHeader{}
	mh.Set("Content-Disposition", `form-data; name="metadata"`)
	mh.Set("Content-Type", "application/json")
	mp, _ := w.CreatePart(mh)
	_, _ = mp.Write(metaJSON)

	fh := textproto.MIMEHeader{}
	fh.Set("Content-Disposition", `form-data; name="worker.js"; filename="worker.js"`)
	fh.Set("Content-Type", "application/javascript+module")
	fp, _ := w.CreatePart(fh)
	_, _ = fp.Write(script)
	_ = w.Close()

	_, err := c.do("PUT", "/accounts/"+acct+"/workers/scripts/"+name, w.FormDataContentType(), &buf)
	return err
}

func (c *client) enableSubdomain(acct, name string) error {
	body, _ := json.Marshal(map[string]bool{"enabled": true})
	_, err := c.do("POST", "/accounts/"+acct+"/workers/scripts/"+name+"/subdomain", "application/json", bytes.NewReader(body))
	return err
}

func (c *client) accountSubdomain(acct string) (string, error) {
	res, err := c.do("GET", "/accounts/"+acct+"/workers/subdomain", "", nil)
	if err != nil {
		return "", err
	}
	var sd struct {
		Subdomain string `json:"subdomain"`
	}
	_ = json.Unmarshal(res, &sd)
	return sd.Subdomain, nil // empty means none registered yet
}

// registerSubdomain claims a workers.dev subdomain for the account (one per
// account, globally unique). Returns the registered name or an error if taken.
func (c *client) registerSubdomain(acct, desired string) (string, error) {
	body, _ := json.Marshal(map[string]string{"subdomain": desired})
	res, err := c.do("PUT", "/accounts/"+acct+"/workers/subdomain", "application/json", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	var sd struct {
		Subdomain string `json:"subdomain"`
	}
	_ = json.Unmarshal(res, &sd)
	if sd.Subdomain != "" {
		return sd.Subdomain, nil
	}
	return desired, nil
}

// ensureSubdomain returns the account's workers.dev subdomain, registering one
// automatically (trying a few unique candidates) if none exists yet.
func (c *client) ensureSubdomain(acct, hint string, log LogFunc) (string, error) {
	if s, err := c.accountSubdomain(acct); err == nil && s != "" {
		return s, nil
	}
	log("No workers.dev subdomain yet — registering one…", "ACCENT")
	// The account subdomain is account-wide and forms the URL as
	// <worker>.<subdomain>.workers.dev, so it must NOT be derived from the
	// project name (that produced ugly "name.name.workers.dev" URLs). Use a
	// short, clean, generic handle instead.
	candidates := []string{"ez-" + randHex(3), "ez" + randHex(4), "edge-" + randHex(4), randHex(8)}
	for _, cand := range candidates {
		cand = sanitizeName(cand)
		if cand == "" {
			continue
		}
		if s, err := c.registerSubdomain(acct, cand); err == nil && s != "" {
			log("✓ Registered subdomain: "+s+".workers.dev", "OK")
			return s, nil
		}
	}
	return "", errors.New("could not auto-register a workers.dev subdomain — register one in Workers & Pages")
}

// FetchWorkerJS returns the bundled BPB panel worker.js (for the in-app editor
// and for deployment). It's embedded in the binary — no external download.
func FetchWorkerJS() ([]byte, error) {
	if len(embeddedWorker) < 1000 {
		return nil, errors.New("bundled worker.js is missing")
	}
	return embeddedWorker, nil
}

// Deploy runs the full deployment and returns the panel URLs.
func Deploy(o Options, log LogFunc) (*Result, error) {
	if log == nil {
		log = func(string, string) {}
	}
	if strings.TrimSpace(o.Token) == "" {
		return nil, errors.New("Cloudflare API token required")
	}
	o.Name = sanitizeName(o.Name)
	if o.Name == "" {
		o.Name = "ezaccess-project"
	}
	if badName(o.Name) {
		return nil, errors.New(`avoid the words "bpb", "vpn", or "proxy" in the project name — Cloudflare may ban it`)
	}
	if o.UUID == "" {
		o.UUID = GenUUID()
	}
	if o.TrojanPwd == "" {
		o.TrojanPwd = randHex(12)
	}
	if o.SubPath == "" {
		o.SubPath = randHex(8)
	}
	if o.PanelPwd == "" {
		o.PanelPwd = o.UUID
	}
	if o.Fallback == "" {
		o.Fallback = defaultFallbk
	}
	// PROXY_IP intentionally left as-is: empty means the panel uses its own
	// rotating clean IPs (no dependency on any external proxy host).

	c := newClient(o.Token)
	acct := o.AccountID
	if acct == "" {
		log("Verifying token…", "ACCENT")
		id, name, err := VerifyToken(o.Token)
		if err != nil {
			return nil, err
		}
		acct = id
		log("✓ Account: "+name, "OK")
	}

	var script []byte
	switch {
	case strings.TrimSpace(o.Script) != "":
		script = []byte(o.Script)
		log(fmt.Sprintf("Using edited worker.js (%d KB)", len(script)/1024), "ACCENT")
	case strings.TrimSpace(o.SourceURL) != "":
		log("Fetching worker.js from "+o.SourceURL+" …", "ACCENT")
		var err error
		script, err = FetchFromURL(o.SourceURL)
		if err != nil {
			return nil, err
		}
		log(fmt.Sprintf("✓ Fetched worker.js (%d KB)", len(script)/1024), "OK")
	default:
		var err error
		script, err = FetchWorkerJS()
		if err != nil {
			return nil, err
		}
		log(fmt.Sprintf("Using bundled V2RayEz panel v%s (%d KB)", PanelVersion, len(script)/1024), "OK")
	}

	log("Creating KV namespace…", "ACCENT")
	kvID, err := c.createKV(acct, o.Name+"-kv")
	if err != nil {
		return nil, errors.New("KV create failed: " + err.Error())
	}
	log("✓ KV namespace ready", "OK")

	// Pre-set the panel login password (stored plaintext in KV under "pwd"), so
	// the panel doesn't prompt to set a new one on first open.
	if strings.TrimSpace(o.PanelPwd) != "" {
		if err := c.kvPut(acct, kvID, "pwd", o.PanelPwd); err != nil {
			log("could not preset panel password: "+err.Error(), "WARN")
		} else {
			log("✓ Panel password set", "OK")
		}
	}

	vars := map[string]string{
		"UUID":     o.UUID,
		"TR_PASS":  o.TrojanPwd,
		"FALLBACK": o.Fallback,
		"SUB_PATH": o.SubPath,
	}
	if strings.TrimSpace(o.ProxyIP) != "" {
		vars["PROXY_IP"] = o.ProxyIP
	}

	res := &Result{Name: o.Name, UUID: o.UUID, TrojanPwd: o.TrojanPwd, SubPath: o.SubPath, PanelPwd: o.PanelPwd}

	if strings.EqualFold(o.Mode, "pages") {
		log("Creating Cloudflare Pages project…", "ACCENT")
		if err := c.createPagesProject(acct, o.Name, kvID, vars); err != nil {
			return nil, errors.New("Pages project create failed: " + err.Error())
		}
		log("✓ Pages project ready", "OK")
		log("Uploading deployment (this can take a minute)…", "ACCENT")
		if err := c.createPagesDeployment(acct, o.Name, script); err != nil {
			return nil, errors.New("Pages deployment failed: " + err.Error())
		}
		base := fmt.Sprintf("https://%s.pages.dev", o.Name)
		res.Subdomain = "pages.dev"
		res.PanelURL = base + "/panel"
		res.SubURL = fmt.Sprintf("%s/sub/normal/%s?app=xray", base, o.SubPath)
		log("✓ Deployed (Pages). Panel: "+res.PanelURL, "OK")
		return res, nil
	}

	// Worker path
	log("Uploading worker…", "ACCENT")
	if err := c.uploadWorker(acct, o.Name, script, kvID, vars); err != nil {
		return nil, errors.New("worker upload failed: " + err.Error())
	}
	log("✓ Worker uploaded", "OK")

	sub, err := c.ensureSubdomain(acct, o.Name, log)
	if err != nil {
		return nil, err
	}
	log("Enabling workers.dev route for this worker…", "ACCENT")
	if err := c.enableSubdomain(acct, o.Name); err != nil {
		log("subdomain enable warning: "+err.Error(), "WARN")
	}

	base := fmt.Sprintf("https://%s.%s.workers.dev", o.Name, sub)
	res.Subdomain = sub
	res.PanelURL = base + "/panel"
	res.SubURL = fmt.Sprintf("%s/sub/normal/%s?app=xray", base, o.SubPath)
	log("✓ Deployed (Worker). Panel: "+res.PanelURL, "OK")
	return res, nil
}

// createPagesProject creates a Pages project with the kv binding + env vars on
// its production config. Ignores "already exists" so re-deploys work.
func (c *client) createPagesProject(acct, name, kvID string, vars map[string]string) error {
	envVars := map[string]any{}
	for k, v := range vars {
		envVars[k] = map[string]string{"type": "plain_text", "value": v}
	}
	body, _ := json.Marshal(map[string]any{
		"name":              name,
		"production_branch": "main",
		"deployment_configs": map[string]any{
			"production": map[string]any{
				"compatibility_date":  compatDate,
				"compatibility_flags": []string{"nodejs_compat"},
				"kv_namespaces":       map[string]any{"kv": map[string]string{"namespace_id": kvID}},
				"env_vars":            envVars,
			},
		},
	})
	_, err := c.do("POST", "/accounts/"+acct+"/pages/projects", "application/json", bytes.NewReader(body))
	if err != nil && strings.Contains(strings.ToLower(err.Error()), "already") {
		return nil // project exists — fine for re-deploy
	}
	return err
}

// createPagesDeployment pushes a functions-only deployment (_worker.js, empty
// static manifest) to the project's production environment.
func (c *client) createPagesDeployment(acct, name string, script []byte) error {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	_ = w.WriteField("manifest", "{}")
	fh := textproto.MIMEHeader{}
	fh.Set("Content-Disposition", `form-data; name="_worker.js"; filename="_worker.js"`)
	fh.Set("Content-Type", "application/javascript+module")
	fp, _ := w.CreatePart(fh)
	_, _ = fp.Write(script)
	_ = w.Close()
	_, err := c.do("POST", "/accounts/"+acct+"/pages/projects/"+name+"/deployments", w.FormDataContentType(), &buf)
	return err
}

// ---- helpers ---------------------------------------------------------------

// GenUUID returns a random RFC-4122 v4 UUID.
func GenUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)
}

func sanitizeName(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var out []rune
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			out = append(out, r)
		} else if r == ' ' || r == '_' {
			out = append(out, '-')
		}
	}
	return strings.Trim(string(out), "-")
}

func badName(s string) bool {
	for _, bad := range []string{"bpb", "vpn", "proxy"} {
		if strings.Contains(s, bad) {
			return true
		}
	}
	return false
}
