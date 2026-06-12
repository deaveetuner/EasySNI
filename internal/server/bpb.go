package server

import (
	"encoding/json"
	"errors"
	"strings"

	"ezsni/internal/bpb"
)

func (s *Server) handleBPBGen(json.RawMessage) (any, error) {
	return map[string]any{
		"uuid":     bpb.GenUUID(),
		"trojan":   bpbRandPwd(),
		"sub_path": bpbRandPath(),
		"name":     "ezaccess-project-" + bpbRandPath()[:6],
	}, nil
}

func bpbRandPwd() string  { return strings.ReplaceAll(bpb.GenUUID(), "-", "")[:16] }
func bpbRandPath() string { return strings.ReplaceAll(bpb.GenUUID(), "-", "")[:10] }

func (s *Server) handleBPBVerify(body json.RawMessage) (any, error) {
	var req struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, err
	}
	if strings.TrimSpace(req.Token) == "" {
		return nil, errors.New("token required")
	}
	accts, err := bpb.ListAccounts(req.Token)
	if err != nil {
		s.log("✗ "+err.Error(), "ERROR")
		return map[string]any{"ok": false, "error": err.Error()}, nil
	}
	return map[string]any{"ok": true, "accounts": accts}, nil
}

func (s *Server) handleBPBWorkerJS(body json.RawMessage) (any, error) {
	var req struct {
		SourceURL string `json:"source_url"`
	}
	_ = json.Unmarshal(body, &req)
	var (
		b   []byte
		err error
		ver = bpb.PanelVersion
	)
	if strings.TrimSpace(req.SourceURL) != "" {
		b, err = bpb.FetchFromURL(req.SourceURL)
		ver = "custom"
	} else {
		b, err = bpb.FetchWorkerJS()
	}
	if err != nil {
		s.log("✗ "+err.Error(), "ERROR")
		return map[string]any{"ok": false, "error": err.Error()}, nil
	}
	return map[string]any{"ok": true, "script": string(b), "version": ver}, nil
}

func (s *Server) handleBPBDeploy(body json.RawMessage) (any, error) {
	var req struct {
		Token     string `json:"token"`
		AccountID string `json:"account_id"`
		Name      string `json:"name"`
		UUID      string `json:"uuid"`
		TrojanPwd string `json:"trojan_password"`
		ProxyIP   string `json:"proxy_ip"`
		Fallback  string `json:"fallback"`
		SubPath   string `json:"sub_path"`
		PanelPwd  string `json:"panel_password"`
		WorkerJS  string `json:"worker_js"`
		SourceURL string `json:"source_url"`
		Mode      string `json:"mode"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, err
	}
	s.log("Deploying panel to Cloudflare ("+req.Mode+")…", "ACCENT")
	res, err := bpb.Deploy(bpb.Options{
		Token:     req.Token,
		AccountID: req.AccountID,
		Name:      req.Name,
		UUID:      req.UUID,
		TrojanPwd: req.TrojanPwd,
		ProxyIP:   req.ProxyIP,
		Fallback:  req.Fallback,
		SubPath:   req.SubPath,
		PanelPwd:  req.PanelPwd,
		Script:    req.WorkerJS,
		SourceURL: req.SourceURL,
		Mode:      req.Mode,
	}, s.bus.Log)
	if err != nil {
		s.log("✗ "+err.Error(), "ERROR")
		return map[string]any{"ok": false, "error": err.Error()}, nil
	}
	return map[string]any{"ok": true, "result": res}, nil
}
