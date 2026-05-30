package gtunnel

import "testing"

func TestGenWorkerJS(t *testing.T) {
	js := GenWorkerJS("myworker.workers.dev")
	for _, want := range []string{"WORKER_HOST = \"myworker.workers.dev\"", "self-fetch blocked", "btoa(bin)", "x-relay-hop", "atob(req.b)"} {
		if !contains(js, want) {
			t.Fatalf("worker.js missing %q", want)
		}
	}
	// default host when blank
	if !contains(GenWorkerJS(""), "myworker.workers.dev") {
		t.Fatal("blank host should default")
	}
}

func TestGenCodeGS(t *testing.T) {
	gs := GenCodeGS("s3cr3t", "myworker.workers.dev")
	for _, want := range []string{"AUTH_KEY   = \"s3cr3t\"", "https://myworker.workers.dev", "req.k !== AUTH_KEY", "UrlFetchApp.fetch", "doPost"} {
		if !contains(gs, want) {
			t.Fatalf("Code.gs missing %q", want)
		}
	}
	// adds https:// when missing, defaults when blank
	if !contains(GenCodeGS("", "x.workers.dev"), "change-this-secret") {
		t.Fatal("blank auth should default")
	}
}

func TestStartValidation(t *testing.T) {
	r := NewRunner(nil)
	if err := r.Start(Config{AuthKey: "k"}); err == nil {
		t.Fatal("expected error without script id")
	}
	if err := r.Start(Config{ScriptID: "id"}); err == nil {
		t.Fatal("expected error without auth key")
	}
}

func TestRelayPayloadShape(t *testing.T) {
	// CA generation must succeed and produce a downloadable PEM after a (failed-listen-free) start path.
	r := NewRunner(nil)
	if err := r.ensureCA(); err != nil {
		t.Fatalf("ensureCA: %v", err)
	}
	if len(r.CAPEM()) == 0 {
		t.Fatal("CA PEM empty")
	}
	leaf, err := r.leafFor("example.com")
	if err != nil || leaf == nil {
		t.Fatalf("leafFor: %v", err)
	}
	if len(leaf.Certificate) != 2 {
		t.Fatalf("leaf should include leaf+CA chain, got %d", len(leaf.Certificate))
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (indexOf(s, sub) >= 0)
}
func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
