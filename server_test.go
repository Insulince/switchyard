package main

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

// The JSON-body endpoints are CSRF-guarded by requiring Content-Type:
// application/json. A cross-site <form> can only send text/plain, urlencoded or
// multipart, and a cross-site fetch that sets application/json triggers a CORS
// preflight this origin never answers -- so only the dashboard's own page can
// reach them. This matters most on /gateway/inspect and the other probes, which
// dial a caller-supplied host and would otherwise be an SSRF reachable by CSRF.
// Pinned here (against the real router) so the guard cannot silently come unwired.
func TestJSONEndpointsRejectNonJSONPost(t *testing.T) {
	h := newServer(filepath.Join(t.TempDir(), "config.json")).routes()

	do := func(method, ctype, body string) int {
		req := httptest.NewRequest(method, "/gateway/inspect", strings.NewReader(body))
		req.Host = "localhost:7160" // past the DNS-rebinding guard; see TestHostGuard
		if ctype != "" {
			req.Header.Set("Content-Type", ctype)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}

	if got := do(http.MethodGet, "", ""); got != http.StatusMethodNotAllowed {
		t.Errorf("GET: status %d, want 405", got)
	}
	if got := do(http.MethodPost, "", "{}"); got != http.StatusUnsupportedMediaType {
		t.Errorf("POST without Content-Type: status %d, want 415", got)
	}
	if got := do(http.MethodPost, "text/plain", "{}"); got != http.StatusUnsupportedMediaType {
		t.Errorf("POST text/plain (a cross-site form's only option): status %d, want 415", got)
	}
	// A malformed JSON body still PASSES the content-type guard (proving it is
	// wired to let JSON through) and only then fails at decode -- 400, never 415,
	// and never a dial.
	if got := do(http.MethodPost, "application/json", "{"); got == http.StatusUnsupportedMediaType {
		t.Errorf("POST application/json was rejected by the content-type guard (415); it must pass")
	}
}

// requireJSONBody accepts the charset-qualified form a browser may attach.
func TestRequireJSONBodyAcceptsCharsetParam(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	if !requireJSONBody(httptest.NewRecorder(), req) {
		t.Fatal("application/json; charset=utf-8 was rejected, but it is valid JSON")
	}
}

// DNS rebinding makes a hostile page same-origin, which walks straight past
// the JSON guard above -- but its requests still carry the hostile name in
// Host. Only localhost and IP literals reach the router. Pinned against the
// real router so the guard cannot come unwired.
func TestHostGuard(t *testing.T) {
	h := newServer(filepath.Join(t.TempDir(), "config.json")).routes()
	get := func(host string) int {
		req := httptest.NewRequest(http.MethodGet, "/status", nil)
		req.Host = host
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	for _, ok := range []string{"localhost:7160", "LOCALHOST", "app.localhost:7160",
		"127.0.0.1:7160", "192.168.1.165:7160", "[::1]:7160", "::1"} {
		if got := get(ok); got == http.StatusForbidden {
			t.Errorf("Host %q refused, want allowed", ok)
		}
	}
	for _, bad := range []string{"attacker.example", "attacker.example:7160",
		"localhost.attacker.example", "127.0.0.1.nip.io:7160", ""} {
		if got := get(bad); got != http.StatusForbidden {
			t.Errorf("Host %q: status %d, want 403", bad, got)
		}
	}
}

// Generate is JSON-guarded like its siblings, so a cross-site form cannot mint
// secrets, and what it stages is bounded however often it is called.
func TestAuthorityGenerateGuardedAndBounded(t *testing.T) {
	s := newServer(filepath.Join(t.TempDir(), "config.json"))
	h := s.routes()
	post := func(ctype string) int {
		req := httptest.NewRequest(http.MethodPost, "/authority/generate", strings.NewReader("{}"))
		req.Host = "localhost:7160"
		if ctype != "" {
			req.Header.Set("Content-Type", ctype)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	if got := post("text/plain"); got != http.StatusUnsupportedMediaType {
		t.Fatalf("text/plain generate: status %d, want 415", got)
	}
	if got := post("application/json"); got != http.StatusOK {
		t.Fatalf("JSON generate: status %d, want 200", got)
	}

	first := s.stageSecret("first")
	for i := 0; i < 3*maxStaged; i++ {
		s.stageSecret("x")
	}
	s.stagedMu.Lock()
	n, order := len(s.staged), len(s.stagedOrder)
	s.stagedMu.Unlock()
	if n > maxStaged || order > 2*maxStaged+1 {
		t.Fatalf("staged=%d order=%d, want <= %d / %d", n, order, maxStaged, 2*maxStaged+1)
	}
	if _, ok := s.consumeStaged(first); ok {
		t.Fatal("the oldest handle survived past the cap")
	}
	// The newest is still there to be saved.
	h2 := s.stageSecret("newest")
	if sec, ok := s.consumeStaged(h2); !ok || sec != "newest" {
		t.Fatalf("newest handle lost: %q %v", sec, ok)
	}
}
