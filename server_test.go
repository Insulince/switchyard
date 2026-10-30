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
