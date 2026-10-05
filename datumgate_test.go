package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

// Cut down from a live DATUM gateway status page, keeping the title
// and header -- the two places the gate looks.
const datumPage = `<!DOCTYPE html><html><head><title>DATUM Gateway Status</title></head>
<body><h1><img src="/assets/icons/datum_logo.svg"> DATUM <span>GATEWAY</span></h1>
<table><tr><td>Status:</td><td>Connected and Ready</td></tr>
<tr><td>Pool Host:</td><td>pool.example:28916</td></tr></table></body></html>`

// statusPage serves whatever page returns, and gives back the pool entry
// pointing at it.
func statusPage(t *testing.T, name string, page func() (int, string)) poolConfig {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		code, body := page()
		w.WriteHeader(code)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	host, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	p, _ := strconv.Atoi(port)
	return poolConfig{Name: name, Host: host, Port: 1, StatusPort: p}
}

func fixed(code int, body string) func() (int, string) {
	return func() (int, string) { return code, body }
}

func shortRecheck(t *testing.T) {
	was := datumRecheck
	datumRecheck = 20 * time.Millisecond
	t.Cleanup(func() { datumRecheck = was })
}

func TestDatumPageIsRecognised(t *testing.T) {
	for _, c := range []struct {
		page string
		want bool
	}{
		{datumPage, true},
		{"<title>DATUM Gateway Status</title>", true},
		{"<h1>DATUM <span>GATEWAY</span></h1>", true},
		{"<html><body>ckpool solo</body></html>", false},
		{"<html><body>Pool Host: pool.example:3333</body></html>", false},
		{"<p>DATUMGATEWAY</p>", false},
	} {
		if got := isDatumPage(stripTags(c.page)); got != c.want {
			t.Errorf("isDatumPage(%q) = %v, want %v", c.page, got, c.want)
		}
	}
}

// One foreign upstream condemns the whole setup, and the refusal names it.
func TestVerifyDatumRefusesAForeignUpstream(t *testing.T) {
	shortRecheck(t)
	pools := []poolConfig{
		statusPage(t, "real", fixed(http.StatusOK, datumPage)),
		statusPage(t, "lazy", fixed(http.StatusOK, "<html><body>Pool dashboard</body></html>")),
	}
	err := verifyDatum(context.Background(), pools, func(string) {})
	var foreign *foreignUpstreamError
	if !errors.As(err, &foreign) {
		t.Fatalf("err = %v, want a foreign-upstream refusal", err)
	}
	if foreign.pool.Name != "lazy" {
		t.Errorf("refusal names %q, want the offending entry %q", foreign.pool.Name, "lazy")
	}
}

// Positive identification is the requirement. A status port that answers
// with nothing usable -- or is never answered at all -- must never let the
// setup through, or pointing it at nothing is the way around the gate.
func TestVerifyDatumNeverPassesAnUnverifiedGateway(t *testing.T) {
	shortRecheck(t)
	dead := statusPage(t, "dead", fixed(http.StatusOK, ""))
	dead.StatusPort = closedPort(t)
	for _, p := range []poolConfig{
		dead,
		statusPage(t, "erroring", fixed(http.StatusServiceUnavailable, datumPage)),
	} {
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		var waited atomic.Int32
		err := verifyDatum(ctx, []poolConfig{p}, func(string) { waited.Add(1) })
		cancel()
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("%s: err = %v, want it still waiting when cancelled", p.Name, err)
		}
		if waited.Load() == 0 {
			t.Errorf("%s: never reported what it was waiting on", p.Name)
		}
	}
}

// A gateway that is merely slow to start is waited for, not refused.
func TestVerifyDatumWaitsForAGatewayStillStarting(t *testing.T) {
	shortRecheck(t)
	var asked atomic.Int32
	p := statusPage(t, "slow", func() (int, string) {
		if asked.Add(1) < 3 {
			return http.StatusServiceUnavailable, ""
		}
		return http.StatusOK, datumPage
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := verifyDatum(ctx, []poolConfig{p}, func(string) {}); err != nil {
		t.Fatalf("err = %v, want it verified once the page came up", err)
	}
}

// Verified at boot is not a licence. A status page that later answers as
// something else stops the generation; one that stops answering is a gateway
// restarting and stops nothing.
func TestGatewayWatchRefusesMidRun(t *testing.T) {
	var foreign atomic.Bool
	p := statusPage(t, "swapped", func() (int, string) {
		if foreign.Load() {
			return http.StatusOK, "<html><body>some pool</body></html>"
		}
		return http.StatusOK, datumPage
	})
	silent := statusPage(t, "restarting", fixed(http.StatusOK, ""))
	silent.StatusPort = closedPort(t)

	co := newCoordinator(config{Pools: []poolConfig{p, silent}, GatewayPollSeconds: 1})
	refused := make(chan error, 4)
	co.refuse = func(err error) { refused <- err }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go co.watchGateways(ctx)

	select {
	case err := <-refused:
		t.Fatalf("refused while every answering gateway was DATUM: %v", err)
	case <-time.After(1500 * time.Millisecond):
	}

	foreign.Store(true)
	select {
	case err := <-refused:
		var fe *foreignUpstreamError
		if !errors.As(err, &fe) || fe.pool.Name != "swapped" {
			t.Errorf("refusal = %v, want one naming %q", err, "swapped")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("a status page that turned foreign mid-run was not refused")
	}
}

// closedPort returns a local port with nothing listening on it.
func closedPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}
