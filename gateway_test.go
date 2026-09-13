package main

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// applyDefaults treats "0 or less" as "not set", which is right for an omitted
// field in a file and wrong for a number somebody typed. Without validateRaw
// running first, a dwell floor of -5 silently becomes 60 and the operator is
// never told their input was thrown away.
func TestValidateRawRejectsWhatDefaultsWouldHide(t *testing.T) {
	for _, c := range []struct {
		name    string
		mutate  func(*config)
		wantErr bool
	}{
		{"sane", func(c *config) { c.MinDwellSeconds, c.MaxDwellSeconds = 60, 900 }, false},
		{"negative floor", func(c *config) { c.MinDwellSeconds = -5 }, true},
		{"negative ceiling", func(c *config) { c.MaxDwellSeconds = -1 }, true},
		{"negative poll", func(c *config) { c.PollSeconds = -0.5 }, true},
		{"equal floor and ceiling", func(c *config) { c.MinDwellSeconds, c.MaxDwellSeconds = 300, 300 }, true},
		{"ceiling below floor", func(c *config) { c.MinDwellSeconds, c.MaxDwellSeconds = 300, 120 }, true},
		{"both omitted", func(c *config) {}, false},
	} {
		var cfg config
		c.mutate(&cfg)
		err := cfg.validateRaw()
		if (err != nil) != c.wantErr {
			t.Errorf("%s: err = %v, wantErr %v", c.name, err, c.wantErr)
		}
		// And prove the point: defaults would have papered over it.
		if c.wantErr {
			after := cfg
			after.applyDefaults()
			if after.validate() == nil && cfg.MinDwellSeconds < 0 {
				t.Logf("%s: confirmed defaults would have accepted it silently", c.name)
			}
		}
	}
}

// The gateway's status page is the one place the pool behind it is named.
// Parsing has to stop at the value and not run on into the next label -- a
// half-parsed value gets written into a config and shown as fact.
func TestInspectGatewayParsesStatusPage(t *testing.T) {
	page := `<html><body>
	  <h1>DATUM GATEWAY</h1>
	  <table><tr><td>Status:</td><td>Connected and Ready</td></tr>
	  <tr><td>Pool Host:</td><td>tides.example.ca:28916</td></tr>
	  <tr><td>Pool Tag:</td><td>"RIPTIDE"</td></tr>
	  <tr><td>Pool Current MinDiff:</td><td>2048</td></tr></table>
	</body></html>`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(page))
	}))
	defer srv.Close()

	info, err := inspectGateway(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	// The port is the pool's stratum port and is of no interest here.
	if info.PoolHost != "tides.example.ca" {
		t.Errorf("PoolHost = %q, want %q", info.PoolHost, "tides.example.ca")
	}
	if info.Status != "Connected and Ready" {
		t.Errorf("Status = %q, want %q -- did it run into the next label?", info.Status, "Connected and Ready")
	}
	if info.Tag != "RIPTIDE" {
		t.Errorf("Tag = %q, want %q", info.Tag, "RIPTIDE")
	}
}

// This endpoint takes an address from the browser and fetches it server-side,
// so it must not be talked into reading anything but http(s), and it must say
// so plainly rather than returning something that looks like a gateway.
func TestInspectGatewayRefusesNonHTTP(t *testing.T) {
	for _, bad := range []string{"", "   ", "file:///etc/passwd", "ftp://example.com"} {
		if _, err := inspectGateway(context.Background(), bad); err == nil {
			t.Errorf("%q was accepted, want an error", bad)
		}
	}
}

// Something that answers but is not a gateway must be reported as such, not
// silently accepted as a pool with an empty name.
func TestInspectGatewayRejectsUnrelatedPages(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<html><body>hello</body></html>"))
	}))
	defer srv.Close()
	if _, err := inspectGateway(context.Background(), srv.URL); err == nil {
		t.Error("an unrelated page was accepted as a DATUM gateway")
	}
}

// The pool-side counters are the point of reading the gateway's status page
// at all, and they exist because of a measured failure: with
// pool_pass_full_users set to true and a worker name that is not a payout
// address, a gateway accepts every share locally while the pool rejects every
// one of them. Observed on a live gateway: 9 accepted locally, 0 accepted by
// the pool, 9 rejected by the pool -- with switchyard reporting 9 accepted and
// 0 rejected throughout.
func TestGatewayHealthReadsPoolSideCounters(t *testing.T) {
	page := `<html><body>
	  <tr><td>Local Shares Accepted:</td><td>9 (9216 diff)</td></tr>
	  <tr><td>Local Shares Rejected:</td><td>0 (0 diff)</td></tr>
	  <tr><td>Pool Shares Accepted:</td><td>0 (0 diff)</td></tr>
	  <tr><td>Pool Shares Rejected:</td><td>9 (9216 diff)</td></tr>
	  <tr><td>Status:</td><td>Connected and Ready</td></tr>
	  <tr><td>Pool Host:</td><td>pool.example.tech:28915</td></tr>
	</body></html>`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(page))
	}))
	defer srv.Close()

	h, err := inspectGatewayFull(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	if h.PoolAccepted != 0 || h.PoolRejected != 9 {
		t.Errorf("pool counters = %d/%d, want 0 accepted and 9 rejected",
			h.PoolAccepted, h.PoolRejected)
	}
	// The LOCAL counters must not be mistaken for the pool ones -- confusing
	// them is exactly the mistake this whole feature exists to prevent.
	if h.PoolAccepted == 9 {
		t.Error("read the local accepted count as the pool accepted count")
	}
	if !h.rejecting() {
		t.Error("100% pool-side rejection was not flagged")
	}
}

// A couple of rejects at a reconnect boundary is ordinary. Crying
// misconfiguration at those would train the operator to ignore the warning
// that matters.
func TestGatewayHealthIgnoresSmallSamples(t *testing.T) {
	for _, c := range []struct {
		acc, rej uint64
		want     bool
	}{
		{0, 0, false},
		{0, 2, false},   // a fresh gateway with two in-flight shares lost
		{0, 9, true},    // the measured failure
		{100, 3, false}, // ordinary boundary rejects
		{4, 60, true},   // overwhelmingly refused
	} {
		h := gatewayHealth{PoolAccepted: c.acc, PoolRejected: c.rej}
		if got := h.rejecting(); got != c.want {
			t.Errorf("acc=%d rej=%d: rejecting = %v, want %v", c.acc, c.rej, got, c.want)
		}
	}
}

// A pool's displayed name is the gateway's coinbase tag, which arrives from a
// poll and overrides whatever the config called it. Everything that refers to
// a pool has to use that same resolved name.
//
// This is a regression test for a silent rendering fault: the override used to
// be applied at the end of building the status document, after each rig's
// BoundTo had already been written from the config label. The two disagreed,
// so nothing could match a rig's binding to a pool -- rigs drew as connected,
// gateways drew as carrying, and every link between them rendered idle. No
// error, no log line, just a diagram missing its middle.
// A gateway whose Prime connection has failed does not stop. DATUM falls back
// to solo mining under the LOCAL coinbase tag and keeps accepting shares, and
// its status page prints that local tag in the "Pool Tag" field. Seen live:
// a Prime upgraded past the gateway's version ("Bad configuration version
// from server"), nine hours in Non-Pooled Mode, the pool-side accepted
// counter frozen, the card green, and the pool quietly renamed to the
// operator. The state must be flagged, and nothing read from the page may
// ever become the pool's name.
func TestUnpooledGatewayIsFlaggedAndKeepsItsConfigName(t *testing.T) {
	page := `<html><body>
	  <tr><td>Pool Shares Accepted:</td><td>6165 (12625920 diff)</td></tr>
	  <tr><td>Pool Shares Rejected:</td><td>92 (188416 diff)</td></tr>
	  <tr><td>Status:</td><td><svg viewBox='0 0 100 100'><circle cx='50' cy='60' r='35' style='fill:yellow' /></svg> Non-Pooled Mode</td></tr>
	  <tr><td>Pool Host:</td><td>tides.example.ca:28916</td></tr>
	  <tr><td>Pool Tag:</td><td>"d8dd1618"</td></tr>
	</body></html>`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(page))
	}))
	defer srv.Close()

	h, err := inspectGatewayFull(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	if !h.Unpooled {
		t.Fatalf("status %q was not flagged as unpooled", h.Status)
	}
	// Counters alone say nothing is wrong here -- 6165 accepted, 92 refused
	// -- which is the whole point: this failure is invisible to rejecting().
	if h.rejecting() {
		t.Error("unpooled gateway wrongly reported as rejecting; these are different failures")
	}

	cfg := config{
		Pools: []poolConfig{{Name: "RIPTIDE", Host: "127.0.0.1", Port: 23336, StatusPort: 7154}},
		Rigs:  []rigConfig{{Listen: "0.0.0.0:23401"}},
	}
	cfg.applyDefaults()
	co := newCoordinator(cfg)
	co.gw.set("RIPTIDE", *h)
	if got := co.status().Pools[0].Name; got != "RIPTIDE" {
		t.Errorf("pool name = %q, want the config label; the tag is the operator's own", got)
	}

	// A page whose status could not be parsed is unknown, not an outage.
	if (gatewayHealth{}).unpooled() {
		t.Error("blank status treated as unpooled")
	}
}

func TestBoundToUsesTheSameNameAsThePool(t *testing.T) {
	cfg := config{
		Pools: []poolConfig{
			{Name: "config-label-a", Host: "127.0.0.1", Port: 23336, StatusPort: 7154},
			{Name: "config-label-b", Host: "127.0.0.1", Port: 23337, StatusPort: 7155},
		},
		Rigs: []rigConfig{{Listen: "0.0.0.0:23401"}},
	}
	cfg.applyDefaults()
	co := newCoordinator(cfg)

	// The gateway reports a tag that is nothing like the config label.
	co.gw.set("config-label-b", gatewayHealth{Tag: "TAG-B", PoolHost: "pool.b.example"})
	co.gw.set("config-label-a", gatewayHealth{Tag: "TAG-A", PoolHost: "pool.a.example"})

	// Bind the rig to the second pool, the way a real session would.
	co.mu.Lock()
	co.sessions[0] = &rigSession{co: co, rigIdx: 0, up: co.ups[0][1]}
	co.mu.Unlock()

	doc := co.status()
	if len(doc.Rigs) != 1 || len(doc.Pools) != 2 {
		t.Fatalf("unexpected shape: %d rigs, %d pools", len(doc.Rigs), len(doc.Pools))
	}
	// The tag does NOT rename the pool. The label is the operator's.
	if doc.Pools[1].Name != "config-label-b" {
		t.Errorf("pool name = %q, want the config label", doc.Pools[1].Name)
	}
	if doc.Rigs[0].BoundTo != doc.Pools[1].Name {
		t.Errorf("BoundTo = %q but the pool is called %q; nothing can match these up",
			doc.Rigs[0].BoundTo, doc.Pools[1].Name)
	}
	// And the pool has to agree that the rig is on it.
	if len(doc.Pools[1].Occupants) != 1 {
		t.Errorf("pool %q lists %d occupants, want 1", doc.Pools[1].Name, len(doc.Pools[1].Occupants))
	}
	if len(doc.Pools[0].Occupants) != 0 {
		t.Errorf("pool %q wrongly claims an occupant", doc.Pools[0].Name)
	}
	// Per-gateway rows carry the same name too, or the tables disagree with
	// the diagram.
	if doc.Rigs[0].Gateways[1].Pool != "config-label-b" {
		t.Errorf("gateway row names the pool %q, want config-label-b", doc.Rigs[0].Gateways[1].Pool)
	}
}

// The probe has to reject a port that is open but is not stratum, because that
// is the exact mistake it exists to catch: typing the status port into the
// stratum field. A bare TCP dial would call that a success.
func TestProbeStratumRejectsAnHTTPServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<html><body>DATUM Gateway</body></html>"))
	}))
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "http://")

	err := probeStratum(context.Background(), addr)
	if err == nil {
		t.Fatal("probeStratum accepted an HTTP server as a stratum port")
	}
	if !strings.Contains(err.Error(), "status port") {
		t.Errorf("error should point at the likely mistake, got %q", err)
	}
}

func TestProbeStratumAcceptsASubscribeResponse(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_, _ = bufio.NewReader(conn).ReadString('\n')
		_, _ = conn.Write([]byte(`{"id":9001,"result":[[["mining.notify","a"]],"b10cf00d",4],"error":null}` + "\n"))
	}()

	if err := probeStratum(context.Background(), ln.Addr().String()); err != nil {
		t.Fatalf("probeStratum rejected a valid subscribe response: %v", err)
	}
}

func TestProbeStratumReportsAClosedPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	err = probeStratum(context.Background(), addr)
	if err == nil {
		t.Fatal("probeStratum accepted a port with nothing on it")
	}
	if !strings.Contains(err.Error(), "nothing is listening") {
		t.Errorf("unhelpful message for a closed port: %q", err)
	}
}

// A dashboard address that cannot bind must be refused at the form, not
// written to disk. listen() closes the running listener before binding the
// new one and main() treats the failure as fatal, so accepting one takes the
// process down with every rig on it -- and since the file is already saved,
// every restart afterwards fails the same way.
func TestSaveRefusesAnUnbindableDashboardAddress(t *testing.T) {
	// Hold a port so the incoming value cannot bind.
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	taken := busy.Addr().String()

	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	srv := newServer(path)

	body := fmt.Sprintf(
		`{"statusListen":%q,"pools":[{"name":"A","host":"h","port":23336,"statusPort":7154}],`+
			`"rigs":[{"listen":"0.0.0.0:0"}]}`, taken)

	rec := httptest.NewRecorder()
	srv.saveAndReload(rec, httptest.NewRequest(http.MethodPost, "/config", strings.NewReader(body)))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("an unbindable dashboard address was accepted: status %d, body %s",
			rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "dashboard cannot listen") {
		t.Fatalf("the error should name the dashboard address, got: %s", rec.Body.String())
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("a rejected config must not reach disk")
	}
}
