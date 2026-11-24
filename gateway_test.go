package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
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
		{"negative poll", func(c *config) { c.DashboardPollSeconds = -0.5 }, true},
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
	page := `<html><head><title>DATUM Gateway Status</title></head><body>
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
	page := `<html><head><title>DATUM Gateway Status</title></head><body>
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
		Rigs:  []rigConfig{{Port: 23401, Protocol: "sv1"}},
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
		Rigs: []rigConfig{{Port: 23401, Protocol: "sv1"}},
	}
	cfg.applyDefaults()
	co := newCoordinator(cfg)

	// The gateway reports a tag that is nothing like the config label.
	co.gw.set("config-label-b", gatewayHealth{Tag: "TAG-B", PoolHost: "pool.b.example"})
	co.gw.set("config-label-a", gatewayHealth{Tag: "TAG-A", PoolHost: "pool.a.example"})

	// Bind the rig to the second pool, the way a real session would.
	co.mu.Lock()
	co.sessions[0] = []downstreamSession{&rigSession{co: co, rigIdx: 0, up: co.ups[0][1]}}
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
	// Hold a port on every interface so the dashboard's ":<port>" bind conflicts
	// (the dashboard always binds all interfaces, so holding only loopback would
	// not collide on every platform).
	busy, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	takenPort := busy.Addr().(*net.TCPAddr).Port

	// A genuinely free port for the rig, so the rig bind-check passes and the
	// dashboard bind is the only thing that fails.
	freeLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	rigPort := freeLn.Addr().(*net.TCPAddr).Port
	freeLn.Close()

	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	srv := newServer(path)

	body := fmt.Sprintf(
		`{"dashboardPort":%d,"pools":[{"name":"A","host":"h","port":23336,"statusPort":7154,"protocol":"sv1"}],`+
			`"rigs":[{"port":%d,"protocol":"sv1"}]}`, takenPort, rigPort)

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

// A gateway configured with no pool, as DATUM prints it (datum_api.c):
// "Non-Pooled Mode" and a pool host of "N/A". The job section, with the
// network difficulty, is printed either way. "Block Difficulty" is the expected
// WORK per block (difficulty x 2^32), SI-formatted -- here 27.2E = 2.72e19
// hashes, the real shape an XBT gateway prints. parseNetworkDifficulty turns
// that back into a difficulty of ~6.33e9.
const soloGatewayPage = `<html><head><title>DATUM Gateway Status</title></head><body>
  <tr><td>Pool Shares Accepted:</td><td>0 (0 diff)</td></tr>
  <tr><td>Pool Shares Rejected:</td><td>0 (0 diff)</td></tr>
  <tr><td>Status:</td><td><svg viewBox='0 0 100 100'><circle style='fill:lime' /></svg> Non-Pooled Mode</td></tr>
  <tr><td>Pool Host:</td><td>N/A</td></tr>
  <tr><td>Pool Tag:</td><td>"d8dd1618"</td></tr>
  <tr><td>Block Height:</td><td>975730</td></tr>
  <tr><td>Block Difficulty:</td><td>27.2E</td></tr>
</body></html>`

func inspectPage(t *testing.T, page string) *gatewayHealth {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(page))
	}))
	defer srv.Close()
	h, err := inspectGatewayFull(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	return h
}

// parseNetworkDifficulty must scale DATUM's SI suffix and normalise the WORK it
// prints (difficulty x 2^32 hashes) back to a difficulty. Reading "27.2E" as
// 27.2 -- dropping the suffix and skipping the normalisation -- put the solo
// card off by ~2.7e11 and produced "~1 min to a block, 1 in 1 chance per day"
// for a sub-terahash miner whose real odds are a block every year or so.
func TestParseNetworkDifficulty(t *testing.T) {
	for _, c := range []struct {
		name string
		text string
		want float64
	}{
		// siScale[""]=1, so a plain value is still read as work and /2^32'd.
		{"plain number is work in hashes", "Block Difficulty: 4294967296", 4294967296.0 / twoPow32},
		{"exa suffix, the real XBT shape", "Block Difficulty: 27.2E", 27.2 * 1e18 / twoPow32},
		{"no whitespace before the suffix", "Block Difficulty:27.2E", 27.2 * 1e18 / twoPow32},
		{"peta suffix", "Block Difficulty: 123.5P", 123.5 * 1e15 / twoPow32},
		{"lowercase kilo scales like K", "Block Difficulty: 50k", 50 * 1e3 / twoPow32},
		// Tags are stripped before parsing, so the next label follows the value.
		{"suffix before the next label", "Block Difficulty: 27.2E Version: a0000000", 27.2 * 1e18 / twoPow32},
		{"next label is not a suffix", "Block Difficulty: 4294967296 Total Shares: 9", 4294967296.0 / twoPow32},
		{"next label on another line", "Block Difficulty: 4294967296\nPrevious Block: x", 4294967296.0 / twoPow32},
		{"absent field is zero", "Block Height: 975730", 0},
		{"unparseable value is zero", "Block Difficulty: n/a", 0},
	} {
		// Exact compare: want mirrors the parser's own float operations.
		if got := parseNetworkDifficulty(c.text); got != c.want {
			t.Errorf("%s: parseNetworkDifficulty(%q) = %v, want %v", c.name, c.text, got, c.want)
		}
	}
}

// The solo entry's "no pool" is the point, not an outage. The same page on an
// UNMARKED entry keeps today's warning: that is the off-path workaround, and
// it is flagged, not stopped.
func TestSoloRoleSilencesTheUnpooledWarning(t *testing.T) {
	h := inspectPage(t, soloGatewayPage)
	// 27.2E hashes of work, normalised to difficulty. Same float ops as the
	// parser, so this compares exactly.
	wantDiff := 27.2 * 1e18 / twoPow32
	if h.NetworkDifficulty != wantDiff {
		t.Errorf("NetworkDifficulty = %v, want %v", h.NetworkDifficulty, wantDiff)
	}

	solo := *h
	solo.applyRole(true)
	if solo.Unpooled || solo.SoloMismatch {
		t.Errorf("solo entry on a no-pool gateway: unpooled=%v mismatch=%v, want neither", solo.Unpooled, solo.SoloMismatch)
	}

	unmarked := *h
	unmarked.applyRole(false)
	if !unmarked.Unpooled {
		t.Error("unmarked no-pool gateway lost its unpooled warning")
	}
}

// Marked solo but pointed at a pool: the dashboard would call pool work solo.
// Warn-only -- flagged, never refused.
func TestSoloMarkedButPooledIsAMismatch(t *testing.T) {
	h := inspectPage(t, `<html><head><title>DATUM Gateway Status</title></head><body>
	  <tr><td>Status:</td><td>Connected and Ready</td></tr>
	  <tr><td>Pool Host:</td><td>tides.example.ca:28916</td></tr>
	</body></html>`)
	h.applyRole(true)
	if !h.SoloMismatch {
		t.Error("solo entry on a pooled gateway was not flagged")
	}
	if h.Unpooled {
		t.Error("solo entry flagged unpooled; the mismatch is the only warning that applies")
	}
}

// /status carries the role, and the page's literal "N/A" never becomes the
// pool's host.
func TestStatusMarksTheSoloPool(t *testing.T) {
	cfg := config{
		Pools: []poolConfig{
			// A real pool called "Solo", next to the solo entry: no name is
			// reserved, and the two must stay distinct.
			{Name: "Solo", Host: "127.0.0.1", Port: 23336, StatusPort: 7154},
			{Solo: true, Host: "127.0.0.1", Port: 23339, StatusPort: 7157},
		},
		Rigs: []rigConfig{{Port: 23401, Protocol: "sv1"}},
	}
	cfg.applyDefaults()
	co := newCoordinator(cfg)
	h := inspectPage(t, soloGatewayPage)
	h.applyRole(true)
	co.gw.set(cfg.Pools[1].displayName(), *h)

	doc := co.status()
	if doc.Pools[0].Solo || !doc.Pools[1].Solo {
		t.Errorf("solo flags = %v,%v, want false,true", doc.Pools[0].Solo, doc.Pools[1].Solo)
	}
	if doc.Pools[0].Name == doc.Pools[1].Name {
		t.Errorf("the pool named Solo and the solo entry share the name %q", doc.Pools[0].Name)
	}
	if doc.Pools[0].Health != nil {
		t.Error("the solo entry's health landed on the pool named Solo")
	}
	if doc.Pools[1].Host == gatewayNoPoolHost {
		t.Errorf("solo pool host is the page's literal %q", gatewayNoPoolHost)
	}
	if doc.Pools[1].Health == nil || doc.Pools[1].Health.NetworkDifficulty == 0 {
		t.Error("solo pool health is missing the network difficulty")
	}
}

// The rejecting warning is the journal's record of the costliest trap there
// is (pool_pass_full_users), so it must say WHICH pool. Gateways usually all
// sit on 127.0.0.1, so a host alone names none of them.
func TestRejectingWarningNamesThePool(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<html><head><title>DATUM Gateway Status</title></head><body>
		  <tr><td>Pool Shares Accepted:</td><td>0 (0 diff)</td></tr>
		  <tr><td>Pool Shares Rejected:</td><td>9 (9216 diff)</td></tr>
		  <tr><td>Status:</td><td>Connected and Ready</td></tr>
		  <tr><td>Pool Host:</td><td>pool.example.tech:28915</td></tr>
		</body></html>`))
	}))
	defer srv.Close()
	host, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	sp, _ := strconv.Atoi(port)

	var buf syncBuffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)

	co := newCoordinator(config{
		Pools:              []poolConfig{{Name: "RIPTIDE", Host: host, Port: 23336, StatusPort: sp}},
		GatewayPollSeconds: 5,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go co.watchGateways(ctx)

	deadline := time.Now().Add(3 * time.Second)
	for !strings.Contains(buf.String(), "is rejecting") {
		if time.Now().After(deadline) {
			t.Fatalf("no rejecting warning logged; log was:\n%s", buf.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
	if line := buf.String(); !strings.Contains(line, "RIPTIDE") {
		t.Errorf("rejecting warning does not name the pool:\n%s", line)
	}
}

// syncBuffer is a bytes.Buffer safe to share between the logger and a test.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// A live pair, captured 2026-11-23 from a mainnet gateway: the page's
// "Previous Block" (display order) and the prevhash switchyard's rotation
// clock held at that moment, which came from the same gateway's SV2 job.
const (
	liveDisplayPrev = "00000000000000005866e7b2095db7eb8a1d8b4502e2c212b8c593f9346a9449"
	liveHiddenPrev  = "0000000000007d77ce6655610f4da212085b7408c3cf9716be72a6441adb4aa3"
)

// The page and the jobs name the same block in two different ways; the height
// is only usable if one can be turned into the other exactly.
func TestHiddenPrevhashMatchesDatum(t *testing.T) {
	if got := hiddenPrevhash(liveDisplayPrev); got != liveHiddenPrev {
		t.Fatalf("hiddenPrevhash = %s, want %s", got, liveHiddenPrev)
	}
	for _, bad := range []string{"", "zz", liveDisplayPrev[:62]} {
		if got := hiddenPrevhash(bad); got != "" {
			t.Errorf("hiddenPrevhash(%q) = %q, want empty", bad, got)
		}
	}
}

// The job section as DATUM really prints it: the hash's leading zeros sit in
// their own span, so the flattened text splits the hash in two.
const heightGatewayPage = `<html><head><title>DATUM Gateway Status</title></head><body>
  <tr><td>Status:</td><td>Connected and Ready</td></tr>
  <tr><td>Pool Host:</td><td>pool.example:23334</td></tr>
  <tr><td class="label">Block Height:</td><td>983250</td></tr>
  <tr><td class="label">Previous Block:</td>
      <td class="fixed-width"><span class='leading_zeros'>0000000000000000</span>5866e7b2095db7eb8a1d8b4502e2c212b8c593f9346a9449</td></tr>
  <tr><td class="label">Block Target:</td><td class="fixed-width">00000000ffff</td></tr>
</body></html>`

func TestGatewayPageYieldsTipHeight(t *testing.T) {
	h := inspectPage(t, heightGatewayPage)
	if h.BlockHeight != 983250 || h.PrevBlock != liveDisplayPrev {
		t.Fatalf("parsed height=%d prev=%q", h.BlockHeight, h.PrevBlock)
	}

	co := newCoordinator(mixedProtoConfig(t))
	// A height for a tip switchyard is not on is never shown -- not before
	// any tip, and not for a different one.
	co.noteGatewayTip(hiddenPrevhash(h.PrevBlock), h.BlockHeight-1)
	if s := co.status(); s.TipHeight != 0 {
		t.Fatalf("height shown with no tip: %d", s.TipHeight)
	}
	co.noteBlock(liveHiddenPrev)
	if co.tipHeightKnown() || co.status().TipHeight != 0 {
		t.Fatal("a height read before the tip arrived was kept")
	}
	co.noteGatewayTip(hiddenPrevhash(h.PrevBlock), h.BlockHeight-1)
	if s := co.status(); s.TipHeight != 983249 || !co.tipHeightKnown() {
		t.Fatalf("tip height = %d, want 983249 (the template is one above the tip)", s.TipHeight)
	}
	// The next block: the old height must not be shown against the new tip.
	next := "0000000000001111" + liveHiddenPrev[16:]
	co.noteBlock(next)
	if s := co.status(); s.TipHeight != 0 || co.tipHeightKnown() {
		t.Fatalf("stale height %d shown against a new tip", s.TipHeight)
	}
	// And noteBlock asked the poller for a fresh read.
	select {
	case <-co.gwKick:
	default:
		t.Fatal("a new block did not request a gateway read")
	}
}
