package main

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"net"
	"testing"
	"time"
)

// An SV2 rig session is a first-class downstreamSession: once bound it shows on
// the dashboard like any rig, and a rotation drops it (marked as switchyard's
// doing) so its reconnect lands on the newly-scheduled pool.
func TestSv2RigSessionRotatesLikeAnyRig(t *testing.T) {
	co := newCoordinator(mixedProtoConfig(t))
	l := co.ups[0][1].(*sv2Link)
	l.ingest(readyWork()) // the SV2 link opens

	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	s := newSv2RigSession(co, 0, c1, nil, nil)
	s.user = "worker1"
	s.link = l
	if _, ok := l.attachCanon(s); !ok {
		t.Fatal("attachCanon refused a ready link")
	}
	co.setSession(0, s)

	// The dashboard now renders it as a connected rig under its own name, on the
	// pool it is bound to.
	doc := co.status()
	if !doc.Rigs[0].Connected || doc.Rigs[0].ClaimedUser != "worker1" {
		t.Errorf("sv2 rig not rendered: connected=%v user=%q", doc.Rigs[0].Connected, doc.Rigs[0].ClaimedUser)
	}
	if doc.Rigs[0].BoundTo != l.displayName() {
		t.Errorf("sv2 rig BoundTo = %q, want %q", doc.Rigs[0].BoundTo, l.displayName())
	}

	// A rotation drops it, attributed to switchyard.
	co.rotate("test rotation")
	select {
	case <-s.doneChan():
	case <-time.After(time.Second):
		t.Fatal("rotation did not close the sv2 rig session")
	}
	if !s.rotatedByUs() {
		t.Error("the sv2 session's gap would read as a miner fault, not a rotation")
	}
}

// primeSV1Upstream fakes an SV1 gateway session that has subscribed (extranonce),
// taken a difficulty, and pushed the real captured XBT notify -- enough state for
// the canonical synthesis an SV2 rig binding to this SV1 pool depends on.
func primeSV1Upstream(t *testing.T, diff uint64) *upstream {
	t.Helper()
	co := newCoordinator(testConfig())
	u := co.ups[0][0].(*upstream)
	u.ready = true
	u.user = "payout.worker"
	u.extranonce1 = "b10cf00d"
	u.extranonce2Size = 8
	u.diff = diff
	u.lastNotifyRaw = json.RawMessage(realSV1Notify)
	return u
}

// An SV2 rig can bind to an SV1 pool: the pool synthesises an sv2Work from its
// stratum state. The commitment and extranonce prefix come straight from the SV1
// notify/subscribe, and the target is the SV2 form of the pool's difficulty.
func TestUpstreamSynthesisesCanonWorkForSv2Rig(t *testing.T) {
	u := primeSV1Upstream(t, 1024)
	sink := &fakeCanonSink{}

	w, ok := u.attachCanon(sink)
	if !ok {
		t.Fatal("attachCanon refused a ready SV1 upstream with a job")
	}
	if got := hexString(w.Commitment[:]); got != realCommitmentHex {
		t.Errorf("commitment = %s, want %s", got, realCommitmentHex)
	}
	if got := hexString(w.ExtranoncePrefix); got != "b10cf00d" {
		t.Errorf("extranonce_prefix = %s, want b10cf00d", got)
	}
	if w.JobID == 0 {
		t.Error("no job id was assigned")
	}
	// The target round-trips to the difficulty it was built from.
	if d := targetToDifficulty(w.Target); !approx(d, 1024, 1e-3) {
		t.Errorf("synthesised target gives difficulty %v, want 1024", d)
	}
	// A second miner is refused: one per port.
	if _, ok := u.attachCanon(&fakeCanonSink{}); ok {
		t.Error("a second SV2 miner was allowed onto an SV1 port")
	}
}

// A share from the SV2 rig is translated into an SV1 mining.submit under the
// pool's own authorised identity, naming the exact job it was mined on.
func TestUpstreamSubmitCanonWritesSv1Submit(t *testing.T) {
	u := primeSV1Upstream(t, 1024)
	sink := &fakeCanonSink{}
	w, ok := u.attachCanon(sink)
	if !ok {
		t.Fatal("attachCanon refused")
	}

	gw, ours := net.Pipe()
	defer gw.Close()
	defer ours.Close()
	u.w = newConnWriter(ours)

	lines := make(chan string, 1)
	go func() {
		sc := bufio.NewScanner(gw)
		if sc.Scan() {
			lines <- sc.Text()
		}
	}()

	en2 := []byte{0xaa, 0xbb, 0xcc, 0xdd, 1, 2, 3, 4}
	if _, err := u.submitCanon(w.JobID, 0x01020304, 0, en2); err != nil {
		t.Fatalf("submitCanon: %v", err)
	}

	select {
	case line := <-lines:
		var m struct {
			Method string          `json:"method"`
			Params json.RawMessage `json:"params"`
		}
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("submit line not JSON: %v (%s)", err, line)
		}
		if m.Method != "mining.submit" {
			t.Errorf("method = %q, want mining.submit", m.Method)
		}
		// params[0] is the worker: the pool's own authorised identity, unchanged.
		var parr []json.RawMessage
		_ = json.Unmarshal(m.Params, &parr)
		var worker string
		_ = json.Unmarshal(parr[0], &worker)
		if worker != "payout.worker" {
			t.Errorf("worker = %q, want the pool's authorised identity payout.worker", worker)
		}
		_, share, err := sv1SubmitToShare(m.Params)
		if err != nil {
			t.Fatalf("submit params do not parse: %v", err)
		}
		if !bytesEqual(share.Extranonce, en2) {
			t.Errorf("extranonce = %x, want %x", share.Extranonce, en2)
		}
		if share.Nonce != 0x01020304 {
			t.Errorf("nonce = %#x, want 0x01020304", share.Nonce)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("submitCanon wrote no line to the gateway")
	}
}

func hexString(b []byte) string { return hex.EncodeToString(b) }

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// serveRigSV2 fails fast on a rig whose own SV2 authority secret is unusable,
// before it ever opens a listener -- switchyard cannot present a downstream
// identity it cannot decode.
func TestServeRigSV2RejectsBadAuthoritySecret(t *testing.T) {
	cfg := config{
		Pools: []poolConfig{{Name: "p", Host: "127.0.0.1", Port: 23338, StatusPort: 7156, Protocol: "sv1"}},
		Rigs:  []rigConfig{{Port: 23401, Protocol: "sv2", AuthoritySecret: "not-hex"}},
	}
	cfg.applyDefaults()
	co := newCoordinator(cfg)

	if err := serveRigSV2(context.Background(), co, 0); err == nil {
		t.Error("serveRigSV2 accepted a rig with an undecodable authority secret")
	}
}
