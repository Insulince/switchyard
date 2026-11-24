package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"sync"
	"testing"
	"time"
)

// fakeCanonSink stands in for an sv2RigSession: it records the work the link
// pushes to it.
type fakeCanonSink struct {
	mu      sync.Mutex
	got     []sv2Work
	stopped bool
}

func (f *fakeCanonSink) pushWork(w sv2Work) {
	f.mu.Lock()
	f.got = append(f.got, w)
	f.mu.Unlock()
}

func (f *fakeCanonSink) stop() {
	f.mu.Lock()
	f.stopped = true
	f.mu.Unlock()
}

func (f *fakeCanonSink) jobs() []uint32 {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]uint32, len(f.got))
	for i, w := range f.got {
		out[i] = w.JobID
	}
	return out
}

// mixedProtoConfig is one rig with two pools: an SV1 gateway and an SV2 gateway.
// It is the shape the whole mixed-mesh design exists to carry.
func mixedProtoConfig(t *testing.T) config {
	t.Helper()
	cfg := config{
		Pools: []poolConfig{
			{Name: "sv1pool", Host: "127.0.0.1", Port: 23338, StatusPort: 7156, Protocol: "sv1"},
			{Name: "sv2pool", Host: "127.0.0.1", Port: 23358, StatusPort: 7157,
				Protocol: "sv2", AuthorityKey: testAuthorityKey(t)},
		},
		Rigs: []rigConfig{{Port: 23401, Protocol: "sv1"}},
	}
	cfg.applyDefaults()
	return cfg
}

// readyWork is a plausible SV2 work snapshot, as an sv2Upstream would deliver on
// a new prevhash. The target is difficulty-1 so set_difficulty is exercised.
func readyWork() sv2Work {
	var prev, comm [32]byte
	for i := range prev {
		prev[i] = byte(i + 1)
		comm[i] = byte(0xff - i)
	}
	return sv2Work{
		ChannelID:        7,
		ExtranoncePrefix: []byte{0xb1, 0x0c, 0xf0, 0x0d},
		JobID:            0x0000002a,
		Commitment:       comm,
		PrevHash:         prev,
		Nbits:            0x1b0fffff,
		Target:           leTargetFromBig(sv1Diff1Target),
		Clean:            true,
		Ready:            true,
	}
}

// leTargetFromBig renders a big-endian target value as the little-endian [32]byte
// the SV2 wire (and sv2Work) carries.
func leTargetFromBig(v *big.Int) [32]byte {
	be := v.FillBytes(make([]byte, 32))
	var le [32]byte
	for i := 0; i < 32; i++ {
		le[i] = be[31-i]
	}
	return le
}

// The mesh is built by protocol: an SV1 pool becomes an *upstream, an SV2 pool
// an *sv2Link, side by side under one coordinator. This is the dispatch that
// newPoolLink exists to make, and the proof that a mixed config is first-class.
func TestNewPoolLinkDispatchByProtocol(t *testing.T) {
	co := newCoordinator(mixedProtoConfig(t))

	if _, ok := co.ups[0][0].(*upstream); !ok {
		t.Errorf("sv1 pool built a %T, want *upstream", co.ups[0][0])
	}
	if _, ok := co.ups[0][1].(*sv2Link); !ok {
		t.Errorf("sv2 pool built a %T, want *sv2Link", co.ups[0][1])
	}
}

// Before its channel opens, an SV2 link is not bindable: it reports not-ready and
// refuses a bind. This is what lets an SV2 pool sit in a live config safely while
// its gateway is unreachable -- upstreamForRig skips a not-ready link, so a rig
// falls back to an SV1 pool instead of looping on a bind that cannot complete.
func TestSv2LinkIsNotBindableBeforeChannelOpens(t *testing.T) {
	co := newCoordinator(mixedProtoConfig(t))
	l := co.ups[0][1].(*sv2Link)
	sess := &rigSession{co: co, rigIdx: 0}

	if l.isReady() {
		t.Error("isReady is true before the channel is open; a rig would be trapped on it")
	}
	if _, _, _, ok := l.attach(sess); ok {
		t.Error("attach succeeded before the channel is open")
	}
	if l.statsAt(time.Now()).ready {
		t.Error("statsAt reports ready before the channel is open")
	}
	if l.connInfo().connected {
		t.Error("connInfo reports connected before the channel is open")
	}
}

// Once work flows, the link becomes bindable and hands the rig the channel's
// extranonce_prefix as its SV1 extranonce1. A second miner is refused (one per
// SV2 port for now). Driving ingest directly stands in for the sv2Upstream, so
// this needs no gateway.
func TestSv2LinkBecomesBindableOnWork(t *testing.T) {
	co := newCoordinator(mixedProtoConfig(t))
	l := co.ups[0][1].(*sv2Link)

	l.ingest(readyWork())

	if !l.isReady() {
		t.Fatal("link did not become ready after a ready work update")
	}
	if !l.statsAt(time.Now()).ready || !l.connInfo().connected {
		t.Error("stats/connInfo do not reflect an open channel")
	}

	en1, en2, cfg, ok := l.attach(&rigSession{co: co, rigIdx: 0})
	if !ok {
		t.Fatal("attach refused after the channel opened")
	}
	if en1 != "b10cf00d" {
		t.Errorf("extranonce1 = %q, want the channel prefix b10cf00d", en1)
	}
	if en2 != xbtExtranonceSize {
		t.Errorf("extranonce2_size = %d, want %d", en2, xbtExtranonceSize)
	}
	if cfg != nil {
		t.Error("SV2 link offered a mining.configure result; it has none")
	}
	if _, _, _, ok := l.attach(&rigSession{co: co, rigIdx: 0}); ok {
		t.Error("a second miner was allowed onto an SV2 port")
	}
}

// SV2 work drives the rotation clock exactly as an SV1 mining.notify does. Before
// this, an all-SV2 mesh never reported a prevhash: the chain tip stayed empty,
// the dwell ceiling never armed, and the schedule froze at step 0 forever.
func TestSv2LinkWorkDrivesRotationClock(t *testing.T) {
	co := newCoordinator(mixedProtoConfig(t))
	l := co.ups[0][1].(*sv2Link)

	// Work before any SetNewPrevHash carries a zero prevhash: not a block.
	early := readyWork()
	early.PrevHash = [32]byte{}
	l.ingest(early)
	if s := co.status(); s.LastPrevhash != "" || !s.LastRotate.IsZero() {
		t.Fatalf("a zero prevhash seeded the clock: tip=%q lastRotate=%v", s.LastPrevhash, s.LastRotate)
	}

	// The first real prevhash: tracked (and the ceiling armed), but not a rotation.
	w := readyWork()
	l.ingest(w)
	s := co.status()
	if want := hex.EncodeToString(w.PrevHash[:]); s.LastPrevhash != want {
		t.Fatalf("chain tip = %q, want %q", s.LastPrevhash, want)
	}
	if s.LastRotate.IsZero() {
		t.Fatal("first prevhash did not arm the dwell ceiling")
	}
	if s.Rotations != 0 {
		t.Fatalf("the first prevhash must not rotate, got %d", s.Rotations)
	}

	// The tip string is the same one the SV1 rigs see in mining.notify params[1],
	// so SV1 and SV2 gateways in one mesh agree on what "the same block" is.
	var params []json.RawMessage
	var msg struct {
		Params json.RawMessage `json:"params"`
	}
	if err := json.Unmarshal(l.lastNotify, &msg); err != nil || json.Unmarshal(msg.Params, &params) != nil {
		t.Fatalf("rendered notify did not parse: %s", l.lastNotify)
	}
	var notifyPrev string
	_ = json.Unmarshal(params[1], &notifyPrev)
	if notifyPrev != s.LastPrevhash {
		t.Fatalf("tip %q differs from the notify prevhash %q an SV1 path would report", s.LastPrevhash, notifyPrev)
	}

	// A new job on the same block is not a block.
	same := readyWork()
	same.JobID++
	l.ingest(same)
	if got := co.status().Rotations; got != 0 {
		t.Fatalf("a new job on the same prevhash rotated (%d)", got)
	}

	// A new prevhash past the dwell floor rotates once.
	co.mu.Lock()
	co.lastRotate = time.Now().Add(-time.Hour)
	co.mu.Unlock()
	next := readyWork()
	next.PrevHash[0] ^= 0xff
	l.ingest(next)
	if got := co.status().Rotations; got != 1 {
		t.Fatalf("a new SV2 prevhash should rotate once, got %d", got)
	}
}

// The notify the link renders from SV2 work is a real mining.notify whose job_id
// is the SV2 job id in hex -- the bridge the share path parses back on submit.
func TestSv2LinkRendersNotifyWithJobID(t *testing.T) {
	co := newCoordinator(mixedProtoConfig(t))
	l := co.ups[0][1].(*sv2Link)
	l.ingest(readyWork())

	l.mu.Lock()
	notify := l.lastNotify
	l.mu.Unlock()
	if notify == nil {
		t.Fatal("no notify was rendered")
	}

	var m struct {
		Method string            `json:"method"`
		Params []json.RawMessage `json:"params"`
	}
	if err := json.Unmarshal(notify, &m); err != nil {
		t.Fatalf("rendered notify is not valid JSON: %v", err)
	}
	if m.Method != "mining.notify" {
		t.Errorf("method = %q, want mining.notify", m.Method)
	}
	var jobID string
	if err := json.Unmarshal(m.Params[0], &jobID); err != nil {
		t.Fatal(err)
	}
	if jobID != "0000002a" {
		t.Errorf("job_id = %q, want the sv2 job id in hex 0000002a", jobID)
	}
	// And it round-trips back to the SV2 job id the share path needs.
	if got, err := sv2JobIDParse(jobID); err != nil || got != 0x2a {
		t.Errorf("sv2JobIDParse(%q) = %d, %v; want 42", jobID, got, err)
	}
}

// targetToDifficulty is the one genuinely new, high-stakes computation: a wrong
// byte order or constant makes the rig flood or withhold by a huge factor. These
// vectors pin it. The difficulty-1 target gives difficulty 1; a target 1024x
// smaller gives difficulty 1024.
func TestTargetToDifficulty(t *testing.T) {
	if d := targetToDifficulty(leTargetFromBig(sv1Diff1Target)); !approx(d, 1, 1e-6) {
		t.Errorf("difficulty-1 target gave difficulty %v, want 1", d)
	}
	d1024 := new(big.Int).Rsh(sv1Diff1Target, 10) // diff1 / 1024
	if d := targetToDifficulty(leTargetFromBig(d1024)); !approx(d, 1024, 1e-3) {
		t.Errorf("1024x-smaller target gave difficulty %v, want 1024", d)
	}
	var zero [32]byte
	if d := targetToDifficulty(zero); d != 0 {
		t.Errorf("zero target gave %v, want 0 (guarded, no divide by zero)", d)
	}
}

// difficultyToTarget is the inverse of targetToDifficulty; a difficulty rendered
// to a target and read back is the same difficulty. This is the relation an SV2
// rig on an SV1 pool depends on for its share threshold.
func TestDifficultyTargetRoundTrip(t *testing.T) {
	for _, d := range []uint64{1, 1024, 65536, 268435456} {
		if got := targetToDifficulty(difficultyToTarget(d)); !approx(got, float64(d), 1e-6) {
			t.Errorf("difficulty %d -> target -> %v, want %d", d, got, d)
		}
	}
}

func approx(got, want, tol float64) bool {
	d := got - want
	if d < 0 {
		d = -d
	}
	return d <= tol*want+tol
}

// upstreamForRig must not hand a rig to an SV2 pool while its channel is not
// open, even when that pool is the scheduled one. (Neither gateway is reachable
// here, so the SV2 link never opens; the point is only that it is not chosen.)
func TestUnreadySv2PoolIsNeverSelected(t *testing.T) {
	co := newCoordinator(mixedProtoConfig(t))
	co.mu.Lock()
	co.cur[0] = 1 // schedule rig 0 onto the SV2 pool
	co.mu.Unlock()
	if u, ok := co.upstreamForRig(0); ok {
		if _, isSv2 := u.(*sv2Link); isSv2 {
			t.Error("upstreamForRig handed a rig to an SV2 link whose channel is not open")
		}
	}
}

// The status document reports each pool's and rig's protocol, so the dashboard
// can badge the SV2 hops and leave SV1 unmarked.
func TestStatusReportsProtocol(t *testing.T) {
	co := newCoordinator(mixedProtoConfig(t))
	doc := co.status()
	if doc.Pools[0].Protocol != "sv1" {
		t.Errorf("sv1 pool protocol = %q, want sv1", doc.Pools[0].Protocol)
	}
	if doc.Pools[1].Protocol != "sv2" {
		t.Errorf("sv2 pool protocol = %q, want sv2", doc.Pools[1].Protocol)
	}
	if doc.Rigs[0].Protocol != "sv1" {
		t.Errorf("rig protocol = %q, want sv1", doc.Rigs[0].Protocol)
	}
}

// run returns promptly when the context is already cancelled: it waits on
// credState for the miner's identity before dialling, and a cancel releases that
// wait, so a reload never hangs on an SV2 pool whose miner never turned up.
func TestSv2LinkRunReturnsOnCancel(t *testing.T) {
	co := newCoordinator(mixedProtoConfig(t))
	l := co.ups[0][1].(*sv2Link)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	done := make(chan struct{})
	go func() { l.run(ctx); close(done) }()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("run did not return on a cancelled context")
	}
}

// An SV2 downstream binds in canonical terms: attachCanon returns the current
// work for its channel-open, later work updates are pushed to it as sv2Work
// (which it renders itself), and the bind is mutually exclusive with an SV1 one
// -- one miner per port. This is the surface sv2RigSession consumes (step 5b).
func TestSv2LinkCanonBindingDeliversWork(t *testing.T) {
	co := newCoordinator(mixedProtoConfig(t))
	l := co.ups[0][1].(*sv2Link)
	l.ingest(readyWork()) // channel opens

	sink := &fakeCanonSink{}
	w, ok := l.attachCanon(sink)
	if !ok {
		t.Fatal("attachCanon refused after the channel opened")
	}
	if w.JobID != 0x2a {
		t.Errorf("attachCanon returned job %#x, want the current 0x2a", w.JobID)
	}

	// An SV1 bind is now refused: the port already has an SV2 miner.
	if _, _, _, ok := l.attach(&rigSession{co: co, rigIdx: 0}); ok {
		t.Error("an SV1 miner was allowed onto a port already held by an SV2 miner")
	}

	// A later work update reaches the SV2 sink as canonical work.
	w2 := readyWork()
	w2.JobID = 0x99
	l.ingest(w2)
	var delivered bool
	for _, j := range sink.jobs() {
		if j == 0x99 {
			delivered = true
		}
	}
	if !delivered {
		t.Errorf("sink never received the 0x99 work update; got jobs %x", sink.jobs())
	}

	// Detaching frees the port for a new bind.
	l.detachCanon(sink)
	if _, _, _, ok := l.attach(&rigSession{co: co, rigIdx: 0}); !ok {
		t.Error("SV1 bind refused after the SV2 downstream detached")
	}
}

// submitCanon refuses when the link has no live upstream session, so an SV2
// downstream never silently drops a share into a closed socket.
func TestSv2LinkSubmitCanonNeedsConnection(t *testing.T) {
	co := newCoordinator(mixedProtoConfig(t))
	l := co.ups[0][1].(*sv2Link)
	l.ingest(readyWork()) // channel "open" for work, but l.up is nil (no real session)
	if _, err := l.submitCanon(0x2a, 1, 0, []byte{1, 2, 3, 4, 5, 6, 7, 8}); err == nil {
		t.Error("submitCanon did not refuse with no upstream session")
	}
}

// A sanity check that the rendered extranonce1 is exactly the channel prefix in
// hex, the identity the SV1<->SV2 leaf equivalence depends on.
func TestSv2LinkExtranonceMatchesPrefix(t *testing.T) {
	co := newCoordinator(mixedProtoConfig(t))
	l := co.ups[0][1].(*sv2Link)
	w := readyWork()
	l.ingest(w)
	en1, _, _, ok := l.attach(&rigSession{co: co, rigIdx: 0})
	if !ok {
		t.Fatal("attach refused")
	}
	if en1 != hex.EncodeToString(w.ExtranoncePrefix) {
		t.Errorf("extranonce1 = %q, want %x", en1, w.ExtranoncePrefix)
	}
}
