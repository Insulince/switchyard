package main

import (
	"encoding/json"
	"fmt"
	"math"
	"testing"
	"time"
)

// The opening placement has the same two jobs the old randomised start had, now
// produced by the balance scheduler itself from an all-zero deficit: it must be
// BALANCED (no pool carrying two rigs while another carries none, so with rigs
// <= pools no two rigs share one) and RANDOM (no pool systematically favoured,
// which a fixed opening order would be -- biasing whichever pools the scheduler
// tries first, on every restart).
func TestOpeningPlacementIsBalanced(t *testing.T) {
	cases := []struct{ rigs, pools int }{
		{1, 3}, {2, 3}, {3, 3}, {4, 3}, {5, 3}, {7, 3},
		{2, 2}, {1, 1}, {6, 2}, {3, 7},
	}
	for _, c := range cases {
		for trial := 0; trial < 300; trial++ {
			co := newCoordinator(scheduleConfig(c.rigs, c.pools))
			load := make([]int, c.pools)
			for _, p := range co.cur {
				if p < 0 || p >= c.pools {
					t.Fatalf("rigs=%d pools=%d: placed on %d, out of range", c.rigs, c.pools, p)
				}
				load[p]++
			}
			lo, hi := load[0], load[0]
			for _, n := range load[1:] {
				if n < lo {
					lo = n
				}
				if n > hi {
					hi = n
				}
			}
			// Spread of at most one. With rigs <= pools this is also the proof
			// that no two rigs opened on the same pool.
			if hi-lo > 1 {
				t.Fatalf("rigs=%d pools=%d: unbalanced opening %v", c.rigs, c.pools, load)
			}
		}
	}
}

func TestOpeningPlacementIsRandom(t *testing.T) {
	const (
		pools  = 3
		rigs   = 2
		trials = 6000
	)
	// With 2 rigs across 3 pools exactly one pool is dark at startup, and over
	// many fresh coordinators each pool should draw that short straw about a
	// third of the time. A fixed opening order would pin it to one pool every
	// single run.
	darkCount := make([]int, pools)
	for i := 0; i < trials; i++ {
		load := make([]int, pools)
		for _, p := range newCoordinator(scheduleConfig(rigs, pools)).cur {
			load[p]++
		}
		for p, n := range load {
			if n == 0 {
				darkCount[p]++
			}
		}
	}
	want := trials / pools
	for p, got := range darkCount {
		if got < want*8/10 || got > want*12/10 {
			t.Errorf("pool %d was dark %d times, want roughly %d (%v)", p, got, want, darkCount)
		}
	}
}

// An absent miner and a miner that has not arrived yet are the same picture in
// one sample; only elapsed time separates them. The status document has to
// carry that time, or the page can do nothing but render red and hope the
// operator waits.
func TestStatusReportsHowLongARigHasBeenWaiting(t *testing.T) {
	co := newCoordinator(config{
		Pools: []poolConfig{{Host: "a", Port: 1, StatusPort: 2}, {Host: "b", Port: 3, StatusPort: 4}},
		Rigs:  []rigConfig{{Port: 23401, Protocol: "sv1"}},
	})

	// Never connected: waiting since construction, and known never to have
	// been seen.
	co.waitingSince[0] = time.Now().Add(-30 * time.Second)
	d := co.status()
	if d.Rigs[0].EverSeen {
		t.Error("a rig that has never connected should not be marked as seen")
	}
	if got := d.Rigs[0].WaitingSeconds; got < 29 || got > 32 {
		t.Errorf("waitingSeconds = %d, want about 30", got)
	}

	// Connected: the clock stops and the rig is remembered.
	s := &rigSession{co: co, rigIdx: 0}
	co.setSession(0, s)
	d = co.status()
	if !d.Rigs[0].Connected || d.Rigs[0].WaitingSeconds != 0 {
		t.Errorf("connected rig should not be waiting, got %+v", d.Rigs[0])
	}
	if !d.Rigs[0].EverSeen {
		t.Error("everSeen should stay true once a miner has connected")
	}

	// Dropped: the clock restarts, but the rig is still known.
	co.clearSession(0, s)
	d = co.status()
	if d.Rigs[0].Connected {
		t.Error("rig should be disconnected")
	}
	if !d.Rigs[0].EverSeen {
		t.Error("everSeen must survive a disconnect -- it is what distinguishes " +
			"'reconnecting' from 'never showed up'")
	}
}

// A nil slice marshals to null, which is a second empty every consumer has to
// remember to handle -- and one that did not brought the whole dashboard down
// on a config with pools but no rigs. The wire format carries [] instead.
func TestStatusNeverEmitsNullCollections(t *testing.T) {
	for _, c := range []struct {
		name string
		cfg  config
	}{
		{"no rigs", config{Pools: []poolConfig{{Host: "a", Port: 1, StatusPort: 2}}}},
		{"nothing at all", config{}},
	} {
		t.Run(c.name, func(t *testing.T) {
			b, err := json.Marshal(newCoordinator(c.cfg).status())
			if err != nil {
				t.Fatal(err)
			}
			var raw map[string]json.RawMessage
			if err := json.Unmarshal(b, &raw); err != nil {
				t.Fatal(err)
			}
			for _, key := range []string{"rigs", "pools"} {
				if string(raw[key]) == "null" {
					t.Errorf("%q marshalled as null; want []", key)
				}
			}
		})
	}
}

// Rotation costs hashrate and the figure operators judge this tool by must be
// measured, not assumed. Only gaps switchyard itself caused count: a miner
// that vanishes for its own reasons is not a rotation cost.
func TestRotationCostCountsOnlyRotationGaps(t *testing.T) {
	co := newCoordinator(config{
		Rigs:  []rigConfig{{Port: 23401, Protocol: "sv1"}},
		Pools: []poolConfig{{Name: "A", Host: "h", Port: 1, StatusPort: 2}},
	})
	s1, s2 := &rigSession{}, &rigSession{}

	// First ever connect: nothing was rotated, so nothing was lost.
	co.setSession(0, s1)
	if got := co.status().Reconnects; got != 0 {
		t.Fatalf("a first connection is not a reconnect, counted %d", got)
	}

	// A rotation drops it; the miner comes back. Marking the session is what
	// rotate() does, and clearSession is what turns that into an attributed
	// wait -- so this exercises the real path rather than the bookkeeping.
	co.mu.Lock()
	s1.rotated = true
	co.mu.Unlock()
	co.clearSession(0, s1)
	time.Sleep(5 * time.Millisecond)
	co.setSession(0, s2)

	d := co.status()
	if d.Reconnects != 1 {
		t.Fatalf("expected 1 timed rotation gap, got %d", d.Reconnects)
	}
	if d.ReconnectMeanSeconds <= 0 {
		t.Fatalf("a timed gap should have a positive mean, got %v", d.ReconnectMeanSeconds)
	}
	if d.RotationCostPct <= 0 {
		t.Fatalf("a timed gap should produce a cost, got %v", d.RotationCostPct)
	}

	// A disconnect switchyard did not cause is excluded.
	co.clearSession(0, s2)
	time.Sleep(5 * time.Millisecond)
	co.setSession(0, &rigSession{})
	if got := co.status().Reconnects; got != 1 {
		t.Fatalf("an unprompted reconnect must not be counted, got %d", got)
	}
}

// THE CENTRAL CLAIM OF THE WHOLE PROGRAM is now adherence, not arithmetic.
//
// The old (base[i]+step)%P scheme guaranteed per-cycle evenness by
// construction. The balance scheduler replaces it with a feedback rule, so the
// claim it has to earn is statistical: whatever the targets, and however
// variable the block timing, each pool's share of delivered time converges to
// the share it was asked for. These two tests are that claim -- for an even
// split and for an uneven one.

// simulateRotations drives the balance scheduler through n rotations, crediting
// each with a DELIBERATELY variable dwell so block-timing variance is part of
// the test rather than assumed away, and reports each pool's final share of
// delivered time. It exercises the real placement logic (assignLocked), not a
// model of it.
func simulateRotations(co *coordinator, n int) []float64 {
	co.mu.Lock()
	defer co.mu.Unlock()
	for r := 0; r < n; r++ {
		// A dwell that swings an order of magnitude, lump by lump: the kind of
		// uneven slot length a real chain produces, and exactly what a by-count
		// scheme could not absorb.
		dwell := float64(1 + r%20)
		for i := range co.cur {
			co.delivered[i][co.cur[i]] += dwell
		}
		co.rotations++
		co.assignLocked()
	}
	total := 0.0
	shares := make([]float64, len(co.cfg.Pools))
	for _, rig := range co.delivered {
		for j, d := range rig {
			shares[j] += d
			total += d
		}
	}
	for j := range shares {
		shares[j] /= total
	}
	return shares
}

// The reason the tallies are per rig. With one rig doing nearly all the hashing, a
// pool's share of HASHRATE only reaches its target if that rig's own time does; a
// single tally per pool could read on target with almost no hashrate behind it. So
// this weighs each rig by its hashrate, which rig-time shares alone cannot catch.
func TestHashrateFollowsTargetsWithADominantRig(t *testing.T) {
	shares := []float64{47.06, 29.41, 23.53}
	hash := []float64{16.8, .5, .5, .75, .75, .75}
	co := newCoordinator(zeroShareConfig(t, shares, len(hash)))
	co.mu.Lock()
	defer co.mu.Unlock()

	work := make([]float64, len(shares))
	total := 0.0
	for r := 0; r < 1008; r++ { // a week of blocks
		dwell := float64(1 + r%20)
		for i, p := range co.cur {
			co.delivered[i][p] += dwell
			work[p] += hash[i] * dwell
			total += hash[i] * dwell
		}
		co.rotations++
		co.assignLocked()
	}
	for j, s := range shares {
		if got := work[j] / total * 100; math.Abs(got-s) > 1 {
			t.Errorf("pool %d: %.2f%% of hashrate, want within 1 point of %.2f%%", j, got, s)
		}
	}
}

// An even split must still come out even -- the common case has to be at least
// as good as the scheme it replaced, over a realistic run.
func TestBalanceConvergesToEvenSplit(t *testing.T) {
	shares := simulateRotations(newCoordinator(scheduleConfig(3, 5)), 40000)
	for j, got := range shares {
		if math.Abs(got-0.2) > 0.01 {
			t.Errorf("pool %d share %.4f, want ~0.20 (even): %v", j, got, shares)
		}
	}
}

// The reason the feature exists: an uneven split, including a tiny solo slot,
// is delivered to within a hair of its target despite wildly variable dwells.
// The weights mirror the simulator's own example so the test reads against a
// case already seen to work.
func TestBalanceConvergesToUnevenTargets(t *testing.T) {
	cfg := config{
		Pools: []poolConfig{
			{Name: "a", Host: "h", Port: 1, StatusPort: 2, Share: sharep(64), Protocol: "sv1"},
			{Name: "b", Host: "h", Port: 3, StatusPort: 4, Share: sharep(22), Protocol: "sv1"},
			{Name: "c", Host: "h", Port: 5, StatusPort: 6, Share: sharep(4), Protocol: "sv1"},
			{Name: "d", Host: "h", Port: 7, StatusPort: 8, Share: sharep(9), Protocol: "sv1"},
			{Solo: true, Host: "gw", Port: 9, StatusPort: 10, Share: sharep(1), Protocol: "sv1"},
		},
		Rigs: []rigConfig{{Port: 23401, Protocol: "sv1"}, {Port: 23402, Protocol: "sv1"}, {Port: 23403, Protocol: "sv1"}},
	}
	cfg.applyDefaults()
	if err := cfg.validate(); err != nil {
		t.Fatalf("fixture invalid: %v", err)
	}
	shares := simulateRotations(newCoordinator(cfg), 60000)
	want := cfg.targets()
	for j := range want {
		if math.Abs(shares[j]-want[j]) > 0.01 {
			t.Errorf("pool %d (target %.2f) delivered %.4f, want within 0.01: %v",
				j, want[j], shares[j], shares)
		}
	}
}

// zeroShareConfig is a valid config with the given shares and rig count.
func zeroShareConfig(t *testing.T, shares []float64, rigs int) config {
	t.Helper()
	var cfg config
	for j, s := range shares {
		cfg.Pools = append(cfg.Pools, poolConfig{
			Name: fmt.Sprintf("p%d", j), Host: "h", Port: 100 + 2*j, StatusPort: 101 + 2*j, Share: sharep(s), Protocol: "sv1",
		})
	}
	for i := 0; i < rigs; i++ {
		cfg.Rigs = append(cfg.Rigs, rigConfig{Port: 23401 + i, Protocol: "sv1"})
	}
	cfg.applyDefaults()
	if err := cfg.validate(); err != nil {
		t.Fatalf("fixture invalid: %v", err)
	}
	return cfg
}

// A pool set to 0% gets no rigs, ever. Not at startup, where every deficit is
// zero and it would otherwise tie with the real pools, and not when rigs
// outnumber the pools that want them, where the anti-clumping penalty would
// otherwise push the spare rig onto it. The long-run share cannot catch either:
// a few stray slots round to nothing over thousands of rotations, so this looks
// at every placement rather than at the final numbers.
func TestZeroSharePoolIsNeverScheduled(t *testing.T) {
	cases := []struct {
		shares []float64
		rigs   int
	}{
		{[]float64{50, 50, 0}, 1},
		{[]float64{50, 50, 0}, 2},
		{[]float64{50, 50, 0}, 3},
		{[]float64{50, 50, 0}, 6},
		{[]float64{100, 0}, 1},
		{[]float64{100, 0}, 2},
		{[]float64{0, 60, 0, 40}, 5},
	}
	for _, c := range cases {
		cfg := zeroShareConfig(t, c.shares, c.rigs)
		for trial := 0; trial < 200; trial++ {
			co := newCoordinator(cfg)
			co.mu.Lock()
			for r := 0; r < 50; r++ {
				for i, p := range co.cur {
					if c.shares[p] == 0 {
						t.Fatalf("shares %v, %d rigs: rig %d placed on 0%% pool %d at rotation %d",
							c.shares, c.rigs, i, p, r)
					}
				}
				for i, p := range co.cur {
					co.delivered[i][p] += float64(1 + r%20)
				}
				co.rotations++
				co.assignLocked()
			}
			co.mu.Unlock()
		}
	}
}

// Excluding the 0% pool must not disturb the split among the others: the rigs
// it would have taken double up, and the targets still converge.
func TestZeroSharePoolLeavesOtherTargetsIntact(t *testing.T) {
	shares := []float64{70, 30, 0}
	cfg := zeroShareConfig(t, shares, 4)
	got := simulateRotations(newCoordinator(cfg), 40000)
	for j, s := range shares {
		if math.Abs(got[j]-s/100) > 0.01 {
			t.Errorf("pool %d delivered %.4f, want ~%.2f: %v", j, got[j], s/100, got)
		}
	}
	if got[2] != 0 {
		t.Errorf("0%% pool delivered %v, want exactly 0", got[2])
	}
}

// The fallback is the other way a rig reaches a pool, and "any ready gateway"
// must not include one the operator set to 0%. The 0% pool is deliberately
// first: it is the first gateway the fallback loop reaches.
func TestFallbackSkipsZeroSharePool(t *testing.T) {
	cfg := zeroShareConfig(t, []float64{0, 50, 50}, 1)
	cases := []struct {
		name    string
		ready   []bool
		wantOK  bool
		wantIdx int
	}{
		{"scheduled gateway up", []bool{true, true, true}, true, 1},
		{"falls back to the other real pool", []bool{true, false, true}, true, 2},
		{"only the 0% pool is up: no rig is better", []bool{true, false, false}, false, 0},
	}
	for _, c := range cases {
		co := newCoordinator(cfg)
		co.mu.Lock()
		co.cur[0] = 1
		co.mu.Unlock()
		for j, ready := range c.ready {
			u := co.ups[0][j].(*upstream)
			u.mu.Lock()
			u.ready = ready
			u.mu.Unlock()
		}
		got, ok := co.upstreamForRig(0)
		if ok != c.wantOK {
			t.Errorf("%s: ok = %v, want %v", c.name, ok, c.wantOK)
			continue
		}
		if ok && got != co.ups[0][c.wantIdx] {
			t.Errorf("%s: bound to %s, want pool %d", c.name, got.displayName(), c.wantIdx)
		}
	}
}

// The real rotate path, which the convergence simulations go around by crediting
// delivered themselves: the dwell that just ended lands on the pool each rig spent
// it on and nowhere else, and the rig then leaves that pool because it is now the
// one furthest ahead.
func TestRotateCreditsTheDwellToEachRigsPool(t *testing.T) {
	co := newCoordinator(zeroShareConfig(t, []float64{50, 30, 20}, 3))
	const dwell = 600.0

	co.mu.Lock()
	before := append([]int(nil), co.cur...)
	co.lastRotate = time.Now().Add(-dwell * time.Second)
	co.mu.Unlock()

	co.rotate("test")

	co.mu.Lock()
	defer co.mu.Unlock()
	for i, on := range before {
		for p, got := range co.delivered[i] {
			want := 0.0
			if p == on {
				want = dwell
			}
			if math.Abs(got-want) > 5 {
				t.Errorf("rig %d: delivered[%d] = %.1f, want about %.0f (it was on pool %d)", i, p, got, want, on)
			}
		}
		if co.cur[i] == on {
			t.Errorf("rig %d stayed on pool %d, the one it just overshot", i, on)
		}
	}
}

// The rotation trigger itself: a new prevhash rotates, the same one does not,
// and the very first job seen is switchyard arriving rather than a block.
func TestBlocksDriveRotationButTheFirstJobDoesNot(t *testing.T) {
	co := newCoordinator(scheduleConfig(2, 3))

	co.noteBlock("aaaa")
	if got := co.status().Rotations; got != 0 {
		t.Fatalf("the first job seen must not rotate, got %d rotations", got)
	}

	co.mu.Lock()
	co.lastRotate = time.Now().Add(-time.Hour) // past the dwell floor
	co.mu.Unlock()

	co.noteBlock("bbbb")
	if got := co.status().Rotations; got != 1 {
		t.Fatalf("a new block should rotate once, got %d", got)
	}

	// The same block again is not a new block.
	co.noteBlock("bbbb")
	if got := co.status().Rotations; got != 1 {
		t.Fatalf("a repeated prevhash must not rotate, got %d", got)
	}
}

// minDwellSeconds exists to stop a burst of fast blocks spending more time
// reconnecting than hashing. A block inside the floor must be ignored.
func TestFastBlocksAreHeldOffByTheDwellFloor(t *testing.T) {
	cfg := scheduleConfig(2, 3)
	cfg.MinDwellSeconds = 600
	co := newCoordinator(cfg)

	co.noteBlock("aaaa") // first job: starts the clock
	co.noteBlock("bbbb") // immediately after, well inside the floor

	if got := co.status().Rotations; got != 0 {
		t.Fatalf("a block inside the dwell floor must not rotate, got %d", got)
	}
}

func scheduleConfig(rigs, pools int) config {
	c := config{}
	for i := 0; i < rigs; i++ {
		c.Rigs = append(c.Rigs, rigConfig{Port: 23401 + i, Protocol: "sv1"})
	}
	for i := 0; i < pools; i++ {
		c.Pools = append(c.Pools, poolConfig{
			Name: fmt.Sprintf("pool%d", i), Host: "h",
			Port: 23336 + i, StatusPort: 7154 + i,
		})
	}
	c.applyDefaults()
	return c
}

// Resetting statistics moves the time base, so anything measured against it
// has to reset with it. Rotation cost is total lost seconds over elapsed
// rig-time: leaving the numerator behind would divide a day of accumulated
// loss by a near-zero elapsed and report an enormous cost that decayed for
// hours -- on the one operation whose whole purpose is a clean baseline.
func TestResetStatsClearsRotationCostWithTheClock(t *testing.T) {
	co := newCoordinator(scheduleConfig(1, 2))
	s1 := &rigSession{}
	co.setSession(0, s1)

	co.mu.Lock()
	s1.rotated = true
	co.mu.Unlock()
	co.clearSession(0, s1)
	time.Sleep(5 * time.Millisecond)
	co.setSession(0, &rigSession{})

	if co.status().Reconnects == 0 {
		t.Fatal("setup failed: no rotation gap was recorded")
	}

	co.resetStats()

	d := co.status()
	if d.Reconnects != 0 || d.ReconnectMeanSeconds != 0 ||
		d.ReconnectWorstSeconds != 0 || d.RotationCostPct != 0 {
		t.Fatalf("reset left rotation cost behind: %+v", struct {
			N          int
			Mean, W, P float64
		}{d.Reconnects, d.ReconnectMeanSeconds, d.ReconnectWorstSeconds, d.RotationCostPct})
	}
}

// After a restart every gateway session and every miner come up at once, and
// a miner can subscribe a moment before its SCHEDULED gateway is ready. It is
// bound to a fallback for that instant -- and must not stay there until the
// next block, sharing a pool with another rig. When the scheduled gateway
// comes up, a rig on a fallback is sent to it, and only such a rig.
func TestRigOnFallbackMovesWhenItsScheduledGatewayIsReady(t *testing.T) {
	cfg := config{
		Pools: []poolConfig{
			{Name: "a", Host: "127.0.0.1", Port: 1, StatusPort: 2},
			{Name: "b", Host: "127.0.0.1", Port: 3, StatusPort: 4},
		},
		Rigs: []rigConfig{{Port: 23401, Protocol: "sv1"}},
	}
	cfg.applyDefaults()
	co := newCoordinator(cfg)
	co.cur[0] = 1 // pin rig 0's scheduled pool to "b"

	onFallback, _ := pipeSession(t, co, "w")
	onFallback.up = co.ups[0][0]
	co.setSession(0, onFallback)

	// A gateway that is not this rig's scheduled one coming up changes nothing.
	co.gatewayReady(0, 0)
	select {
	case <-onFallback.done:
		t.Fatal("rig moved when a gateway it is not scheduled on came up")
	default:
	}

	co.gatewayReady(0, 1)
	select {
	case <-onFallback.done:
	case <-time.After(time.Second):
		t.Fatal("rig on a fallback was not sent to its scheduled gateway")
	}
	if !onFallback.rotated {
		t.Error("the move was not attributed to switchyard, so its gap would read as a miner fault")
	}

	// A rig already on its scheduled gateway is left alone.
	onTime, _ := pipeSession(t, co, "w2")
	onTime.up = co.ups[0][1]
	co.setSession(0, onTime)
	co.gatewayReady(0, 1)
	select {
	case <-onTime.done:
		t.Fatal("closed a rig that was already on its scheduled gateway")
	default:
	}
}
