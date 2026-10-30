package main

import (
	"encoding/json"
	"fmt"
	"net"
	"testing"
	"time"
)

// randomBalancedStart has two jobs and it is easy to get one without the
// other: the arrangement must be BALANCED (no pool carrying two rigs while
// another carries none) and it must be RANDOM (no pool systematically
// favoured, which is the whole reason it exists -- a fixed opening order
// biases whichever pools sit late in the cycle every time the process
// restarts).
func TestRandomBalancedStartIsBalanced(t *testing.T) {
	cases := []struct{ rigs, pools int }{
		{1, 3}, {2, 3}, {3, 3}, {4, 3}, {5, 3}, {7, 3},
		{2, 2}, {1, 1}, {6, 2}, {3, 7},
	}
	for _, c := range cases {
		for trial := 0; trial < 500; trial++ {
			base := randomBalancedStart(c.rigs, c.pools)
			if len(base) != c.rigs {
				t.Fatalf("rigs=%d pools=%d: got %d offsets", c.rigs, c.pools, len(base))
			}
			load := make([]int, c.pools)
			for _, p := range base {
				if p < 0 || p >= c.pools {
					t.Fatalf("rigs=%d pools=%d: offset %d out of range", c.rigs, c.pools, p)
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
			// Perfectly spread means no pool holds two more rigs than any
			// other. With rigs <= pools this also proves no two rigs share a
			// pool, which is what keeps their cycle offsets distinct.
			if hi-lo > 1 {
				t.Fatalf("rigs=%d pools=%d: unbalanced load %v", c.rigs, c.pools, load)
			}
		}
	}
}

func TestRandomBalancedStartIsRandom(t *testing.T) {
	const (
		pools  = 3
		rigs   = 2
		trials = 6000
	)
	// Count how often each pool is left empty. With 2 rigs across 3 pools
	// exactly one pool is dark at t=0, and over many restarts each pool should
	// draw that short straw about a third of the time. A fixed opening
	// arrangement would pin it to one pool every single run.
	darkCount := make([]int, pools)
	for i := 0; i < trials; i++ {
		load := make([]int, pools)
		for _, p := range randomBalancedStart(rigs, pools) {
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

// THE CENTRAL CLAIM OF THE WHOLE PROGRAM, and it was not covered.
//
// The README states two properties of (base[i] + t) mod P as facts: two rigs
// can never collide, and every rig visits every pool exactly once per cycle.
// Everything switchyard promises about fairness rests on both. They are one
// line of arithmetic, which is exactly the kind of code that gets refactored
// by somebody who has not read the paragraph explaining why it is shaped that
// way.
func TestTwoRigsNeverShareAPool(t *testing.T) {
	for pools := 2; pools <= 7; pools++ {
		for rigs := 2; rigs <= pools; rigs++ {
			co := newCoordinator(scheduleConfig(rigs, pools))
			for step := 0; step < pools*3; step++ {
				co.step = step
				seen := map[int]int{}
				for r := 0; r < rigs; r++ {
					p := co.activePoolIdx(r)
					if prev, dup := seen[p]; dup {
						t.Fatalf("%d rigs / %d pools, step %d: rigs %d and %d both on pool %d",
							rigs, pools, step, prev, r, p)
					}
					seen[p] = r
				}
			}
		}
	}
}

// Every rig tours every pool exactly once per cycle, at ANY ratio.
//
// rig i's positions over P steps are (base[i] + t) mod P for t in 0..P-1,
// which is a complete residue system regardless of what the other rigs are
// doing -- so this holds just as firmly when rigs outnumber pools and several
// share a destination. It is what makes every pool's long-run share equal, and
// what makes randomising the opening arrangement safe.
func TestEveryRigToursEveryPoolOncePerCycle(t *testing.T) {
	for pools := 2; pools <= 7; pools++ {
		for rigs := 1; rigs <= pools*3; rigs++ {
			co := newCoordinator(scheduleConfig(rigs, pools))
			for r := 0; r < rigs; r++ {
				visits := make([]int, pools)
				for step := 0; step < pools; step++ {
					co.step = step
					visits[co.activePoolIdx(r)]++
				}
				for p, n := range visits {
					if n != 1 {
						t.Fatalf("%d rigs / %d pools: rig %d visited pool %d %d times in one cycle, want 1",
							rigs, pools, r, p, n)
					}
				}
			}
		}
	}
}

// Exactly P-R pools are dark, which the README calls the arithmetic minimum.
func TestDarkPoolCountIsTheArithmeticMinimum(t *testing.T) {
	for pools := 2; pools <= 7; pools++ {
		for rigs := 1; rigs <= pools; rigs++ {
			co := newCoordinator(scheduleConfig(rigs, pools))
			for step := 0; step < pools*2; step++ {
				co.step = step
				lit := map[int]bool{}
				for r := 0; r < rigs; r++ {
					lit[co.activePoolIdx(r)] = true
				}
				if dark := pools - len(lit); dark != pools-rigs {
					t.Fatalf("%d rigs / %d pools, step %d: %d dark, want %d",
						rigs, pools, step, dark, pools-rigs)
				}
			}
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

// zeroRng is a deterministic stand-in for the tie-breaker: it always picks the
// first candidate, so spreadOffsets' arithmetic can be asserted exactly without
// the randomness it uses in production for fairness.
func zeroRng() func(int) int { return func(int) int { return 0 } }

// THE BUG THIS FIXES COST A WHOLE RUN OF LOPSIDED WORK.
//
// Four rig ports over three pools, only two with a miner, and the opening
// arrangement wedged BOTH live rigs onto one pool -- every rotation, for the
// life of the process, because the offsets were frozen over all four phantom
// ports. The live set is what has to be spread, not the configured set.
func TestSpreadOffsetsSeparatesWedgedLiveRigs(t *testing.T) {
	base := []int{0, 1, 2, 1}                // rigs 1 and 3 share offset 1
	live := []bool{false, true, false, true} // only rigs 1 and 3 are hashing
	out, moved := spreadOffsets(base, live, 3, 3, zeroRng())
	if out[1]%3 == out[3]%3 {
		t.Fatalf("live rigs still share a pool: offsets %v", out)
	}
	if out[3] != 1 {
		t.Errorf("preferKeep rig should not move, got offsets %v", out)
	}
	if len(moved) != 1 || moved[0] != 1 {
		t.Errorf("only the incumbent that collided should move, got %v", moved)
	}
}

// A departure or arrival that does not create a collision must move nobody --
// re-spreading an already-spread fleet would spend reconnects (hashrate) for
// no gain, and spread-as-often-as-possible does not mean churn-for-its-own-sake.
func TestSpreadOffsetsLeavesSpreadRigsAlone(t *testing.T) {
	base := []int{0, 1, 2, 1}
	live := []bool{true, true, false, false} // rigs 0,1 on offsets 0,1 -- distinct
	out, moved := spreadOffsets(base, live, 3, -1, zeroRng())
	if len(moved) != 0 {
		t.Fatalf("already-spread rigs moved: %v (offsets %v)", moved, out)
	}
	if out[0] != 0 || out[1] != 1 {
		t.Errorf("offsets of settled rigs changed: %v", out)
	}
}

// When live rigs outnumber pools the guarantee weakens to balance, exactly as
// the opening arrangement's does: no pool holds two more live rigs than another.
func TestSpreadOffsetsBalancesWhenLiveExceedPools(t *testing.T) {
	base := []int{0, 0, 0, 0} // all wedged onto one pool
	live := []bool{true, true, true, true}
	out, _ := spreadOffsets(base, live, 3, -1, zeroRng())
	load := make([]int, 3)
	for i, l := range live {
		if l {
			load[out[i]%3]++
		}
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
	if hi-lo > 1 {
		t.Fatalf("live load not balanced: %v", load)
	}
}

// The end-to-end path: a second live rig connecting onto a pool another live
// rig already holds re-spreads through the real coordinator, closing the
// incumbent's session (so it reconnects onto a free pool) and attributing the
// gap to switchyard.
func TestRespreadLiveMovesACollidingRigThroughTheCoordinator(t *testing.T) {
	co := newCoordinator(scheduleConfig(4, 3))
	co.base = []int{0, 1, 2, 1} // rigs 1 and 3 scheduled onto the same pool

	s1 := liveSession(t, co, 1)
	co.setSession(1, s1) // first live rig: nothing to spread against yet
	select {
	case <-s1.done:
		t.Fatal("the first live rig was moved with no collision to fix")
	default:
	}

	s3 := liveSession(t, co, 3)
	co.setSession(3, s3) // collides with rig 1 -> respread moves the incumbent

	select {
	case <-s1.done:
	case <-time.After(time.Second):
		t.Fatal("wedged incumbent was not moved off the shared pool")
	}
	if !s1.rotated {
		t.Error("the move was not attributed to switchyard; its gap would read as a miner fault")
	}
	co.mu.Lock()
	o1, o3 := co.base[1]%3, co.base[3]%3
	co.mu.Unlock()
	if o1 == o3 {
		t.Fatalf("live rigs still share a pool after respread: %d == %d", o1, o3)
	}
}

// liveSession builds a session on an arbitrary rig port with a real pipe behind
// it, so close() has something to close. pipeSession is pinned to rig 0.
func liveSession(t *testing.T, co *coordinator, rigIdx int) *rigSession {
	t.Helper()
	a, b := net.Pipe()
	s := newRigSession(co, co.cfg.Rigs[rigIdx], rigIdx, a)
	t.Cleanup(func() { s.close(); _ = b.Close() })
	return s
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

// MORE RIGS THAN POOLS IS A SUPPORTED SHAPE, not a misconfiguration.
//
// Collision-freedom is impossible once R > P -- pigeonhole -- so the guarantee
// weakens to "as evenly as arithmetic allows": every pool carries either
// floor(R/P) or ceil(R/P) rigs at every step, and never a spread wider than
// one. Nothing is dark. The README advertises any number of rigs against any
// number of pools, so this is the half of that claim which is easy to break
// without noticing.
func TestMoreRigsThanPoolsStaysEvenlySpread(t *testing.T) {
	for pools := 2; pools <= 5; pools++ {
		for rigs := pools + 1; rigs <= pools*3; rigs++ {
			co := newCoordinator(scheduleConfig(rigs, pools))
			lo, hi := rigs/pools, (rigs+pools-1)/pools
			for step := 0; step < pools*2; step++ {
				co.step = step
				load := make([]int, pools)
				for r := 0; r < rigs; r++ {
					load[co.activePoolIdx(r)]++
				}
				for p, n := range load {
					if n < lo || n > hi {
						t.Fatalf("%d rigs / %d pools, step %d: pool %d carries %d rigs, want %d-%d",
							rigs, pools, step, p, n, lo, hi)
					}
				}
			}
		}
	}
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
	co.base[0] = 1 // scheduled on "b" at step 0

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
