package main

import (
	"math"
	"testing"
	"time"
)

// The band's whole purpose is to tighten as evidence accumulates, so that a
// lopsided first minute is not reported as a problem while a lopsided day is.
// A band that did not shrink would be a fixed threshold wearing a statistic's
// clothing.
func TestSigmaTightensAsChunksAccumulate(t *testing.T) {
	const (
		pools = 3
		chunk = 40960.0 // one rig's work over one dwell
	)
	var prev float64
	for _, chunks := range []int{10, 100, 1000, 10000} {
		work := uint64(chunk) * uint64(chunks)
		chunkSq := chunk * chunk * float64(chunks)
		got := sigmaPct(chunkSq, work, pools)

		if got <= 0 {
			t.Fatalf("chunks=%d: sigma = %v, want positive", chunks, got)
		}
		if prev > 0 && got >= prev {
			t.Errorf("chunks=%d: sigma %.3f did not tighten from %.3f", chunks, got, prev)
		}
		// Sampling error falls as 1/sqrt(n), so a hundredfold increase in
		// ROTATIONS should shrink the band tenfold. Note what does not appear
		// anywhere in this test: the number of shares. More shares per dwell
		// buy no additional evidence about fairness, because they all land on
		// the same pool.
		if prev > 0 {
			ratio := prev / got
			if math.Abs(ratio-math.Sqrt(10)) > 0.01 {
				t.Errorf("chunks=%d: band shrank by %.3fx, want sqrt(10)", chunks, ratio)
			}
		}
		prev = got
	}
}

// This is the regression test for the calibration bug, and it is worth stating
// as a ratio because the ratio is the size of the error. Same total work, same
// rotations: counting shares as the independent unit reports a band several
// times tighter than counting dwells, and that gap is entirely fictional
// precision.
func TestShareUnitOverstatesPrecisionAgainstDwellUnit(t *testing.T) {
	const (
		pools     = 3
		rotations = 208 // 104 rotations x 2 rigs, roughly the live figure
		perDwell  = 3456.0 * 2048 / rotations
		total     = uint64(perDwell * rotations)
	)
	byDwell := sigmaPct(perDwell*perDwell*rotations, total, pools)

	// The old model: ~3456 shares at difficulty 2048.
	const shares = 3456.0
	byShare := sigmaPct(2048*2048*shares, total, pools)

	if !(byShare < byDwell) {
		t.Fatalf("share-unit band %.3f is not tighter than dwell-unit %.3f", byShare, byDwell)
	}
	// sqrt(shares/rotations) = sqrt(16.6) ~ 4.1x of invented certainty.
	if ratio := byDwell / byShare; math.Abs(ratio-math.Sqrt(shares/rotations)) > 0.05 {
		t.Errorf("band ratio %.3f, want sqrt(shares/rotations) = %.3f",
			ratio, math.Sqrt(shares/rotations))
	}
}

// Chunks are not equal in size -- a dwell that ran the full ceiling carries far
// more work than one cut short by a fast block -- and squaring is what makes
// the band reflect that. A chunk COUNT would treat both alike.
func TestSigmaUsesSquaredChunkWorkNotChunkCount(t *testing.T) {
	// Same total work, delivered as few big dwells versus many small ones.
	const total = 4096 * 1000

	few := sigmaPct(4096.0*4096.0*1000, total, 3)  // 1000 chunks of 4096
	many := sigmaPct(1024.0*1024.0*4000, total, 3) // 4000 chunks of 1024

	if !(many < few) {
		t.Fatalf("many small chunks gave sigma %.4f, few large gave %.4f; "+
			"more independent contributions must give a tighter band", many, few)
	}
	// Four times the chunks at a quarter the size: half the band.
	if ratio := few / many; math.Abs(ratio-2) > 0.01 {
		t.Errorf("band ratio %.3f, want 2", ratio)
	}
}

func TestSigmaDegenerateInputs(t *testing.T) {
	// No work yet, one pool, or an impossible variance term: report no band
	// rather than a misleading one. A fresh process must not colour anything.
	for _, c := range []struct {
		name   string
		workSq float64
		work   uint64
		pools  int
	}{
		{"no work", 0, 0, 3},
		{"single pool", 1 << 20, 4096, 1},
		{"negative variance", -1, 4096, 3},
	} {
		if got := sigmaPct(c.workSq, c.work, c.pools); got != 0 {
			t.Errorf("%s: sigma = %v, want 0", c.name, got)
		}
	}
}

// The ceiling exists to stop a quiet chain stranding a pool; a ceiling at or
// below the floor would instead make every rotation immediately eligible for
// another, which is a reconnect storm.
func TestDwellCeilingMustExceedFloor(t *testing.T) {
	base := func() config {
		return config{
			Pools: []poolConfig{{Name: "a", Host: "127.0.0.1", Port: 23336, StatusPort: 7154}, {Name: "b", Host: "127.0.0.1", Port: 23337, StatusPort: 7155}},
			Rigs:  []rigConfig{{Listen: "0.0.0.0:1"}},
		}
	}
	for _, c := range []struct {
		name     string
		min, max int
		wantErr  bool
	}{
		{"ceiling above floor", 60, 900, false},
		{"ceiling equals floor", 60, 60, true},
		{"ceiling below floor", 60, 30, true},
	} {
		cfg := base()
		cfg.MinDwellSeconds, cfg.MaxDwellSeconds = c.min, c.max
		cfg.applyDefaults()
		err := cfg.validate()
		if (err != nil) != c.wantErr {
			t.Errorf("%s: err = %v, wantErr %v", c.name, err, c.wantErr)
		}
	}
}

// The chunk accounting has to survive the boundary it exists to mark: work
// accumulated during a dwell must be squared as ONE term when that dwell
// closes, and the dwell in progress must already be counted at its current
// size so the band moves smoothly instead of stepping at each rotation.
func TestDwellChunksAreSealedWhole(t *testing.T) {
	cfg := testConfig()
	u := newUpstream(newCoordinator(cfg), 0, cfg.Rigs[0], cfg.Pools[0])

	if got := u.statsAt(time.Now()).chunkSq; got != 0 {
		t.Fatalf("fresh upstream: chunkSq = %v, want 0", got)
	}

	// A dwell in progress is visible before it is sealed.
	u.acceptedWork = 300
	if got := u.statsAt(time.Now()).chunkSq; got != 300*300 {
		t.Errorf("open dwell: chunkSq = %v, want %v", got, 300*300)
	}

	// Sealing turns it into a closed term and starts the next chunk at zero.
	u.sealDwell()
	if got := u.statsAt(time.Now()).chunkSq; got != 300*300 {
		t.Errorf("after seal: chunkSq = %v, want %v", got, 300*300)
	}

	// A second dwell of 400 contributes 400^2 -- NOT (700^2 - 300^2), and
	// emphatically not 700^2. Squaring the running total instead of the
	// per-dwell delta would make the band grow without bound.
	u.acceptedWork = 700
	u.sealDwell()
	if want := float64(300*300 + 400*400); u.statsAt(time.Now()).chunkSq != want {
		t.Errorf("two dwells: chunkSq = %v, want %v", u.statsAt(time.Now()).chunkSq, want)
	}
}
