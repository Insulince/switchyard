package main

import (
	"context"
	"fmt"
	"log"
	"math"
	"math/rand/v2"
	"strings"
	"sync"
	"time"
)

// coordinator owns the rig->pool assignment and the clock that advances it.
type coordinator struct {
	cfg config

	// ups is the full mesh, indexed [rigIdx][poolIdx]. Every one of these
	// sessions is live at all times regardless of the current assignment. The
	// element is a poolLink, so one mesh can mix SV1 and SV2 pools; each link's
	// protocol is fixed at construction (see newPoolLink).
	ups [][]poolLink

	// cur is the current rig->pool placement: cur[i] is the pool rig i is on
	// right now, and it is the single thing activePoolIdx reports. The balance
	// scheduler rewrites it on every rotation (assignLocked) to steer each pool
	// toward its target share. It replaces the old (base[i]+step)%P arithmetic,
	// which could only ever divide the rotation evenly.
	cur []int

	// delivered[rig][pool] is how many seconds of that rig's time that pool has
	// had: the quantity the targets divide and the scheduler balances.
	//
	// PER RIG, because that is what makes time stand in for hashrate. A rig that
	// spends 47% of its own time on a pool gives that pool 47% of its hashrate,
	// whatever size it is. A single tally per pool cannot do this: it counts an
	// hour of a 16 TH/s rig and an hour of a 0.5 TH/s rig as equal, so with one
	// dominant rig a pool could read on target while getting almost no hashrate.
	//
	// Time rather than measured work, because work carries share luck -- the
	// pool's variance, not the split's -- and feeding that back would have the
	// scheduler chase noise.
	delivered [][]float64

	// targets is each pool's intended fraction of delivered time, summing to 1,
	// taken once from the config. An even split is just equal targets, so there
	// is one scheduler and no special case for it.
	targets []float64

	startedAt time.Time

	// creds is one per rig, holding the identity that rig authorised with.
	// Read by every upstream for that rig; written once when the miner first
	// connects. Its own lock, because it is waited on rather than polled.
	creds []*credState

	// gw holds what each gateway says about its own link to its pool. See
	// gatewaywatch.go -- it is the only place one specific, total, silent
	// failure is visible.
	gw *gatewayWatcher

	// feed is the server's share event feed, handed to each generation as it
	// is built. Nil outside a server, and every use of it is nil-safe.
	feed *shareFeed

	// refuse stops this whole generation for good: see datumgate.go. Set by
	// the supervisor; nil outside one.
	refuse func(error)

	// gwKick asks watchGateways for an immediate read; noteBlock sends on it
	// so a new tip's height is not a whole poll interval behind the tip.
	gwKick chan struct{}

	mu        sync.Mutex
	step      int
	rotations int
	// rotationsAtReset is rotations as of the last statistics reset. A reset
	// restarts the work the fairness band is computed from without touching the
	// rotation count, so the band's age is the difference between the two.
	rotationsAtReset int
	lastPrevhash     string
	lastRotate       time.Time
	// tipHeight is the chain height of the block whose hidden prevhash is
	// tipHeightOf. Kept as a pair so a height is only ever shown against the
	// tip it was read for: see noteGatewayTip.
	tipHeight   uint64
	tipHeightOf string
	// sessions is every miner bound on each rig port. A port is one virtual
	// rig however many machines sit behind it; the slice is only so the
	// dashboard can say how many. The element is a downstreamSession so an SV1
	// (*rigSession) and an SV2 (*sv2RigSession) miner rotate and render alike.
	sessions [][]downstreamSession

	// waitingSince and everSeen are what let a missing miner be reported as
	// "not here YET" rather than "not here".
	//
	// A rig that has never connected and a rig whose miner is broken look
	// identical in a single sample -- both are simply absent -- and the
	// difference between them is entirely a matter of how long it has been.
	// Miners reconnect on their own firmware's schedule, which is tens of
	// seconds and occasionally minutes, and none of that is switchyard's to
	// hurry. What switchyard CAN do is say how long it has been waiting, so
	// the operator is watching a clock instead of guessing at a colour.
	waitingSince []time.Time
	everSeen     []bool

	// ROTATION COSTS HASHRATE, AND THE COST IS MEASURED RATHER THAN ASSUMED.
	//
	// Rotating means ending a rig's session (extranonce1 is per-session and
	// folded into the coinbase, so a share cannot be re-addressed), and the
	// miner is not hashing from the moment its socket closes until its
	// firmware has reconnected, resubscribed and taken a job. That interval
	// is pure loss, and it is entirely the miner's own schedule -- switchyard
	// cannot hurry it.
	//
	// It can time it. rotating[i] marks the rigs whose sessions THIS process
	// deliberately closed, so the gap that follows is attributable to a
	// rotation rather than to somebody power-cycling a miner. Everything else
	// -- restarts, config applies, a rig pulled off the shelf -- is excluded,
	// because folding those in would report a number that is not the cost of
	// rotating.
	// rotating[i] says the wait rig i is currently in began with a rotation
	// rather than with the miner leaving of its own accord. It is written by
	// clearSession, from the departing session's own record, at the instant
	// of the disconnect -- not guessed beforehand. A session switchyard did
	// not close carries false, so shutdowns and config applies are excluded
	// by construction rather than by anyone remembering to exclude them.
	rotating []bool
	cost     rotationCost
}

// rotationCost is what rotating has cost, measured.
//
// Grouped rather than loose on the coordinator because these counters are
// measured AGAINST startedAt: status() divides total by elapsed x rigs. A
// reset that moved the time base without clearing the numerator would divide
// hours of accumulated loss by a near-zero elapsed and report an enormous
// cost that decayed for the rest of the day -- on the one operation whose
// entire purpose is a clean baseline. As one value they reset together.
type rotationCost struct {
	n     int
	total time.Duration
	worst time.Duration
}

// maxRotationGap bounds what counts as a rotation reconnect.
//
// A miner that comes back in three seconds paid the rotation's price. One that
// comes back in four minutes was off for a reason of its own that happened to
// begin at a rotation, and averaging that in would triple a figure operators
// use to judge whether this tool is worth running. Gaps beyond this are
// dropped from the average rather than counted, and the rig still reports its
// wait through waitingSince like any other absent rig.
const maxRotationGap = 60 * time.Second

func newCoordinator(cfg config) *coordinator {
	co := &coordinator{
		cfg:       cfg,
		startedAt: time.Now(),
		sessions:  make([][]downstreamSession, len(cfg.Rigs)),
		// The clock starts at construction: a fresh boot and a config reload
		// are the same event to a miner, which finds its connection gone and
		// backs off before trying again.
		waitingSince: filledNow(len(cfg.Rigs)),
		everSeen:     make([]bool, len(cfg.Rigs)),
		rotating:     make([]bool, len(cfg.Rigs)),
		targets:      cfg.targets(),
		delivered:    make([][]float64, len(cfg.Rigs)),
		cur:          make([]int, len(cfg.Rigs)),
	}
	for i := range co.delivered {
		co.delivered[i] = make([]float64, len(cfg.Pools))
	}
	// Opening placement. delivered is all zero, so every deficit is zero and
	// this spreads the rigs across pools -- balanced, and random on the ties --
	// just as the old randomised start did, with no arrangement a restart could
	// systematically favour.
	co.assignLocked()
	co.gw = newGatewayWatcher()
	co.gwKick = make(chan struct{}, 1)
	co.creds = make([]*credState, len(cfg.Rigs))
	for i := range co.creds {
		co.creds[i] = newCredState()
	}
	co.ups = make([][]poolLink, len(cfg.Rigs))
	for i, rig := range cfg.Rigs {
		co.ups[i] = make([]poolLink, len(cfg.Pools))
		for j, pool := range cfg.Pools {
			co.ups[i][j] = newPoolLink(co, i, j, rig, pool)
		}
	}
	return co
}

func (co *coordinator) start(ctx context.Context) {
	co.mu.Lock()
	table := co.assignmentTableLocked(nil)
	co.mu.Unlock()
	log.Printf("initial placement%s", table)

	for i := range co.ups {
		for j := range co.ups[i] {
			go co.ups[i][j].run(ctx)
		}
	}
}

// activePoolIdx is where rig i is placed right now. It simply reports the
// current assignment; all the policy lives in assignLocked, which rewrites that
// assignment at startup and on every rotation.
//
// Caller must hold co.mu: cur is written under the lock in rotate, and every
// reader here already holds it.
func (co *coordinator) activePoolIdx(rigIdx int) int {
	return co.cur[rigIdx]
}

// spreadDwells is how strongly a rig prefers a pool with no rig on it this round,
// in average dwells of deficit. It is a tiebreak, not a goal, because hitting the
// split comes first: a rig only takes the emptier pool when the two are close.
//
// Measured across fleets and splits. At 0.25 the split is as accurate as with no
// tiebreak at all, and on a fleet of one 16.8 TH/s rig and five small ones a pool
// with a target sits empty 4% of the time instead of 42%. From 1 upward it starts
// costing accuracy, and at 4 a day's miss is more than three times as large.
const spreadDwells = 0.25

// assignLocked recomputes the rig->pool placement to steer each rig's time toward
// the target split. It is the whole scheduling policy, and it runs once at startup
// and once per rotation. Caller holds co.mu.
//
// The rule is the "balance" scheduler, applied to each rig on its own. A pool is
// BEHIND on a rig by how much its target share of that rig's time so far exceeds
// what it has actually had:
//
//	behind[rig][p] = target[p] * sum(delivered[rig]) - delivered[rig][p]
//
// and the rig goes to the pool furthest behind, less a small preference for pools
// no other rig has been sent to this round (see spreadDwells). Rigs can share a
// pool while others sit empty when their deficits say so; that is accepted, because
// each rig holding the split on its own is what makes the hashrate hold it too.
//
// One large rig cannot be divided, so it moves as a lump and the shares swing until
// enough blocks have gone by to smooth it out. That is the nature of the fleet and
// not something a scheduler can remove.
//
// Unlike the old (base[i]+step)%P scheme this gives soft, statistical evenness
// rather than a hard per-cycle guarantee -- the price of handling uneven splits
// at all, and of one scheduler instead of two.
func (co *coordinator) assignLocked() {
	nP, nR := len(co.cfg.Pools), len(co.cfg.Rigs)
	if nP == 0 || nR == 0 {
		return
	}
	// A pool set to 0% is not a candidate at all, rather than one that scores
	// badly. Scoring cannot express "never": with nothing delivered every deficit
	// is zero, so it ties with the real pools at startup, and the spreading
	// preference can make it the best score whenever rigs outnumber the pools that
	// want them. validate guarantees shares total 100, so this is never empty on
	// a config that reached here; the guard is what keeps that from being a panic
	// if that ever stops being true.
	eligible := make([]int, 0, nP)
	for p := range co.targets {
		if co.targets[p] > 0 {
			eligible = append(eligible, p)
		}
	}
	if len(eligible) == 0 {
		return
	}
	penalty := spreadDwells * co.avgDwellLocked()
	sent := make([]int, nP)
	cands := make([]int, 0, nP)
	// Randomised rig order so no rig always gets first pick of the empty pools.
	for _, i := range rand.Perm(nR) {
		rigTotal := 0.0
		for _, d := range co.delivered[i] {
			rigTotal += d
		}
		score := func(p int) float64 {
			return co.targets[p]*rigTotal - co.delivered[i][p] - penalty*float64(sent[p])
		}
		best := math.Inf(-1)
		for _, p := range eligible {
			if s := score(p); s > best {
				best = s
			}
		}
		// Every pool within rounding of the best score is a true tie; pick among
		// them at random so the opening placement, where every deficit is zero,
		// carries no fixed bias -- exactly what the old randomised start did.
		cands = cands[:0]
		for _, p := range eligible {
			if s := score(p); s >= best-1e-9 {
				cands = append(cands, p)
			}
		}
		p := cands[rand.IntN(len(cands))]
		co.cur[i] = p
		sent[p]++
	}
}

// avgDwellLocked is the mean time between rotations, which sizes spreadDwells to
// the chain's own block rate: a rig's total delivered time divided by the rotations
// that produced it. Every rig is credited every dwell, so any rig will do. Before
// anything has been delivered it falls back to the dwell floor, a stand-in for one
// dwell's length. Caller holds co.mu.
func (co *coordinator) avgDwellLocked() float64 {
	if co.rotations <= 0 || len(co.delivered) == 0 {
		return float64(co.cfg.MinDwellSeconds)
	}
	total := 0.0
	for _, d := range co.delivered[0] {
		total += d
	}
	if total <= 0 {
		return float64(co.cfg.MinDwellSeconds)
	}
	return total / float64(co.rotations)
}

// settleDeliveredLocked credits the dwell that just ended to the pool each rig
// spent it on, so the next assignment can see who is now behind. Caller holds
// co.mu.
//
// Every assigned rig is credited the full dwell, whether or not a miner was
// actually on it. The targets describe where work is INTENDED to go; a rig that
// is physically absent is a presence problem the operator sees elsewhere, not a
// reason to quietly reweight the split toward the pools the working rigs happen
// to sit on.
func (co *coordinator) settleDeliveredLocked(now time.Time) {
	if co.lastRotate.IsZero() {
		return
	}
	dwell := now.Sub(co.lastRotate).Seconds()
	if dwell <= 0 {
		return
	}
	for i := range co.cur {
		co.delivered[i][co.cur[i]] += dwell
	}
}

// upstreamForRig returns the gateway a newly-connecting rig should bind to.
//
// It prefers the scheduled pool, but falls back to any ready gateway rather
// than refusing the connection. A rig earning on the "wrong" pool for one
// slot is strictly better than a rig sitting idle because one gateway
// happens to be down -- and gateways do go down, as maveth's version
// rejection demonstrated.
//
// The one exception is a pool set to 0%: the operator asked for that pool to get
// nothing, and an outage elsewhere does not change the answer. So if only 0%
// gateways are up, the rig gets no gateway, its connection drops and the miner
// retries until a pool it is allowed on comes back.
func (co *coordinator) upstreamForRig(rigIdx int) (poolLink, bool) {
	co.mu.Lock()
	want := co.activePoolIdx(rigIdx)
	co.mu.Unlock()

	if u := co.ups[rigIdx][want]; u.isReady() {
		return u, true
	}
	for j := range co.ups[rigIdx] {
		if co.targets[j] <= 0 {
			continue
		}
		if u := co.ups[rigIdx][j]; u.isReady() {
			log.Printf("[%s] scheduled pool %s unavailable; falling back to %s",
				co.rigLabel(rigIdx), co.cfg.Pools[want].displayName(), u.displayName())
			return u, true
		}
	}
	return nil, false
}

// gatewayReady is told by an upstream the moment its session becomes usable.
//
// After a restart every gateway session and every miner come up at once, and
// a miner can subscribe a moment before its SCHEDULED gateway is ready.
// upstreamForRig then binds it to whichever gateway is -- right for that
// instant and wrong from the next, because nothing else ever moves it back:
// until the next block it shares a pool with another rig, and its own pool
// gets nothing. So when a rig's scheduled gateway comes up, any of its miners
// on a fallback are sent over. One reconnect for that rig alone, instead of a
// doubled pool for up to a block. A gateway recovering mid-run is the same
// case.
//
// Marked rotated, like a rotation's victims: switchyard caused this
// reconnect, so its gap is a cost of scheduling, not a miner fault.
func (co *coordinator) gatewayReady(rigIdx, poolIdx int) {
	co.mu.Lock()
	if co.activePoolIdx(rigIdx) != poolIdx {
		co.mu.Unlock()
		return
	}
	want := co.ups[rigIdx][poolIdx]
	var strays []downstreamSession
	for _, s := range co.sessions[rigIdx] {
		if s.boundLink() != nil && s.boundLink() != want {
			s.markRotated()
			strays = append(strays, s)
		}
	}
	co.mu.Unlock()

	if len(strays) == 0 {
		return
	}
	log.Printf("[%s] scheduled gateway %s is ready; moving off its fallback",
		co.rigLabel(rigIdx), co.cfg.Pools[poolIdx].displayName())
	// Outside the lock, as in rotate: each session calls back into
	// clearSession as it unwinds.
	for _, s := range strays {
		s.close()
	}
}

// noteBlock is called for every mining.notify seen on every upstream. All
// gateways follow the same chain, so they report the same prevhash; the
// first one to report a new value wins and the rest are no-ops.
func (co *coordinator) noteBlock(prevhash string) {
	co.mu.Lock()
	if prevhash == "" || prevhash == co.lastPrevhash {
		co.mu.Unlock()
		return
	}
	first := co.lastPrevhash == ""
	co.lastPrevhash = prevhash
	// Ask for the new tip's height now. Non-blocking: one pending read
	// covers any number of blocks, and a coordinator with no poller running
	// (tests, a nil channel) simply skips it.
	select {
	case co.gwKick <- struct{}{}:
	default:
	}
	if first {
		// The first job we ever see is not a block arriving, it is us
		// arriving. Rotating on it would throw away a fresh assignment.
		co.lastRotate = time.Now()
		co.mu.Unlock()
		log.Printf("tracking chain at prevhash %s", prevhash)
		return
	}
	if time.Since(co.lastRotate) < co.cfg.minDwell() {
		co.mu.Unlock()
		return
	}
	co.mu.Unlock()
	co.rotate("new block " + shortHash(prevhash))
}

// noteGatewayTip records a chain height read from a gateway's status page,
// keyed by the hidden prevhash of the block it belongs to.
//
// Nothing in the work itself says how tall the chain is. A BLAKE2b job's
// coinbase is a bare 32-byte commitment with no BIP34 height in it, and the
// prevhash is a hash of a hash -- so the height can only come from the
// gateway's page, which is read on its own schedule and can be a block behind
// (or, briefly, a block ahead of) the jobs. Pairing each height with the tip
// it was read for, and accepting it only for the tip switchyard is actually
// on, means the dashboard can show "height unknown" for a moment but never a
// height that belongs to a different block.
func (co *coordinator) noteGatewayTip(hidden string, height uint64) {
	if hidden == "" {
		return
	}
	co.mu.Lock()
	if hidden == co.lastPrevhash {
		co.tipHeight, co.tipHeightOf = height, hidden
	}
	co.mu.Unlock()
}

// tipHeightFor is the recorded height if it belongs to prevhash, else 0. For
// the current tip that is the chain tip's height -- what a node's
// getblockcount says -- and zero until a gateway's page has confirmed it for
// that exact tip. Caller holds co.mu.
func (co *coordinator) tipHeightFor(prevhash string) uint64 {
	if prevhash == "" || co.tipHeightOf != prevhash {
		return 0
	}
	return co.tipHeight
}

// tipHeightKnown reports whether the current tip's height has been read.
func (co *coordinator) tipHeightKnown() bool {
	co.mu.Lock()
	defer co.mu.Unlock()
	return co.lastPrevhash != "" && co.tipHeightOf == co.lastPrevhash
}

// watchDwellCeiling forces a rotation when the chain has been quiet too long.
//
// Rotating on blocks is the right default -- it is a schedule nobody can
// predict or game -- but it inherits the chain's own variance, and block
// intervals are exponential, so multi-ceiling gaps are routine rather than
// exceptional. Without this a quiet hour is an hour one pool receives nothing
// from us at all.
func (co *coordinator) watchDwellCeiling(ctx context.Context) {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			co.mu.Lock()
			idle := time.Since(co.lastRotate)
			armed := !co.lastRotate.IsZero()
			co.mu.Unlock()
			if armed && idle >= co.cfg.maxDwell() {
				co.rotate(fmt.Sprintf("no block for %s", idle.Round(time.Second)))
			}
		}
	}
}

// rotate advances the schedule one step and drops every rig session so each
// reconnects onto its new pool. Both triggers -- a block, and the dwell
// ceiling -- come through here so they cannot drift apart.
func (co *coordinator) rotate(reason string) {
	// Close the fairness chunks BEFORE the step moves. Every share accepted
	// up to this instant belongs to the placement that is about to end, and
	// that placement is the unit the fairness band treats as one independent
	// draw. Sealing after the step would smear two placements into one chunk.
	for i := range co.ups {
		for j := range co.ups[i] {
			co.ups[i][j].sealDwell()
		}
	}

	co.mu.Lock()
	now := time.Now()
	// Credit the dwell that just ended before the placement changes, so the new
	// assignment is computed against who is actually behind as of this instant.
	co.settleDeliveredLocked(now)
	co.step++
	co.rotations++
	co.lastRotate = now
	step := co.step
	victims := co.allSessionsLocked()
	// Mark the SESSIONS we are about to drop, so the gap each one leaves
	// behind can be attributed when it unwinds.
	//
	// On the session rather than on the rig index, because the two are not
	// the same thing for as long as it takes to close a socket. A rig that
	// hangs up on its own between here and the close below is no longer the
	// session in this slot, so it cannot inherit this mark -- where a
	// rig-indexed flag would have handed it a rotation's attribution for a
	// disconnect that had nothing to do with us. A rig already absent is nil
	// here and loses nothing to a rotation.
	//
	// Written under co.mu and read under co.mu in clearSession, which is what
	// makes the handoff race-free.
	for _, s := range victims {
		s.markRotated()
	}
	// Snapshot the placement we are leaving, for the "from" column, then steer
	// toward the targets. The new assignment is what every reconnecting rig
	// will bind to.
	prevCur := append([]int(nil), co.cur...)
	co.assignLocked()
	table := co.assignmentTableLocked(prevCur)
	co.mu.Unlock()

	log.Printf("%s -> rotation #%d%s", reason, step, table)

	// Closing is done outside the lock: a session's own goroutine calls back
	// into clearSession as it unwinds, and holding the lock here would make
	// it wait on us for no reason.
	for _, s := range victims {
		s.close()
	}
}

// shutdown closes every rig session this coordinator owns.
//
// Cancelling the context stops the listeners and the upstreams, but an
// ALREADY ACCEPTED miner connection is not tied to it -- it lives until the
// miner hangs up. On a reload that would leave rigs happily feeding a
// coordinator that no longer exists, hashing into upstreams whose sockets are
// closing underneath them. Dropping them makes the miners reconnect, which is
// exactly what they should do when the thing they are pointed at has just been
// reconfigured.
func (co *coordinator) shutdown() {
	co.mu.Lock()
	victims := co.allSessionsLocked()
	co.mu.Unlock()
	for _, s := range victims {
		s.close()
	}
}

// resetStats zeroes every measurement without disturbing a single connection.
// Its purpose is a clean baseline after rebalancing hardware, and a reset that
// dropped the rigs would poison the very measurement it exists to restart.
func (co *coordinator) resetStats() {
	for i := range co.ups {
		for j := range co.ups[i] {
			co.ups[i][j].resetStats()
		}
	}
	co.mu.Lock()
	co.startedAt = time.Now()
	co.rotationsAtReset = co.rotations
	// With the time base. See rotationCost.
	co.cost = rotationCost{}
	co.mu.Unlock()
	log.Printf("statistics reset; sessions and placement untouched")
}

// assignmentTableLocked renders the placement pool-first rather than rig-first.
//
// Rig-first output ("rig1->iohzrd, rig2->lazarus") makes you do the inversion
// in your head to answer the question that actually matters -- what is on each
// pool right now, and which pool is currently dark. Pool-first states it, and
// listing every pool means the idle one is visible as a line rather than as an
// absence you have to notice.
//
// prevCur is the placement this rotation moved away from, so each rig can say
// where it came from; nil on the opening placement, which came from nowhere.
func (co *coordinator) assignmentTableLocked(prevCur []int) string {
	width := 0
	for _, p := range co.cfg.Pools {
		if len(p.displayName()) > width {
			width = len(p.displayName())
		}
	}

	// Invert the current rig->pool mapping. A pool can hold several rigs once
	// rigs outnumber pools, so this collects them all rather than keeping only
	// the last one found.
	occupants := make([][]int, len(co.cfg.Pools))
	for i := range co.cfg.Rigs {
		occupants[co.cur[i]] = append(occupants[co.cur[i]], i)
	}

	var b strings.Builder
	for j, pool := range co.cfg.Pools {
		fmt.Fprintf(&b, "\n  %-*s  ", width, pool.displayName())
		here := occupants[j]
		if len(here) == 0 {
			b.WriteString("(idle)")
			continue
		}
		for k, i := range here {
			if k > 0 {
				b.WriteString(", ")
			}
			b.WriteString(co.rigLabel(i))
			if prevCur != nil {
				fmt.Fprintf(&b, " (from %s)", co.cfg.Pools[prevCur[i]].displayName())
			}
		}
	}
	return b.String()
}

// filledNow stamps every entry with the current time.
func filledNow(n int) []time.Time {
	out := make([]time.Time, n)
	now := time.Now()
	for i := range out {
		out[i] = now
	}
	return out
}

func (co *coordinator) setSession(rigIdx int, s downstreamSession) {
	co.mu.Lock()
	// Before the clock is cleared below: the gap between the close and now is
	// what the rotation cost.
	// Only the first miner back ends the wait; a second one joining a live
	// port is not a reconnect.
	if len(co.sessions[rigIdx]) == 0 {
		co.recordRotationGapLocked(rigIdx)
		co.waitingSince[rigIdx] = time.Time{}
	}
	co.sessions[rigIdx] = append(co.sessions[rigIdx], s)
	co.everSeen[rigIdx] = true
	co.mu.Unlock()
}

// recordRotationGapLocked times a rig's return, if switchyard is what sent it
// away. Caller holds co.mu.
func (co *coordinator) recordRotationGapLocked(rigIdx int) {
	if !co.rotating[rigIdx] {
		return
	}
	co.rotating[rigIdx] = false
	t := co.waitingSince[rigIdx]
	if t.IsZero() {
		return
	}
	gap := time.Since(t)
	if gap > maxRotationGap {
		return
	}
	co.cost.n++
	co.cost.total += gap
	if gap > co.cost.worst {
		co.cost.worst = gap
	}
}

// otherMiners counts the sessions on a port besides s that are still alive.
// A session already closing has not yet unwound to clearSession, and must
// not count as company.
// allSessionsLocked flattens every port's miners into one list. Caller
// holds co.mu.
func (co *coordinator) allSessionsLocked() []downstreamSession {
	var out []downstreamSession
	for _, ss := range co.sessions {
		out = append(out, ss...)
	}
	return out
}

func (co *coordinator) otherMiners(rigIdx int, s downstreamSession) int {
	co.mu.Lock()
	defer co.mu.Unlock()
	n := 0
	for _, x := range co.sessions[rigIdx] {
		// doneChan is nil only on a bare literal; every accepted session has
		// one. Guarded so a test can register placeholders without a socket.
		if x == s || x.doneChan() == nil {
			continue
		}
		select {
		case <-x.doneChan():
		default:
			n++
		}
	}
	return n
}

func (co *coordinator) clearSession(rigIdx int, s downstreamSession) {
	co.mu.Lock()
	ss := co.sessions[rigIdx]
	for i, x := range ss {
		if x != s {
			continue
		}
		ss = append(ss[:i], ss[i+1:]...)
		co.sessions[rigIdx] = ss
		if len(ss) == 0 {
			// One stamp: when the wait began, and what began it. Recording
			// the cause anywhere other than the moment of the disconnect
			// means recording it about a different moment.
			co.waitingSince[rigIdx] = time.Now()
			co.rotating[rigIdx] = s.rotatedByUs()
		}
		break
	}
	co.mu.Unlock()
}

type gatewayStatus struct {
	Pool string `json:"pool"`

	// AuthorisedAs is the stratum username switchyard sent upstream on this
	// session, verbatim.
	//
	// It is here for one reason: switchyard REPLACES the username a miner
	// offers, and a substitution nobody can see is indistinguishable from a
	// substitution nobody agreed to. Publishing both sides of it -- this, and
	// the miner's own ClaimedUser below -- is what makes the swap auditable
	// from outside the process.
	AuthorisedAs string `json:"authorisedAs"`

	Ready      bool      `json:"ready"`
	Active     bool      `json:"active"`
	Difficulty uint64    `json:"difficulty"`
	Submitted  uint64    `json:"submitted"`
	Accepted   uint64    `json:"accepted"`
	Rejected   uint64    `json:"rejected"`
	Work       uint64    `json:"work"`
	Ths        float64   `json:"ths"`
	NowThs     float64   `json:"nowThs"`
	LastShare  time.Time `json:"lastShare"`
}

type rigStatus struct {
	Name string `json:"name"`

	// ClaimedUser is the username the MINER asked to authorise as, exactly as
	// it arrived on the wire. AuthorisedAs is what switchyard then presented
	// to the gateways.
	//
	// They are the same value unless config.json carries an explicit override,
	// and that is the point of publishing both: switchyard forwards your
	// identity rather than inventing one, and this is where you check it
	// without reading any code.
	ClaimedUser string `json:"claimedUser,omitempty"`
	// Miners is every worker name currently bound on this port, in bind
	// order. One entry is the ordinary case; the port is a virtual rig and
	// this is what is behind it.
	Miners       []string `json:"miners"`
	AuthorisedAs string   `json:"authorisedAs,omitempty"`

	Port       int    `json:"port"`
	ActivePool string `json:"activePool"`
	Connected  bool   `json:"connected"`

	// Protocol is how the miner on this port speaks to switchyard, "sv1" or
	// "sv2". The dashboard badges sv2 and leaves sv1 unmarked, since sv1 is the
	// norm -- the same "identity, shown only when it applies" treatment as Solo.
	Protocol string `json:"protocol,omitempty"`

	// WaitingSeconds is how long this rig has had no miner on it, and
	// EverSeen whether one has ever arrived. Together they separate "give it a
	// moment" from "something is actually wrong" -- a distinction the operator
	// otherwise has to make by staring at an unchanging red line and guessing.
	WaitingSeconds int  `json:"waitingSeconds"`
	EverSeen       bool `json:"everSeen"`

	BoundTo  string          `json:"boundTo"`
	Ths      float64         `json:"ths"`
	NowThs   float64         `json:"nowThs"`
	Gateways []gatewayStatus `json:"gateways"`
}

// poolStatus is the same information inverted, and the inversion is the whole
// point. Per-rig figures answer "is this rig working"; they cannot answer "is
// this pool still seeing us", because a pool is fed by whichever rig happens
// to be on it. A rig's last share to lazarus being twenty minutes old is
// meaningless if the OTHER rig was on lazarus five minutes ago.
type poolStatus struct {
	Name string `json:"name"`

	// Gateway, Addr and Host describe the two hops this entry really is. Addr
	// and Gateway are measured facts -- that socket is open or it is not, and
	// everything else in this struct is a property of it. Host names the pool
	// on the far side, which switchyard cannot see and does not pretend to;
	// it is either operator-supplied or read from the gateway's own status
	// page.
	Gateway string `json:"gateway"`
	Addr    string `json:"addr"`
	Host    string `json:"host,omitempty"`

	// Solo is the config's mark: this entry is the solo slot, and the
	// dashboard draws it as "Solo -> network" rather than as a pool.
	Solo bool `json:"solo,omitempty"`

	// Protocol is how switchyard speaks to this gateway, "sv1" or "sv2". Badged
	// on the dashboard for sv2 only (sv1 is the norm, left unmarked).
	Protocol string `json:"protocol,omitempty"`

	// Health is the gateway's own report of how the pool behind it is treating
	// the work. Absent when no status page is configured.
	Health *gatewayHealth `json:"health,omitempty"`

	Ready      bool      `json:"ready"`
	Occupants  []string  `json:"occupants"`
	Difficulty uint64    `json:"difficulty"`
	Accepted   uint64    `json:"accepted"`
	Rejected   uint64    `json:"rejected"`
	Submitted  uint64    `json:"submitted"`
	Work       uint64    `json:"work"`
	LastShare  time.Time `json:"lastShare"`

	Ths         float64 `json:"ths"`
	NowThs      float64 `json:"nowThs"`
	ExpectedThs float64 `json:"expectedThs"`
	SharePct    float64 `json:"sharePct"`
	ExpectedPct float64 `json:"expectedPct"`

	// SigmaPct is one standard deviation of this pool's share, in percentage
	// points, and Sigmas is how many of them the observed share sits from its
	// target. See sigmaPct for the model and its caveat.
	SigmaPct float64 `json:"sigmaPct"`
	Sigmas   float64 `json:"sigmas"`
}

type statusDoc struct {
	Version string `json:"version"`

	// ReloadError reports why the last rebuild-from-disk did not fully come
	// up -- almost always a rig port that something else took. Surfaced on
	// the dashboard because the operator is the only one who can fix it, and
	// the process deliberately stays alive so they have a page to fix it from.
	ReloadError string `json:"reloadError,omitempty"`

	// The DATUM gate (datumgate.go). GateWaiting names a gateway that has not
	// yet identified itself, so nothing has started; GateRefused is the
	// refusal, and nothing will start until the config changes. Filled in by
	// the server, like ReloadError.
	GateWaiting string `json:"gateWaiting,omitempty"`
	GateRefused string `json:"gateRefused,omitempty"`

	// Configured is false when there are no rigs or no pools. Not an error --
	// it is what a fresh install looks like, and it is what makes the page
	// show a setup form instead of an empty dashboard.
	Configured bool `json:"configured"`

	Step      int `json:"step"`
	Rotations int `json:"rotations"`
	// BandRotations is how many rotations the fairness band's numbers span: the
	// rotations since the last statistics reset.
	BandRotations        int       `json:"bandRotations"`
	LastPrevhash         string    `json:"lastPrevhash"`
	TipHeight            uint64    `json:"tipHeight,omitempty"` // height of LastPrevhash's block; see tipHeightFor
	LastRotate           time.Time `json:"lastRotate"`
	MinDwellSeconds      int       `json:"minDwellSeconds"`
	MaxDwellSeconds      int       `json:"maxDwellSeconds"`
	DashboardPollSeconds float64   `json:"dashboardPollSeconds"`
	RateWindowSecs       int       `json:"rateWindowSecs"`
	StartedAt            time.Time `json:"startedAt"`
	Now                  time.Time `json:"now"`
	ElapsedSeconds       float64   `json:"elapsedSeconds"`
	TotalThs             float64   `json:"totalThs"`
	TotalNowThs          float64   `json:"totalNowThs"`

	// What rotating has actually cost, measured. Reconnects is how many
	// rotation-caused gaps have been timed; the mean and worst are those gaps
	// in seconds; CostPct is the share of all available rig-time lost to
	// them. Zero until the first rig has been rotated and come back.
	Reconnects            int     `json:"reconnects"`
	ReconnectMeanSeconds  float64 `json:"reconnectMeanSeconds"`
	ReconnectWorstSeconds float64 `json:"reconnectWorstSeconds"`
	RotationCostPct       float64 `json:"rotationCostPct"`

	// Banded reports whether any pool has a fairness band to draw: true from the
	// first share, unless no pool has a target strictly between 0 and 100.
	Banded bool `json:"banded"`
	// Outbound is every socket switchyard holds open to another machine. See
	// outbound.go for why a self-reported list is still worth publishing.
	Outbound []outboundConn `json:"outbound"`

	Pools []poolStatus `json:"pools"`
	Rigs  []rigStatus  `json:"rigs"`
}

// sigmaPct is one standard deviation of a pool's share of total work, in
// percentage points, for a pool whose intended share is p.
//
// The model: the rotation hands one rig's output for one dwell to one pool.
// Treat each of those DWELL CHUNKS as landing on this pool with probability p
// -- the pool's target share -- independently of the others. Its work is then a
// sum of independent terms, so Var(W_j) = p(1-p) * sum(c_k^2) and the standard
// deviation of its SHARE is sqrt(p(1-p)*sum(c^2)) / W_total. An even split is
// just p = 1/P, so this is the same band it has always been when the targets
// are equal, now drawn per pool around whatever share each one was asked for.
//
// THE UNIT IS THE WHOLE ARGUMENT. An earlier version of this summed squared
// share difficulty instead, which quietly asserted that every share was
// independently assigned. Shares are not: a rig's entire output for a dwell
// goes to one pool by construction, so thousands of shares are really only a
// couple of hundred draws. Sampling error falls as 1/sqrt(n), and getting n
// wrong by a factor of twenty makes the band four to five times too tight --
// tight enough that an even split reading 0.31 / 0.34 / 0.36 TH/s against an
// expected 0.34, which is plainly fine, was painted as a three-sigma failure.
//
// It still tightens on its own as the run goes on, which is the behaviour
// worth having: chunks accumulate, sum(c^2) grows linearly in their number
// while W_total grows linearly too, so the ratio falls as 1/sqrt(rotations).
// An hour in the band is loose and nothing can be out of range; a week in it
// is tight enough that a real imbalance shows.
//
// CAVEATS, and both point the same way -- the band is WIDER than the truth:
//
//  1. The rotation is not random. Each rig goes wherever it is furthest behind,
//     so a dwell that overshoots a pool is corrected by the next ones instead of
//     adding to the error as an independent draw would. The real miss shrinks
//     about as 1/rotations against this band's 1/sqrt(rotations), so a healthy
//     pool sits deeper inside the band the longer a run goes on.
//  2. The spreading preference steers rigs apart when their deficits are close.
//     Those chunks are negatively correlated, which the model ignores, and
//     negative correlation reduces the variance of the total further.
//
// Erring wide is the right direction for a band whose job is to stay quiet
// unless something is actually wrong. But it means sitting inside the band is
// weaker evidence of fairness than falling outside it is of unfairness.
func sigmaPct(chunkSq float64, totalWork uint64, p float64) float64 {
	// p outside (0,1) has no band: a pool asked for nothing (0) expects nothing,
	// and a pool asked for everything (1) has no other pool to vary against.
	if totalWork == 0 || p <= 0 || p >= 1 || chunkSq <= 0 {
		return 0
	}
	return math.Sqrt(p*(1-p)*chunkSq) / float64(totalWork) * 100
}

func (co *coordinator) status() statusDoc {
	co.mu.Lock()
	now := time.Now()
	elapsed := now.Sub(co.startedAt)

	// What rotating has cost so far.
	//
	// The denominator is rig-time, not wall-time: with two rigs, two seconds
	// lost by each is four rig-seconds gone out of every two seconds the
	// process has been up per rig. Expressing it that way makes the figure
	// directly comparable to the hashrate it describes -- a 1% cost means 1%
	// less hashrate reaching pools than the hardware produced.
	var reconnectMean float64
	if co.cost.n > 0 {
		reconnectMean = co.cost.total.Seconds() / float64(co.cost.n)
	}
	// No guard on n: with nothing measured total is zero, and zero over any
	// elapsed is the zero this should report.
	var rotationCostPct float64
	if rigSeconds := elapsed.Seconds() * float64(len(co.cfg.Rigs)); rigSeconds > 0 {
		rotationCostPct = co.cost.total.Seconds() / rigSeconds * 100
	}

	doc := statusDoc{
		// EMPTY, NEVER NIL.
		//
		// A nil slice marshals to JSON null, and null is a second kind of
		// empty that every consumer then has to remember to handle. One that
		// forgot -- "rigs.filter(...)" on a config with pools but no rigs --
		// threw before the page could decide what to render, so a perfectly
		// legible half-finished setup came up as a blank skeleton with no
		// error anywhere. Emitting [] costs nothing and removes the case.
		Rigs:                  []rigStatus{},
		Pools:                 []poolStatus{},
		Version:               versionString(),
		Configured:            co.cfg.configured(),
		Step:                  co.step,
		Rotations:             co.rotations,
		BandRotations:         co.rotations - co.rotationsAtReset,
		LastPrevhash:          co.lastPrevhash,
		TipHeight:             co.tipHeightFor(co.lastPrevhash),
		LastRotate:            co.lastRotate,
		MinDwellSeconds:       co.cfg.MinDwellSeconds,
		MaxDwellSeconds:       co.cfg.MaxDwellSeconds,
		DashboardPollSeconds:  co.cfg.DashboardPollSeconds,
		RateWindowSecs:        int(rateWindow / time.Second),
		StartedAt:             co.startedAt,
		Now:                   now,
		ElapsedSeconds:        elapsed.Seconds(),
		Reconnects:            co.cost.n,
		ReconnectMeanSeconds:  reconnectMean,
		ReconnectWorstSeconds: co.cost.worst.Seconds(),
		RotationCostPct:       rotationCostPct,
	}
	active := make([]int, len(co.cfg.Rigs))
	sessions := make([][]downstreamSession, len(co.sessions))
	for i, ss := range co.sessions {
		sessions[i] = append([]downstreamSession(nil), ss...)
	}
	// Copied under the same lock as the sessions they describe, so a rig
	// cannot appear absent here and connected two lines later.
	waitingSince := make([]time.Time, len(co.waitingSince))
	copy(waitingSince, co.waitingSince)
	everSeen := make([]bool, len(co.everSeen))
	copy(everSeen, co.everSeen)
	for i := range co.cfg.Rigs {
		active[i] = co.activePoolIdx(i)
	}
	co.mu.Unlock()

	// RESOLVE DISPLAY NAMES FIRST, before anything else refers to a pool.
	// One name per pool, computed once, used everywhere: BoundTo, Occupants
	// and the per-gateway rows all key on it, and two sources of truth once
	// left the dashboard unable to join a rig to the pool it was on.
	//
	// The name is the operator's label and nothing else. The setup form
	// fills it in from the gateway's pool tag, so it usually IS the tag --
	// but a live override from the status page was tried and removed: in
	// non-pooled mode DATUM prints the local coinbase tag in the same field,
	// and for nine hours a pool was renamed to its operator.
	poolName := make([]string, len(co.cfg.Pools))
	for j, pool := range co.cfg.Pools {
		poolName[j] = pool.displayName()
	}

	pools := make([]poolStatus, len(co.cfg.Pools))
	for j, pool := range co.cfg.Pools {
		pools[j] = poolStatus{
			Name:      poolName[j],
			Gateway:   pool.gatewayName(),
			Addr:      pool.stratumAddr(),
			Host:      pool.Host,
			Solo:      pool.Solo,
			Protocol:  pool.proto(),
			Occupants: []string{},
		}
	}

	var totalWork uint64
	var totalChunkSq float64
	for i, rig := range co.cfg.Rigs {
		rs := rigStatus{
			Name:       co.rigLabel(i),
			Port:       rig.Port,
			ActivePool: poolName[active[i]],
			Connected:  len(sessions[i]) > 0,
			EverSeen:   everSeen[i],
			Protocol:   rig.proto(),
			Miners:     []string{},
		}
		for _, s := range sessions[i] {
			rs.Miners = append(rs.Miners, s.label())
		}
		if len(sessions[i]) == 0 && !waitingSince[i].IsZero() {
			rs.WaitingSeconds = int(time.Since(waitingSince[i]).Seconds())
		}
		if user, _, known, _ := co.creds[i].get(); known {
			rs.AuthorisedAs = user
		}
		// boundIdx rather than a name comparison. The upstream is a pointer we
		// already hold, so the index is exact -- and it cannot be knocked out
		// of alignment by a pool being renamed underneath it.
		boundIdx := -1
		if len(sessions[i]) > 0 {
			first := sessions[i][0]
			rs.ClaimedUser = first.label()
			if bl := first.boundLink(); bl != nil {
				for j := range co.ups[i] {
					if co.ups[i][j] == bl {
						boundIdx = j
						rs.BoundTo = poolName[j]
						break
					}
				}
			}
		}
		var rigWork uint64
		for j := range co.cfg.Pools {
			st := co.ups[i][j].statsAt(now)
			rigWork += st.work
			totalChunkSq += st.chunkSq
			rs.NowThs += st.nowThs
			rs.Gateways = append(rs.Gateways, gatewayStatus{
				Pool:         poolName[j],
				AuthorisedAs: rs.AuthorisedAs,
				Ready:        st.ready,
				Active:       j == active[i],
				Difficulty:   st.diff,
				Submitted:    st.submitted,
				Accepted:     st.accepted,
				Rejected:     st.rejected,
				Work:         st.work,
				Ths:          thsFromWork(st.work, elapsed),
				NowThs:       st.nowThs,
				LastShare:    st.lastShare,
			})
			if st.ready {
				pools[j].Ready = true
				pools[j].Difficulty = st.diff
			}
			pools[j].Accepted += st.accepted
			pools[j].Rejected += st.rejected
			pools[j].Submitted += st.submitted
			pools[j].Work += st.work
			pools[j].NowThs += st.nowThs
			// The pool's last share is the most recent from ANY rig. That is
			// the number that answers whether the pool still sees us.
			if st.lastShare.After(pools[j].LastShare) {
				pools[j].LastShare = st.lastShare
			}
			// Occupancy follows the BINDING, not the schedule. When a gateway
			// is down a rig falls back elsewhere, and a view that showed the
			// schedule would quietly lie about where the work is going.
			if j == boundIdx {
				pools[j].Occupants = append(pools[j].Occupants, rs.Name)
			}
		}
		rs.Ths = thsFromWork(rigWork, elapsed)
		totalWork += rigWork
		doc.Rigs = append(doc.Rigs, rs)
		doc.TotalNowThs += rs.NowThs
	}

	doc.TotalThs = thsFromWork(totalWork, elapsed)

	// The band applies from the first share, with no warm-up. The balance
	// scheduler has no cycle to wait for, and few dwells already make the band
	// wide: sum(c^2)/W^2 is largest when one chunk is all of the work. With
	// ordinary splits that keeps early readings out of the red on its own. A very
	// small target can still read red for hours, because one whole dwell is a
	// large overshoot of it, but a warm-up short enough to be worth having would
	// not have outlasted that anyway.
	//
	// A pool whose target is 0 or 100 has no spread to measure and gets no sigma.
	for j := range pools {
		tgt := co.targets[j]
		pools[j].Ths = thsFromWork(pools[j].Work, elapsed)
		// Expectation follows the TARGET, not an even 1/P: a pool asked for 20%
		// is doing fine at 20% and starved at 5%, and the band has to be drawn
		// around the number the operator actually chose.
		pools[j].ExpectedThs = doc.TotalThs * tgt
		pools[j].ExpectedPct = tgt * 100
		sigma := sigmaPct(totalChunkSq, totalWork, tgt)
		if sigma > 0 {
			doc.Banded = true
		}
		pools[j].SigmaPct = sigma
		if totalWork > 0 {
			pools[j].SharePct = float64(pools[j].Work) / float64(totalWork) * 100
			if sigma > 0 {
				pools[j].Sigmas = (pools[j].SharePct - pools[j].ExpectedPct) / sigma
			}
		}
	}
	for j, pool := range co.cfg.Pools {
		if h, ok := co.gw.get(pool.displayName()); ok {
			hh := h
			pools[j].Health = &hh
			// A live reading beats a config label, and means the config does
			// not have to carry one at all.
			// Not for the solo entry: its page says "N/A", and that is not a
			// host.
			if hh.PoolHost != "" && !pool.Solo {
				pools[j].Host = hh.PoolHost
			}
		}
	}
	doc.Pools = pools
	doc.Outbound = co.outbound()
	return doc
}

func shortHash(h string) string {
	if len(h) <= 16 {
		return h
	}
	return h[:8] + ".." + h[len(h)-8:]
}
