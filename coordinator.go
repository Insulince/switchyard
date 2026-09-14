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
	// sessions is live at all times regardless of the current assignment.
	ups [][]*upstream

	// base is each rig's fixed starting pool offset, randomised at startup.
	base []int

	startedAt time.Time

	// creds is one per rig, holding the identity that rig authorised with.
	// Read by every upstream for that rig; written once when the miner first
	// connects. Its own lock, because it is waited on rather than polled.
	creds []*credState

	// gw holds what each gateway says about its own link to its pool. See
	// gatewaywatch.go -- it is the only place one specific, total, silent
	// failure is visible.
	gw *gatewayWatcher

	mu           sync.Mutex
	step         int
	rotations    int
	lastPrevhash string
	lastRotate   time.Time
	// sessions is every miner bound on each rig port. A port is one virtual
	// rig however many machines sit behind it; the slice is only so the
	// dashboard can say how many.
	sessions [][]*rigSession

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
		sessions:  make([][]*rigSession, len(cfg.Rigs)),
		// The clock starts at construction: a fresh boot and a config reload
		// are the same event to a miner, which finds its connection gone and
		// backs off before trying again.
		waitingSince: filledNow(len(cfg.Rigs)),
		everSeen:     make([]bool, len(cfg.Rigs)),
		rotating:     make([]bool, len(cfg.Rigs)),
		base:         randomBalancedStart(len(cfg.Rigs), len(cfg.Pools)),
	}
	co.gw = newGatewayWatcher()
	co.creds = make([]*credState, len(cfg.Rigs))
	for i := range co.creds {
		co.creds[i] = newCredState()
	}
	co.ups = make([][]*upstream, len(cfg.Rigs))
	for i, rig := range cfg.Rigs {
		co.ups[i] = make([]*upstream, len(cfg.Pools))
		for j, pool := range cfg.Pools {
			co.ups[i][j] = newUpstream(co, i, rig, pool)
		}
	}
	return co
}

func (co *coordinator) start(ctx context.Context) {
	co.mu.Lock()
	table := co.assignmentTableLocked(co.step, false)
	co.mu.Unlock()
	log.Printf("initial placement%s", table)

	for i := range co.ups {
		for j := range co.ups[i] {
			go co.ups[i][j].run(ctx)
		}
	}
}

// activePoolIdx is the whole scheduling policy: rig i at step t is on pool
// (base[i] + t) mod P.
//
// Each rig keeps a fixed offset, so two rigs with different offsets can never
// collide -- their separation is constant. With R rigs and P pools exactly
// P-R pools are dark at any moment, the arithmetic minimum; doubling rigs onto
// one pool would leave more of them dark, never fewer.
//
// Whatever the offsets are, every rig still visits every pool exactly once per
// P steps, so each pool's average is the same regardless of the starting
// arrangement. That is what makes randomising the start safe.
func (co *coordinator) activePoolIdx(rigIdx int) int {
	return (co.base[rigIdx] + co.step) % len(co.cfg.Pools)
}

// randomBalancedStart picks a random but evenly-spread opening arrangement.
//
// The counter resets to zero on every restart, so a fixed opening arrangement
// means a fixed set of pools is favoured every time the process starts. Over a
// week of deploys that is a real, systematic bias against whichever pools sit
// late in the cycle -- the one place this scheme's evenness guarantee does not
// hold, because the guarantee is per COMPLETE cycle and a restart truncates it.
//
// Each rig goes to a uniformly random choice among the LEAST-loaded pools.
// Least-loaded rather than empty is what makes this work when rigs outnumber
// pools: there is never a point where the candidate set is empty, because when
// every pool is equally loaded, every pool qualifies.
func randomBalancedStart(nRigs, nPools int) []int {
	base := make([]int, nRigs)
	load := make([]int, nPools)
	cand := make([]int, 0, nPools)

	for i := range base {
		lo := load[0]
		for _, n := range load[1:] {
			if n < lo {
				lo = n
			}
		}
		cand = cand[:0]
		for p, n := range load {
			if n == lo {
				cand = append(cand, p)
			}
		}
		p := cand[rand.IntN(len(cand))]
		base[i] = p
		load[p]++
	}
	return base
}

// upstreamForRig returns the gateway a newly-connecting rig should bind to.
//
// It prefers the scheduled pool, but falls back to any ready gateway rather
// than refusing the connection. A rig earning on the "wrong" pool for one
// slot is strictly better than a rig sitting idle because one gateway
// happens to be down -- and gateways do go down, as maveth's version
// rejection demonstrated.
func (co *coordinator) upstreamForRig(rigIdx int) (*upstream, bool) {
	co.mu.Lock()
	want := co.activePoolIdx(rigIdx)
	co.mu.Unlock()

	if u := co.ups[rigIdx][want]; u.isReady() {
		return u, true
	}
	for j := range co.ups[rigIdx] {
		if u := co.ups[rigIdx][j]; u.isReady() {
			log.Printf("[%s] scheduled pool %s unavailable; falling back to %s",
				co.rigLabel(rigIdx), co.cfg.Pools[want].Name, u.pool.Name)
			return u, true
		}
	}
	return nil, false
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
	prevStep := co.step
	co.step++
	co.rotations++
	co.lastRotate = time.Now()
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
		s.rotated = true
	}
	table := co.assignmentTableLocked(prevStep, true)
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
// prevStep is the placement this rotation moved away from, so each rig can say
// where it came from.
func (co *coordinator) assignmentTableLocked(prevStep int, showFrom bool) string {
	width := 0
	for _, p := range co.cfg.Pools {
		if len(p.Name) > width {
			width = len(p.Name)
		}
	}

	// Invert the rig->pool mapping for the step we are rendering. A pool can
	// hold several rigs once rigs outnumber pools, so this collects them all
	// rather than keeping only the last one found.
	occupants := make([][]int, len(co.cfg.Pools))
	for i := range co.cfg.Rigs {
		p := co.activePoolIdx(i)
		occupants[p] = append(occupants[p], i)
	}

	var b strings.Builder
	for j, pool := range co.cfg.Pools {
		fmt.Fprintf(&b, "\n  %-*s  ", width, pool.Name)
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
			if showFrom {
				from := co.cfg.Pools[(co.base[i]+prevStep)%len(co.cfg.Pools)].Name
				fmt.Fprintf(&b, " (from %s)", from)
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

func (co *coordinator) setSession(rigIdx int, s *rigSession) {
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
func (co *coordinator) allSessionsLocked() []*rigSession {
	var out []*rigSession
	for _, ss := range co.sessions {
		out = append(out, ss...)
	}
	return out
}

func (co *coordinator) otherMiners(rigIdx int, s *rigSession) int {
	co.mu.Lock()
	defer co.mu.Unlock()
	n := 0
	for _, x := range co.sessions[rigIdx] {
		// done is nil only on a bare literal; every accepted session has
		// one. Guarded so a test can register placeholders without a socket.
		if x == s || x.done == nil {
			continue
		}
		select {
		case <-x.done:
		default:
			n++
		}
	}
	return n
}

func (co *coordinator) clearSession(rigIdx int, s *rigSession) {
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
			co.rotating[rigIdx] = s.rotated
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

	Listen     string `json:"listen"`
	ActivePool string `json:"activePool"`
	Connected  bool   `json:"connected"`

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
	// points, and Sigmas is how many of them the observed share sits from an
	// even split. See sigmaPct for the model and its caveat.
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

	// Configured is false when there are no rigs or no pools. Not an error --
	// it is what a fresh install looks like, and it is what makes the page
	// show a setup form instead of an empty dashboard.
	Configured bool `json:"configured"`

	Step            int       `json:"step"`
	Rotations       int       `json:"rotations"`
	LastPrevhash    string    `json:"lastPrevhash"`
	LastRotate      time.Time `json:"lastRotate"`
	MinDwellSeconds int       `json:"minDwellSeconds"`
	MaxDwellSeconds int       `json:"maxDwellSeconds"`
	PollSeconds     float64   `json:"pollSeconds"`
	RateWindowSecs  int       `json:"rateWindowSecs"`
	StartedAt       time.Time `json:"startedAt"`
	Now             time.Time `json:"now"`
	ElapsedSeconds  float64   `json:"elapsedSeconds"`
	TotalThs        float64   `json:"totalThs"`
	TotalNowThs     float64   `json:"totalNowThs"`

	// What rotating has actually cost, measured. Reconnects is how many
	// rotation-caused gaps have been timed; the mean and worst are those gaps
	// in seconds; CostPct is the share of all available rig-time lost to
	// them. Zero until the first rig has been rotated and come back.
	Reconnects            int     `json:"reconnects"`
	ReconnectMeanSeconds  float64 `json:"reconnectMeanSeconds"`
	ReconnectWorstSeconds float64 `json:"reconnectWorstSeconds"`
	RotationCostPct       float64 `json:"rotationCostPct"`

	// Banded reports whether the fairness band means anything yet. See the
	// gate in status() -- before one full cycle the model does not apply and
	// no pool should be coloured.
	Banded bool `json:"banded"`
	// Outbound is every socket switchyard holds open to another machine. See
	// outbound.go for why a self-reported list is still worth publishing.
	Outbound []outboundConn `json:"outbound"`

	Pools []poolStatus `json:"pools"`
	Rigs  []rigStatus  `json:"rigs"`
}

// sigmaPct is one standard deviation of a pool's share of total work, in
// percentage points.
//
// The model: the rotation hands one rig's output for one dwell to one pool.
// Treat each of those DWELL CHUNKS as landing independently on one of P pools
// with probability p = 1/P. A pool's work is then a sum of independent terms,
// so Var(W_j) = p(1-p) * sum(c_k^2) and the standard deviation of its SHARE is
// sqrt(p(1-p)*sum(c^2)) / W_total.
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
//  1. The rotation is not random, it is a cyclic schedule. That is stratified
//     sampling, which has strictly less variance than this independent model.
//  2. With more rigs than one, the rigs are placed on DISTINCT pools in any
//     given dwell. Those chunks are negatively correlated, which the model
//     ignores, and negative correlation reduces the variance of the total
//     further.
//
// Erring wide is the right direction for a band whose job is to stay quiet
// unless something is actually wrong. But it means sitting inside the band is
// weaker evidence of fairness than falling outside it is of unfairness.
func sigmaPct(chunkSq float64, totalWork uint64, nPools int) float64 {
	if totalWork == 0 || nPools <= 1 || chunkSq <= 0 {
		return 0
	}
	p := 1.0 / float64(nPools)
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
		LastPrevhash:          co.lastPrevhash,
		LastRotate:            co.lastRotate,
		MinDwellSeconds:       co.cfg.MinDwellSeconds,
		MaxDwellSeconds:       co.cfg.MaxDwellSeconds,
		PollSeconds:           co.cfg.PollSeconds,
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
	sessions := make([][]*rigSession, len(co.sessions))
	for i, ss := range co.sessions {
		sessions[i] = append([]*rigSession(nil), ss...)
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
			Occupants: []string{},
		}
	}

	var totalWork uint64
	var totalChunkSq float64
	for i, rig := range co.cfg.Rigs {
		rs := rigStatus{
			Name:       co.rigLabel(i),
			Listen:     rig.Listen,
			ActivePool: poolName[active[i]],
			Connected:  len(sessions[i]) > 0,
			EverSeen:   everSeen[i],
			Miners:     []string{},
		}
		for _, s := range sessions[i] {
			rs.Miners = append(rs.Miners, s.claimedUserSafe())
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
			rs.ClaimedUser = first.claimedUserSafe()
			if first.up != nil {
				for j := range co.ups[i] {
					if co.ups[i][j] == first.up {
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
	evenPct := 100.0 / float64(len(pools))
	sigma := sigmaPct(totalChunkSq, totalWork, len(pools))

	// THE BAND DOES NOT APPLY UNTIL EVERY POOL HAS HAD A TURN.
	//
	// sigmaPct models shares as landing on a random pool, but the schedule is
	// cyclic: a pool that has not come up yet has zero work with CERTAINTY,
	// not by bad luck. Feeding that certainty into a luck model produces
	// nonsense -- three minutes after start the unvisited pool sits at 0% of
	// an expected 33%, which the model dutifully reports as a three-sigma
	// scandal and paints red.
	//
	// So the band is withheld until a full cycle has completed AND every pool
	// has actually delivered work. That matches what the scheme guarantees:
	// evenness holds per complete cycle, and says nothing within one.
	everyPoolVisited := true
	for j := range pools {
		if pools[j].Work == 0 {
			everyPoolVisited = false
			break
		}
	}
	doc.Banded = doc.Rotations >= len(pools) && everyPoolVisited && sigma > 0
	if !doc.Banded {
		sigma = 0
	}
	for j := range pools {
		pools[j].Ths = thsFromWork(pools[j].Work, elapsed)
		pools[j].ExpectedThs = doc.TotalThs / float64(len(pools))
		pools[j].ExpectedPct = evenPct
		pools[j].SigmaPct = sigma
		if totalWork > 0 {
			pools[j].SharePct = float64(pools[j].Work) / float64(totalWork) * 100
			if sigma > 0 {
				pools[j].Sigmas = (pools[j].SharePct - evenPct) / sigma
			}
		}
	}
	for j, pool := range co.cfg.Pools {
		if h, ok := co.gw.get(pool.Name); ok {
			hh := h
			pools[j].Health = &hh
			// A live reading beats a config label, and means the config does
			// not have to carry one at all.
			if hh.PoolHost != "" {
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
