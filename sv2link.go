package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"math/big"
	"strconv"
	"sync"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
)

// sv2NominalHashrate is the nominal rate switchyard advertises when it opens an
// extended channel. The gateway uses it only to seed vardiff; it converges on
// the real rate from submitted shares, so the exact figure does not matter.
const sv2NominalHashrate float32 = 1e12

// sv2Link is one rig's always-on session to one SV2 gateway: the poolLink
// sibling of *upstream. It wraps an sv2Upstream (Noise + SetupConnection +
// OpenExtendedMiningChannel + the job/share read loop) and gives it the same
// lifecycle the SV1 mesh has -- a persistent, reconnecting member whose channel
// is deferred until the rig's miner has identified itself.
//
// It serves the SV1-rig -> SV2-pool translate cell: an ordinary SV1 rigSession
// binds to it and never knows the pool is SV2. sv2Link renders the SV2 work it
// receives into an SV1 mining.notify / mining.set_difficulty (via translate.go),
// and converts the rig's SV1 mining.submit back into a SubmitSharesExtended. The
// leaf-equivalence proof (translate_test.go) is what makes that sound: the share
// the SV1 rig finds is a valid SV2 share for the same extranonce.
//
// WHY IT MUST BE PERSISTENT, like *upstream. DATUM keys its vardiff on the TCP
// connection, not the worker name (CLAUDE.md), so a socket dialled per miner and
// dropped on every rotation would reset difficulty to the floor each time. The
// socket outlives any one miner; only the rig-facing session cycles.
//
// WHY THE CHANNEL IS DEFERRED. OpenExtendedMiningChannel carries the MINER's
// user_identity, which switchyard does not know until a miner authorises. So run
// waits on the same credState as *upstream.session before it dials -- switchyard
// never invents an identity, on either protocol.
//
// SCOPE. One miner per SV2 port (the real case: one box = one translator = one
// connection). A second miner is refused rather than sub-partitioning the
// channel extranonce, which is a later enhancement. Several header
// fields (prevhash byte order, and the target->difficulty conversion below) are
// carried per the SV2 spec but can only be confirmed against a live gateway --
// the leaf-equivalence proof covers the coinbase, not the header.
type sv2Link struct {
	co      *coordinator
	rigIdx  int
	poolIdx int
	pool    poolConfig

	// authority is the gateway's pinned SV2 authority key, decoded once at
	// construction. authErr holds a decode failure so run can report it and
	// then stay down -- a link with no key can never handshake.
	authority *btcec.PublicKey
	authErr   error

	mu          sync.Mutex
	up          *sv2Upstream // the current session, nil between connections
	connectedAt time.Time    // when the channel last came up
	channelOpen bool         // the extended channel is open and work is flowing
	work        sv2Work      // latest upstream work (valid once haveJob)
	haveJob     bool

	// A port holds one downstream miner at a time, in one of two shapes, never
	// both: boundSess is an SV1 rig session that is fed pre-rendered SV1 bytes;
	// boundCanon is an SV2 rig session (sv2RigSession) that is fed canonical
	// work (sv2Work) and renders SV2 itself. lastDiff / lastNotify are the most
	// recent SV1 lines, replayed to prime a freshly bound SV1 session.
	boundSess  *rigSession
	boundCanon canonDownstream
	lastDiff   []byte
	lastNotify []byte
	curDiff    uint64 // current difficulty (rounded), what an accepted share is worth

	// Counters for the status view, cumulative since process start -- the SV2
	// mirror of the fields on *upstream, read by statsAt.
	submitted    uint64
	accepted     uint64
	rejected     uint64
	acceptedWork uint64
	lastShare    time.Time

	// dwellBase / chunkSq are the fairness-band accounting, identical in meaning
	// to *upstream's: the squared size of each closed dwell chunk.
	dwellBase uint64
	chunkSq   float64

	// buckets is the "right now" rate ring, mirroring *upstream's. Duplicated
	// rather than shared for now; a later refactor could lift both links'
	// accounting into one helper.
	buckets     [rateBuckets]uint64
	bucketAt    int
	bucketStart time.Time
	boundAt     time.Time
}

func newSv2Link(co *coordinator, rigIdx, poolIdx int, rig rigConfig, pool poolConfig) *sv2Link {
	_ = rig // a rig's own config does not shape an upstream link; kept for a uniform newPoolLink signature
	l := &sv2Link{co: co, rigIdx: rigIdx, poolIdx: poolIdx, pool: pool}
	l.authority, l.authErr = pool.authorityPub()
	return l
}

// *sv2Link is the SV2 poolLink. The assertion keeps it in step with the
// interface at build time rather than at a call site.
var _ poolLink = (*sv2Link)(nil)

func (l *sv2Link) logf(format string, args ...any) {
	log.Printf("[%s->%s] "+format, append([]any{l.co.rigLabel(l.rigIdx), l.pool.displayName()}, args...)...)
}

// run keeps one SV2 gateway session alive forever, reconnecting with backoff and
// deferring each connection until the rig's miner is known. It mirrors
// upstream.run, so the two mesh members behave identically from the
// coordinator's side.
func (l *sv2Link) run(ctx context.Context) {
	if l.authority == nil {
		// No usable authority key means no handshake is ever possible, so there
		// is nothing to retry. Fail loud once and stay down; validate() should
		// have caught this, which is why it is logged as a defect.
		l.logf("sv2 pool has no usable authority key (%v); link will not come up", l.authErr)
		return
	}
	backoff := time.Second
	for ctx.Err() == nil {
		// Nothing is dialled until the rig has said who it is -- the channel's
		// user_identity is the miner's own, exactly as SV1 waits to authorise.
		user, _, ok := l.co.creds[l.rigIdx].waitKnown(ctx)
		if !ok {
			return
		}
		healthy, err := l.session(ctx, user)
		if err != nil && ctx.Err() == nil {
			l.logf("sv2 session ended: %v (retry in %s)", err, backoff)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff < 30*time.Second {
			backoff *= 2
		}
		// A session that actually opened its channel earns a fast retry; only a
		// link that never got that far gets backed off.
		if healthy {
			backoff = time.Second
		}
	}
}

// session runs one connection to completion and reports whether it ever reached
// an open channel (so run can reset its backoff).
func (l *sv2Link) session(ctx context.Context, user string) (healthy bool, err error) {
	up := newSv2Upstream(l.pool.stratumAddr(), l.authority, user, sv2NominalHashrate)
	up.onUpdate = l.ingest

	l.mu.Lock()
	l.up = up
	l.mu.Unlock()

	defer func() {
		l.mu.Lock()
		healthy = l.channelOpen
		bound := l.boundSess
		canon := l.boundCanon
		l.up, l.boundSess, l.boundCanon = nil, nil, nil
		l.channelOpen, l.haveJob = false, false
		l.connectedAt = time.Time{}
		l.lastDiff, l.lastNotify = nil, nil
		l.mu.Unlock()
		// A rig bound to a link we just lost is holding a dead route; drop it so
		// it reconnects and rebinds to a live gateway, exactly as upstream does.
		if bound != nil {
			bound.close()
		}
		if canon != nil {
			canon.stop()
		}
	}()

	return false, up.run(ctx)
}

// ingest receives each work update from the sv2Upstream (outside its lock),
// renders it to an SV1 notify (and a set_difficulty when the difficulty moved),
// and pushes both to the bound session. The first ready update opens the channel.
func (l *sv2Link) ingest(w sv2Work) {
	// The rotation clock. An SV1 upstream feeds the coordinator every
	// mining.notify's prevhash (upstream.handleNotification); an SV2 link must do
	// the same, or a mesh whose gateways are all SV2 never learns the chain tip:
	// no block ever rotates it, and the dwell ceiling -- armed by the first
	// prevhash seen -- never arms either, so the schedule freezes at step 0
	// forever ("since last rotation: never", "chain tip: waiting for a job").
	//
	// The string MUST be the one an SV1 gateway would send for the same block, or
	// a mixed SV1/SV2 mesh would see every block as two different prevhashes and
	// rotate on the alternation. It is: it is exactly params[1] of the
	// mining.notify this link renders for its SV1 rigs (jobToSV1NotifyParams),
	// which those rigs mine valid shares from. An all-zero prevhash is "no
	// SetNewPrevHash yet", not a block, and must not seed the clock.
	//
	// Called before taking l.mu, like the SV1 path: a rotation closes rig
	// sessions, which call back into their links.
	if l.co != nil && w.PrevHash != ([32]byte{}) {
		l.co.noteBlock(hex.EncodeToString(w.PrevHash[:]))
	}

	job := sv2WorkToJob(w)
	notifyParams, err := jobToSV1NotifyParams(sv2JobIDString(w.JobID), job)
	if err != nil {
		l.logf("rendering notify from sv2 work failed: %v", err)
		return
	}
	notify := []byte(fmt.Sprintf(`{"id":null,"method":"mining.notify","params":%s}`, notifyParams))

	d := targetToDifficulty(w.Target)
	dr := uint64(math.Round(d))
	if dr == 0 {
		dr = 1
	}
	var diffLine []byte
	if d > 0 {
		diffLine = []byte(fmt.Sprintf(`{"id":null,"method":"mining.set_difficulty","params":[%s]}`,
			strconv.FormatFloat(d, 'f', -1, 64)))
	}

	l.mu.Lock()
	justOpened := w.Ready && !l.channelOpen
	if justOpened {
		l.channelOpen = true
		l.connectedAt = time.Now()
	}
	l.work, l.haveJob = w, w.Ready
	diffChanged := l.curDiff != dr
	l.curDiff = dr
	if diffLine != nil {
		l.lastDiff = diffLine
	}
	l.lastNotify = notify
	sess := l.boundSess
	canon := l.boundCanon
	l.mu.Unlock()

	if justOpened {
		l.logf("extended channel open (extranonce_prefix=%x, difficulty=%s)", w.ExtranoncePrefix,
			strconv.FormatFloat(d, 'f', -1, 64))
		// A rig that bound to a fallback while this link was coming up belongs
		// here now; same hand-off as upstream.session.
		if l.co != nil {
			l.co.gatewayReady(l.rigIdx, l.poolIdx)
		}
	}
	// An SV2 downstream renders the work itself, so it gets the canonical snapshot
	// untouched; an SV1 downstream is handed the bytes already rendered for it.
	if canon != nil {
		canon.pushWork(w)
	} else if sess != nil {
		// Difficulty first, and only on a change, exactly as the SV1 path: a rig
		// that receives a job before its difficulty hashes at the default of 1.
		if diffChanged && diffLine != nil {
			sess.push(diffLine)
		}
		sess.push(notify)
	}
}

// canonDownstream is a miner session a poolLink feeds in canonical (sv2Work)
// terms, because it renders onto its own wire itself -- i.e. the SV2 rig session.
// The SV1 rigSession is NOT one of these: the link renders SV1 bytes for it.
type canonDownstream interface {
	// pushWork delivers a new work snapshot for the downstream to render.
	pushWork(w sv2Work)
	// stop tears the session down, called when the link loses its upstream so a
	// bound SV2 miner is dropped and reconnects rather than mining dead work.
	stop()
}

// attachCanon binds an SV2 downstream and returns the current work for its
// channel-open. Mutually exclusive with an SV1 bind: one miner per port.
func (l *sv2Link) attachCanon(d canonDownstream) (sv2Work, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.channelOpen {
		return sv2Work{}, false
	}
	if l.boundSess != nil || l.boundCanon != nil {
		l.logf("SV2 port already has a miner; refusing a second (multi-miner on SV2 pools not yet supported)")
		return sv2Work{}, false
	}
	l.boundCanon = d
	l.boundAt = time.Now()
	l.buckets = [rateBuckets]uint64{}
	l.bucketAt, l.bucketStart = 0, time.Time{}
	return l.work, true
}

func (l *sv2Link) detachCanon(d canonDownstream) {
	l.mu.Lock()
	if l.boundCanon == d {
		l.boundCanon = nil
		l.boundAt = time.Time{}
	}
	l.mu.Unlock()
}

// submitCanon relays an SV2 downstream's share straight upstream (both sides are
// XBT extended channels, so the share is valid unchanged) and returns a channel
// carrying the gateway's verdict. Accounting is done here, on the way through, so
// an SV2-rig pool row reads the same as any other.
func (l *sv2Link) submitCanon(jobID uint32, nonce, ntime uint64, extranonce []byte) (<-chan sv2SubmitResult, error) {
	l.mu.Lock()
	up := l.up
	worth := l.curDiff
	if up != nil {
		l.submitted++
	}
	l.mu.Unlock()
	if up == nil {
		return nil, fmt.Errorf("sv2 pool %s not connected", l.pool.displayName())
	}
	inner, err := up.Submit(jobID, nonce, ntime, extranonce)
	if err != nil {
		return nil, err
	}
	out := make(chan sv2SubmitResult, 1)
	go func() {
		r := <-inner // released even on a dropped socket, by sv2Upstream.failAllPending
		now := time.Now()
		l.mu.Lock()
		if r.OK {
			l.accepted++
			l.acceptedWork += worth
			l.addRecentLocked(now, worth)
		} else {
			l.rejected++
		}
		l.lastShare = now
		l.mu.Unlock()
		if r.OK && l.co != nil {
			l.co.feed.publish(shareEvent{Kind: "gw", Rig: l.rigIdx, Pool: l.poolIdx, N: 1})
		}
		out <- r
	}()
	return out, nil
}

func (l *sv2Link) displayName() string { return l.pool.displayName() }

// isReady reports whether a rig may bind here: true once the extended channel is
// open and work is flowing. upstreamForRig gates placement on this, so a rig is
// only ever handed a link that can actually carry it.
func (l *sv2Link) isReady() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.channelOpen
}

// dropForReauth closes the socket so run reconnects under the new identity, the
// SV2 analogue of upstream.dropForReauth.
func (l *sv2Link) dropForReauth() {
	l.mu.Lock()
	up := l.up
	l.mu.Unlock()
	if up != nil {
		up.closeConn()
	}
}

// attach binds a single SV1 rig session to this SV2 link. The rig is handed the
// channel's extranonce_prefix as its extranonce1 and the XBT extranonce size; the
// leaf-equivalence proof guarantees the 8 bytes it then rolls are a valid SV2
// extended-channel extranonce. A second miner is refused (one per SV2 port).
func (l *sv2Link) attach(sess *rigSession) (en1 string, en2 int, configure json.RawMessage, ok bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.channelOpen {
		return "", 0, nil, false
	}
	if l.boundSess != nil || l.boundCanon != nil {
		l.logf("SV2 port already has a miner; refusing a second (multi-miner on SV2 pools not yet supported)")
		return "", 0, nil, false
	}
	l.boundSess = sess
	// Start this visit's rate measurement from empty, like upstream.attach.
	l.boundAt = time.Now()
	l.buckets = [rateBuckets]uint64{}
	l.bucketAt, l.bucketStart = 0, time.Time{}
	return hex.EncodeToString(l.work.ExtranoncePrefix), xbtExtranonceSize, nil, true
}

func (l *sv2Link) detach(sess *rigSession) {
	l.mu.Lock()
	if l.boundSess == sess {
		l.boundSess = nil
		l.boundAt = time.Time{}
	}
	l.mu.Unlock()
}

// primeSession sends a freshly bound rig the current difficulty and job so it
// hashes immediately. Difficulty first, for the reason in the SV1 primeSession.
func (l *sv2Link) primeSession(sess *rigSession) {
	l.mu.Lock()
	diff, notify := l.lastDiff, l.lastNotify
	l.mu.Unlock()
	if diff != nil {
		sess.send(diff)
	} else {
		sess.logf("WARNING: sv2 pool %s has announced no difficulty yet; rig will default to 1", l.pool.displayName())
	}
	if notify != nil {
		sess.send(notify)
	}
}

// grantedConfigure is nil: XBT SV2 extended channels carry no version field, so
// there is no mining.configure/version-rolling to negotiate or offer. The SV1
// rig is answered version-rolling:false by downstream.go's default.
func (l *sv2Link) grantedConfigure() json.RawMessage { return nil }

// submit converts the rig's SV1 share into a SubmitSharesExtended, sends it up,
// and routes the gateway's accept/reject back to the rig when it arrives.
func (l *sv2Link) submit(sess *rigSession, downID json.RawMessage, params json.RawMessage) error {
	jobIDStr, share, err := sv1SubmitToShare(params)
	if err != nil {
		return err
	}
	// The SV1 job_id we handed out IS the SV2 job id in hex; parse it straight
	// back. A share naming a job id we never issued is refused rather than
	// re-pointed at the current job (which would mis-credit a stale share).
	jobID, err := sv2JobIDParse(jobIDStr)
	if err != nil {
		return fmt.Errorf("submit names job_id %q: %w", jobIDStr, err)
	}

	l.mu.Lock()
	up := l.up
	worth := l.curDiff
	if up != nil {
		l.submitted++
	}
	l.mu.Unlock()
	if up == nil {
		return fmt.Errorf("sv2 pool %s not connected", l.pool.displayName())
	}

	resCh, err := up.Submit(jobID, share.Nonce, share.Ntime, share.Extranonce)
	if err != nil {
		return err
	}
	go l.awaitResult(sess, downID, resCh, worth)
	return nil
}

// awaitResult waits for one share's upstream verdict and answers the rig with
// its own id. It also abandons on the session closing, so a gateway that never
// replies (a dropped socket) cannot leak this goroutine.
func (l *sv2Link) awaitResult(sess *rigSession, downID json.RawMessage, resCh <-chan sv2SubmitResult, worth uint64) {
	var res sv2SubmitResult
	select {
	case res = <-resCh:
	case <-sess.done:
		return
	}

	now := time.Now()
	l.mu.Lock()
	if res.OK {
		l.accepted++
		l.acceptedWork += worth
		l.addRecentLocked(now, worth)
	} else {
		l.rejected++
	}
	l.lastShare = now
	l.mu.Unlock()

	if res.OK && l.co != nil {
		l.co.feed.publish(shareEvent{Kind: "gw", Rig: l.rigIdx, Pool: l.poolIdx, N: 1})
		sess.send([]byte(fmt.Sprintf(`{"id":%s,"result":true,"error":null}`, rawID(downID))))
		return
	}
	code := res.Code
	if code == "" {
		code = "rejected"
	}
	sess.send([]byte(fmt.Sprintf(`{"id":%s,"result":false,"error":[23,%q,null]}`, rawID(downID), code)))
}

// connInfo reports the link's outbound socket for outbound(). The SV2 session
// owns the socket internally, so this reports the dialled address and whether
// the channel is up; the local address is not surfaced yet.
func (l *sv2Link) connInfo() linkConn {
	l.mu.Lock()
	defer l.mu.Unlock()
	return linkConn{
		connected: l.channelOpen,
		resolved:  l.pool.stratumAddr(),
		since:     l.connectedAt,
	}
}

// statsAt snapshots everything the dashboard reads under one lock, mirroring
// upstream.statsAt so an SV2 pool row is indistinguishable from an SV1 one.
func (l *sv2Link) statsAt(now time.Time) upstreamStats {
	l.mu.Lock()
	defer l.mu.Unlock()
	st := upstreamStats{
		ready:     l.channelOpen,
		diff:      l.curDiff,
		submitted: l.submitted,
		accepted:  l.accepted,
		rejected:  l.rejected,
		work:      l.acceptedWork,
		chunkSq:   l.chunkSq + sq(l.acceptedWork-l.dwellBase),
		lastShare: l.lastShare,
	}
	st.nowThs = l.recentThsLocked(now)
	return st
}

// sealDwell closes the current fairness chunk and starts the next, called on
// every rotation for every link. Identical in meaning to upstream.sealDwell.
func (l *sv2Link) sealDwell() {
	l.mu.Lock()
	l.chunkSq += sq(l.acceptedWork - l.dwellBase)
	l.dwellBase = l.acceptedWork
	l.mu.Unlock()
}

func (l *sv2Link) resetStats() {
	l.mu.Lock()
	l.submitted, l.accepted, l.rejected = 0, 0, 0
	l.acceptedWork, l.chunkSq, l.dwellBase = 0, 0, 0
	l.lastShare = time.Time{}
	l.buckets = [rateBuckets]uint64{}
	l.bucketAt, l.bucketStart = 0, time.Time{}
	l.mu.Unlock()
}

// The rate ring below mirrors upstream's (addRecentLocked / advanceLocked /
// recentThsLocked). Kept in step with it by intent; see the field comment.
func (l *sv2Link) addRecentLocked(now time.Time, d uint64) {
	l.advanceLocked(now)
	l.buckets[l.bucketAt] += d
}

func (l *sv2Link) advanceLocked(now time.Time) {
	if l.bucketStart.IsZero() {
		l.bucketStart = now
		return
	}
	steps := int(now.Sub(l.bucketStart) / (rateBucketSecs * time.Second))
	if steps <= 0 {
		return
	}
	if steps >= rateBuckets {
		l.buckets = [rateBuckets]uint64{}
		l.bucketAt = 0
	} else {
		for i := 0; i < steps; i++ {
			l.bucketAt = (l.bucketAt + 1) % rateBuckets
			l.buckets[l.bucketAt] = 0
		}
	}
	l.bucketStart = l.bucketStart.Add(time.Duration(steps) * rateBucketSecs * time.Second)
}

func (l *sv2Link) recentThsLocked(now time.Time) float64 {
	if (l.boundSess == nil && l.boundCanon == nil) || l.boundAt.IsZero() {
		return 0
	}
	l.advanceLocked(now)
	var sum uint64
	for _, b := range l.buckets {
		sum += b
	}
	span := now.Sub(l.boundAt)
	if span > rateWindow {
		span = rateWindow
	}
	if span < minRateSpan {
		span = minRateSpan
	}
	return thsFromWork(sum, span)
}

// --- helpers specific to the SV1<->SV2 job id bridge and difficulty ---

// sv2JobIDString renders an SV2 job id (uint32) as the SV1 job_id string handed
// to the rig; sv2JobIDParse reverses it on submit. Making the SV1 id BE the SV2
// id means a share always names the exact SV2 job it was mined on, with no map
// to fall out of date.
func sv2JobIDString(id uint32) string { return fmt.Sprintf("%08x", id) }

func sv2JobIDParse(s string) (uint32, error) {
	v, err := strconv.ParseUint(s, 16, 32)
	if err != nil {
		return 0, err
	}
	return uint32(v), nil
}

// sv1Diff1Target is the stratum "difficulty 1" target (0xffff << 208),
// big-endian, the denominator that turns a target into a share difficulty.
var sv1Diff1Target = new(big.Int).Lsh(big.NewInt(0xffff), 208)

// targetToDifficulty converts an SV2 channel target into the stratum difficulty
// an SV1 rig needs in mining.set_difficulty.
//
// The SV2 target is a U256 carried LITTLE-ENDIAN on the wire (and stored raw in
// the [32]byte), so it is reversed to big-endian before it is read as a number.
// Difficulty is then diff1 / target. WARNING: like the other header-adjacent
// fields, this byte order is per the SV2 spec but is NOT covered by the
// leaf-equivalence proof -- it was confirmed on a live run against a gateway.
// A wrong order here makes the rig flood or withhold.
func targetToDifficulty(leTarget [32]byte) float64 {
	var be [32]byte
	for i := range leTarget {
		be[i] = leTarget[31-i]
	}
	t := new(big.Int).SetBytes(be[:])
	if t.Sign() == 0 {
		return 0
	}
	f, _ := new(big.Rat).SetFrac(sv1Diff1Target, t).Float64()
	return f
}

// difficultyToTarget is the inverse: the SV2 channel target (little-endian) for a
// stratum difficulty, used when an SV1 pool link feeds an SV2 downstream. target
// = diff1 / difficulty. Same live-validation caveat as targetToDifficulty: this
// relation is per spec but the byte order feeding the gateway is confirmed on the
// live run, not by the leaf-equivalence proof.
func difficultyToTarget(diff uint64) [32]byte {
	var le [32]byte
	if diff == 0 {
		return le
	}
	t := new(big.Int).Div(sv1Diff1Target, new(big.Int).SetUint64(diff))
	be := t.FillBytes(make([]byte, 32)) // big-endian, left-padded
	for i := 0; i < 32; i++ {
		le[i] = be[31-i]
	}
	return le
}
