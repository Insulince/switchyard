package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net"
	"strconv"
	"sync"
	"time"
)

// maxLine bounds one stratum line. mining.notify carries the full merkle
// branch and both coinbase halves, so it is the largest thing on the wire by
// a wide margin -- but it is still nowhere near this. The generous ceiling is
// purely so a malformed peer cannot make us allocate without bound.
const maxLine = 4 << 20

// upstreamIdleTimeout is how long we tolerate silence from a gateway before
// assuming the socket is dead and reconnecting.
//
// A DATUM gateway pushes work continuously whether or not anything is
// hashing against it, so real silence means the socket is gone. Note this is
// OUR timer against the gateway on localhost; it is unrelated to the
// gateway's own unimplemented-keepalive reconnect against its Prime.
const upstreamIdleTimeout = 5 * time.Minute

// pendingSubmit remembers who asked, so a gateway's reply can be routed back
// to the right rig with the id that rig used. Upstream ids are ours; rigs
// have their own numbering and we must not leak one into the other.
type pendingSubmit struct {
	sess   *rigSession
	downID json.RawMessage
}

// upstream is one persistent stratum session from switchyard to one gateway,
// on behalf of one rig. There is a full mesh: every rig holds an open session
// to every gateway, all the time.
//
// That mesh is the entire trick. A DATUM gateway keeps its vardiff state in
// T_DATUM_MINER_DATA hanging off the stratum client object, so it lives and
// dies with the TCP connection and is NOT keyed by worker name. If we dialled
// a gateway only while a rig was pointed at it, every rotation would reset
// that gateway's difficulty to the floor and force it to re-climb. By holding
// all sessions open permanently, only the rig-facing connection cycles: each
// gateway's per-rig difficulty merely sags toward the pool-supplied floor
// while idle (bounded by override_vardiff_min) and recovers when work returns.
type upstream struct {
	pool   poolConfig
	rig    rigConfig
	rigIdx int
	co     *coordinator

	// user and pass are whatever the MINER authorised with, learned when it
	// first connects and then presented upstream unchanged. Empty until then,
	// which is why session() waits rather than dialling immediately.
	user string
	pass string

	mu              sync.Mutex
	w               *connWriter
	conn            net.Conn
	connectedAt     time.Time
	ready           bool
	extranonce1     string
	extranonce2Size int
	configureResult json.RawMessage
	lastDiff        []byte
	lastNotify      []byte
	// sessions is every miner currently bound here, each with the one-byte
	// extranonce2 prefix that is its private slice of this upstream's nonce
	// space -- or noPrefix, when the gateway left no byte to spare.
	//
	// A port is a VIRTUAL rig. Whatever hardware is behind it -- one ASIC,
	// or fifty rented machines -- is one entity to switchyard: one gateway
	// session, one difficulty, one line in every table. The gateway hands
	// this session an extranonce1 and an 8-byte extranonce2; switchyard
	// keeps the first byte of extranonce2 for itself and gives each miner
	// extranonce1+prefix with a 7-byte extranonce2. Nonce spaces are
	// disjoint by construction, so two miners on one port can never
	// duplicate work, and a submit is rebuilt to the gateway's shape by
	// putting the prefix back. This is what every stratum proxy does; it is
	// what the gateway itself does to the miners behind it.
	sessions map[*rigSession]int
	nextID   uint64
	pending  map[uint64]pendingSubmit

	// Counters for the status view. These are per (rig, pool) because that is
	// the pairing an operator reasons about: "how is this rig doing on this
	// pool". They are cumulative since process start and deliberately not
	// persisted -- a restart reshuffles the placement anyway, so carrying old
	// totals across one would describe an arrangement that no longer exists.
	diff      uint64
	submitted uint64
	accepted  uint64
	rejected  uint64
	lastShare time.Time

	// acceptedWork is the summed difficulty of accepted shares, which is the
	// only honest basis for a hashrate here. Counting shares alone would not
	// do: difficulty differs per gateway (1024, 2048, 4096) and changes over
	// a session, so one share on lazarus is worth four on iohzrd. Difficulty
	// is what actually measures hashes done.
	acceptedWork uint64

	// dwellBase is acceptedWork as it stood when the current dwell began, and
	// chunkSq accumulates the squared size of every dwell that has since
	// closed. Together they are the variance term for the fairness band.
	//
	// The unit here is the whole point, and getting it wrong is what made the
	// band absurdly tight. A SHARE is not the thing that gets assigned to a
	// pool: every share a rig produces during one dwell goes to the SAME
	// pool, by construction. The independently assigned unit is the dwell
	// chunk -- one rig's output over one dwell -- so the variance term is
	// sum over chunks of c^2, not sum over shares of d^2. With a few thousand
	// shares spread across a couple of hundred chunks that is a band several
	// times wider, and the narrow one was reporting ordinary scheduling as a
	// three-sigma scandal.
	//
	// Squared work rather than a chunk count, for the same reason difficulty
	// rather than share count is used above: chunks are not equal in size. A
	// dwell that ran nine minutes carries far more work than one cut short by
	// a fast block, and it moves the total correspondingly further.
	dwellBase uint64
	chunkSq   float64

	// buckets is a ring of fixed-width time slices holding recently accepted
	// work, used for the "right now" rate. A cumulative average cannot answer
	// "what is this link carrying at this moment", and that is the number a
	// flow diagram is claiming to show.
	buckets     [rateBuckets]uint64
	bucketAt    int
	bucketStart time.Time

	// boundAt is when the current rig session attached, and it is what makes
	// the "right now" rate honest across a rotation. Without it the window
	// keeps reporting work from a previous visit, so a pool that has just gone
	// dark reads as still receiving hashrate for several more minutes -- the
	// exact claim a flow diagram must not make.
	boundAt time.Time
}

func newUpstream(co *coordinator, rigIdx int, rig rigConfig, pool poolConfig) *upstream {
	return &upstream{
		pool:     pool,
		rig:      rig,
		rigIdx:   rigIdx,
		co:       co,
		pending:  map[uint64]pendingSubmit{},
		sessions: map[*rigSession]int{},
	}
}

// noPrefix marks a session bound without an extranonce slice, which only
// happens when a gateway's extranonce2 is a single byte and there is nothing
// to split. That upstream then behaves as it always did: one miner, and a
// new subscriber displaces it.
const noPrefix = -1

// prefixBytes is how much of the gateway's extranonce2 switchyard keeps.
// One byte is 256 miners per port, and leaves 7 bytes of rolling space --
// more than any firmware uses.
const prefixBytes = 1

// sessionsLocked snapshots the bound sessions. Caller holds u.mu; the copy is
// so the caller can drop the lock before touching a session, since a
// session's own goroutine calls back into detach as it unwinds.
func (u *upstream) sessionsLocked() []*rigSession {
	out := make([]*rigSession, 0, len(u.sessions))
	for s := range u.sessions {
		out = append(out, s)
	}
	return out
}

// dropForReauth closes this upstream's socket so its run loop reconnects and
// re-authorises.
//
// Stratum has no way to change the authorised user on a live session, so when
// a miner turns up under a different name the only correct response is a fresh
// handshake. Closing the connection is how that is requested: the read loop
// errors, session() returns, and the retry picks up the new credentials.
func (u *upstream) dropForReauth() {
	u.mu.Lock()
	conn := u.conn
	u.mu.Unlock()
	if conn != nil {
		_ = conn.Close()
	}
}

func (u *upstream) logf(format string, args ...any) {
	log.Printf("[%s->%s] "+format, append([]any{u.co.rigLabel(u.rigIdx), u.pool.Name}, args...)...)
}

// run keeps one gateway session alive forever, reconnecting with backoff.
func (u *upstream) run(ctx context.Context) {
	backoff := time.Second
	for ctx.Err() == nil {
		if err := u.session(ctx); err != nil && ctx.Err() == nil {
			u.logf("session ended: %v (retry in %s)", err, backoff)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff < 30*time.Second {
			backoff *= 2
		}
		// A session that survived long enough to be useful earns a fresh
		// fast retry; only genuinely flapping gateways get backed off.
		if u.sessionWasHealthy() {
			backoff = time.Second
		}
	}
}

func (u *upstream) sessionWasHealthy() bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.lastNotify != nil
}

func (u *upstream) session(ctx context.Context) error {
	// Nothing is dialled until the rig has said who it is. Connecting first
	// and authorising later is not an option in stratum -- the username is
	// part of the handshake -- and inventing one is precisely what this
	// design exists to stop doing.
	user, pass, ok := u.co.creds[u.rigIdx].waitKnown(ctx)
	if !ok {
		return nil
	}
	u.mu.Lock()
	u.user, u.pass = user, pass
	u.mu.Unlock()

	d := net.Dialer{Timeout: u.co.cfg.dialTimeout()}
	conn, err := d.DialContext(ctx, "tcp", u.pool.stratumAddr())
	if err != nil {
		return fmt.Errorf("dial %s: %w", u.pool.stratumAddr(), err)
	}
	defer conn.Close()
	// readLoop blocks on the socket, not on ctx. Without this a cancelled
	// generation (a config reload) leaves its gateway sessions alive: they
	// keep receiving notifies and keep rotating a coordinator nothing is
	// attached to any more, in parallel with the live one.
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	u.mu.Lock()
	u.conn, u.w = conn, newConnWriter(conn)
	u.connectedAt = time.Now()
	u.ready = false
	u.lastNotify, u.lastDiff = nil, nil
	u.mu.Unlock()

	defer func() {
		u.mu.Lock()
		u.ready = false
		u.conn, u.connectedAt = nil, time.Time{}
		if u.w != nil {
			u.w.close()
		}
		bound := u.sessionsLocked()
		u.mu.Unlock()
		// A rig bound to a gateway we just lost is holding a dead route.
		// Drop it so it reconnects and gets rebound to a live gateway.
		for _, s := range bound {
			s.close()
		}
	}()

	sc := bufio.NewScanner(conn)
	sc.Buffer(make([]byte, 0, 64<<10), maxLine)

	if err := u.handshake(sc, conn); err != nil {
		return fmt.Errorf("handshake: %w", err)
	}

	u.mu.Lock()
	u.ready = true
	en1 := u.extranonce1
	u.mu.Unlock()
	u.logf("ready as %s (extranonce1=%s)", u.user, en1)

	return u.readLoop(sc, conn)
}

// handshake performs mining.configure (optional), mining.subscribe and
// mining.authorize in that order. The order is fixed by the protocol:
// configure is only legal before subscribe, which is exactly why we
// negotiate version rolling here on the rig's behalf rather than passing the
// rig's own request through later.
func (u *upstream) handshake(sc *bufio.Scanner, conn net.Conn) error {
	_ = conn.SetDeadline(time.Now().Add(u.co.cfg.dialTimeout()))
	defer func() { _ = conn.SetDeadline(time.Time{}) }()

	if mask := u.co.cfg.VersionRollingMask; mask != "" {
		req := fmt.Sprintf(`{"id":1,"method":"mining.configure","params":[["version-rolling"],{"version-rolling.mask":"%s"}]}`, mask)
		if err := u.w.writeLine([]byte(req)); err != nil {
			return err
		}
		// A gateway that does not implement mining.configure is not an
		// error worth failing the whole session over -- we simply mine
		// without version rolling, which costs a little efficiency and
		// nothing else.
		resp, err := u.readUntilResponse(sc, "1")
		switch {
		case err != nil:
			u.logf("version rolling unavailable: %v", err)
		case len(resp.Error) > 0 && string(resp.Error) != "null":
			u.logf("version rolling refused: %s", resp.Error)
		default:
			u.mu.Lock()
			u.configureResult = resp.Result
			u.mu.Unlock()
		}
	}

	if err := u.w.writeLine([]byte(`{"id":2,"method":"mining.subscribe","params":["switchyard/1.0"]}`)); err != nil {
		return err
	}
	resp, err := u.readUntilResponse(sc, "2")
	if err != nil {
		return fmt.Errorf("subscribe: %w", err)
	}
	if err := u.applySubscribe(resp.Result); err != nil {
		return err
	}

	auth := fmt.Sprintf(`{"id":3,"method":"mining.authorize","params":[%q,%q]}`, u.user, u.pass)
	if err := u.w.writeLine([]byte(auth)); err != nil {
		return err
	}
	resp, err = u.readUntilResponse(sc, "3")
	if err != nil {
		return fmt.Errorf("authorize: %w", err)
	}
	var ok bool
	if err := json.Unmarshal(resp.Result, &ok); err != nil || !ok {
		return fmt.Errorf("authorize rejected for %q: result=%s error=%s", u.user, resp.Result, resp.Error)
	}
	return nil
}

// applySubscribe records the extranonce1 and extranonce2 size this gateway
// assigned us. These are per-session values baked into the coinbase, so they
// are the reason a rig cannot be silently swung between gateways: a share
// mined under one gateway's extranonce1 is simply a different share and
// cannot be re-addressed to another.
func (u *upstream) applySubscribe(result json.RawMessage) error {
	var arr []json.RawMessage
	if err := json.Unmarshal(result, &arr); err != nil {
		return fmt.Errorf("decoding subscribe result: %w", err)
	}
	if len(arr) < 3 {
		return fmt.Errorf("subscribe result has %d fields, want 3", len(arr))
	}
	var en1 string
	if err := json.Unmarshal(arr[1], &en1); err != nil {
		return fmt.Errorf("decoding extranonce1: %w", err)
	}
	var en2 int
	if err := json.Unmarshal(arr[2], &en2); err != nil {
		return fmt.Errorf("decoding extranonce2_size: %w", err)
	}
	u.mu.Lock()
	u.extranonce1, u.extranonce2Size = en1, en2
	u.mu.Unlock()
	return nil
}

// readUntilResponse consumes lines until the response to id arrives,
// dispatching any notifications that overtake it. Gateways routinely push a
// job before answering a subscribe, so this cannot assume ordering.
func (u *upstream) readUntilResponse(sc *bufio.Scanner, id string) (*message, error) {
	for sc.Scan() {
		// COPY. bufio.Scanner hands back a slice into a buffer it reuses on
		// the very next Scan, and handleNotification retains what it is given
		// for the lifetime of the session. Aliasing here meant lastNotify and
		// lastDiff silently mutated into whatever line arrived afterwards --
		// a share rejection, half a job -- and rigs were primed with that.
		line := append([]byte(nil), sc.Bytes()...)
		if len(line) == 0 {
			continue
		}
		var m message
		if err := json.Unmarshal(line, &m); err != nil {
			continue
		}
		if m.isNotification() {
			u.handleNotification(&m, line)
			continue
		}
		if string(m.ID) == id {
			return &m, nil
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("connection closed awaiting response %s", id)
}

func (u *upstream) readLoop(sc *bufio.Scanner, conn net.Conn) error {
	for {
		_ = conn.SetReadDeadline(time.Now().Add(upstreamIdleTimeout))
		if !sc.Scan() {
			if err := sc.Err(); err != nil {
				return err
			}
			return fmt.Errorf("gateway closed the connection")
		}
		line := append([]byte(nil), sc.Bytes()...)
		if len(line) == 0 {
			continue
		}
		var m message
		if err := json.Unmarshal(line, &m); err != nil {
			u.logf("undecodable line dropped: %s", truncate(line, 160))
			continue
		}
		if m.isNotification() {
			u.handleNotification(&m, line)
			continue
		}
		u.routeResponse(&m)
	}
}

func (u *upstream) handleNotification(m *message, line []byte) {
	switch m.Method {
	case "mining.notify":
		// params[1] is prevhash. A change means the network moved on, which
		// is our rotation clock -- and it costs nothing to observe, because
		// every gateway already pushes a fresh job on every block. No
		// blocknotify wiring and no node restart required to get it.
		if ph, ok := paramStringAt(m.Params, 1); ok {
			u.co.noteBlock(ph)
		}
		u.mu.Lock()
		// Copied again rather than trusted: this is retained until the next
		// job arrives, and every caller getting the ownership right is a
		// weaker guarantee than not needing them to.
		u.lastNotify = append([]byte(nil), line...)
		bound := u.sessionsLocked()
		u.mu.Unlock()
		for _, s := range bound {
			s.push(line)
		}

	case "mining.set_difficulty":
		// Difficulty is REBUILT from the parsed number rather than replayed
		// from the wire. A rig that receives a malformed set_difficulty does
		// not complain -- it just keeps working at its default of 1 and
		// floods the gateway with shares four thousand times too easy. Since
		// nothing downstream can detect the mistake, nothing we cannot parse
		// is allowed to become a difficulty in the first place.
		f, ok := paramNumberAt(m.Params, 0)
		if !ok || !(f > 0) || math.IsInf(f, 0) {
			u.logf("ignoring unparseable set_difficulty: %s", truncate(line, 120))
			return
		}
		// Forward the exact value the gateway chose; the rig's target must
		// match the gateway's or shares are rejected. Accounting keeps whole
		// units -- 1023.984375 credits as 1024, which is what a human reads
		// on the card and is within a fifteen-thousandth of the truth.
		line = []byte(fmt.Sprintf(`{"id":null,"method":"mining.set_difficulty","params":[%s]}`,
			strconv.FormatFloat(f, 'f', -1, 64)))
		d := uint64(math.Round(f))
		if d == 0 {
			d = 1
		}

		u.mu.Lock()
		changed := u.diff != d
		u.lastDiff = line
		u.diff = d
		bound := u.sessionsLocked()
		u.mu.Unlock()
		// Difficulty is the one push worth logging: it is rare, and a rig
		// working at a difficulty the gateway is not expecting is invisible
		// from every other vantage point until the reject counter explodes.
		if changed {
			u.logf("difficulty now %s", truncate(line, 120))
		}
		for _, s := range bound {
			s.push(line)
		}

	case "mining.set_extranonce":
		// The gateway reassigned our extranonce1 mid-session. Any rig bound
		// to us is now mining a coinbase we no longer own, so drop it and
		// let it re-subscribe against the new value rather than forwarding
		// an extension its firmware may not implement.
		if en1, ok := paramStringAt(m.Params, 0); ok {
			u.mu.Lock()
			u.extranonce1 = en1
			if en2, ok := paramsAt(m.Params, 1); ok {
				var n int
				if json.Unmarshal(en2, &n) == nil {
					u.extranonce2Size = n
				}
			}
			bound := u.sessionsLocked()
			u.mu.Unlock()
			u.logf("extranonce reassigned to %s; rebinding rig", en1)
			for _, s := range bound {
				s.close()
			}
		}

	default:
		// mining.ping and friends. Nothing downstream needs them.
	}
}

func (u *upstream) routeResponse(m *message) {
	var id uint64
	if err := json.Unmarshal(m.ID, &id); err != nil {
		return
	}
	u.mu.Lock()
	p, ok := u.pending[id]
	delete(u.pending, id)
	if ok {
		// A share is accepted only on a literal true. Anything else -- false,
		// null, an error object -- is a rejection, and lumping them together
		// is right here: the status view answers "is this rig working", and
		// every non-true answer means it is not.
		if string(m.Result) == "true" {
			u.accepted++
			u.acceptedWork += u.diff
			u.addRecentLocked(time.Now(), u.diff)
		} else {
			u.rejected++
		}
		u.lastShare = time.Now()
	}
	u.mu.Unlock()
	if !ok {
		return
	}
	res := m.Result
	if len(res) == 0 {
		res = json.RawMessage("null")
	}
	errField := m.Error
	if len(errField) == 0 {
		errField = json.RawMessage("null")
	}
	p.sess.send([]byte(fmt.Sprintf(`{"id":%s,"result":%s,"error":%s}`, rawID(p.downID), res, errField)))
}

// submit forwards a rig's share to this gateway under our own id, rewriting
// the worker name to the one our session authorised with.
func (u *upstream) submit(sess *rigSession, downID json.RawMessage, params json.RawMessage) error {
	fixed, err := replaceParam0(params, u.user)
	if err != nil {
		return fmt.Errorf("rewriting worker name: %w", err)
	}
	u.mu.Lock()
	if !u.ready || u.w == nil {
		u.mu.Unlock()
		return fmt.Errorf("gateway %s not ready", u.pool.Name)
	}
	// Put the prefix back. The miner rolled its 7 bytes; the gateway
	// expects the 8 it handed out, and the leading byte is the one that
	// says which miner this was.
	if prefix, ok := u.sessions[sess]; ok && prefix != noPrefix {
		en2, _ := paramStringAt(params, 2)
		fixed, err = replaceParamAt(fixed, 2, fmt.Sprintf("%02x", prefix)+en2)
		if err != nil {
			u.mu.Unlock()
			return fmt.Errorf("rewriting extranonce2: %w", err)
		}
	}
	u.nextID++
	u.submitted++
	id := u.nextID + 100 // stay clear of the handshake ids
	u.pending[id] = pendingSubmit{sess: sess, downID: downID}
	w := u.w
	u.mu.Unlock()

	return w.writeLine([]byte(fmt.Sprintf(`{"id":%d,"method":"mining.submit","params":%s}`, id, fixed)))
}

// attach binds a rig session to this gateway and primes it with the current
// difficulty and job, so the rig starts hashing immediately rather than
// waiting for the next push.
func (u *upstream) attach(sess *rigSession) (en1 string, en2 int, configure json.RawMessage, ok bool) {
	u.mu.Lock()
	if !u.ready {
		u.mu.Unlock()
		return "", 0, nil, false
	}
	prefix := noPrefix
	if u.extranonce2Size > prefixBytes {
		// Lowest free byte. Freed slots are reused, so a miner that
		// reconnects all day does not walk the space.
		taken := make([]bool, 256)
		for _, p := range u.sessions {
			if p >= 0 {
				taken[p] = true
			}
		}
		for p := 0; p < 256; p++ {
			if !taken[p] {
				prefix = p
				break
			}
		}
		if prefix == noPrefix {
			u.mu.Unlock()
			u.logf("all 256 extranonce slots taken; refusing another miner")
			return "", 0, nil, false
		}
	} else if len(u.sessions) > 0 {
		// Nothing to split, so the port holds one miner -- and it is the
		// one already hashing. Refusing the newcomer is the same rule as
		// everywhere else: nothing on a port is ever evicted.
		u.mu.Unlock()
		u.logf("gateway leaves no extranonce byte to split; refusing a second miner")
		return "", 0, nil, false
	}
	if len(u.sessions) == 0 {
		u.boundAt = time.Now()
		// Start this visit's rate measurement from empty. Work from the
		// last time this rig sat here is not evidence about what is flowing
		// now. Only on the FIRST miner: a second one joining a live port is
		// adding to a measurement, not starting one.
		u.buckets = [rateBuckets]uint64{}
		u.bucketAt, u.bucketStart = 0, time.Time{}
	}
	u.sessions[sess] = prefix
	en1, en2, configure = u.extranonce1, u.extranonce2Size, u.configureResult
	if prefix != noPrefix {
		en1 += fmt.Sprintf("%02x", prefix)
		en2 -= prefixBytes
	}
	u.mu.Unlock()
	return en1, en2, configure, true
}

// There is deliberately NO reconnect eviction. "Same worker name from the
// same address" was tried and displaced the wrong miner: behind Docker's
// published port every external miner arrives from the bridge address, and
// rented hashrate routinely shares one worker name. A stale session -- a
// miner that vanished without closing its socket -- is reaped by TCP
// keepalive within a couple of minutes and by the next rotation regardless;
// until then it shows as one more miner on the port, and holds one of 256
// slots. That is cheaper than ever closing a live miner by mistake.

// minerCount is how many miners are bound to this upstream right now.
func (u *upstream) minerCount() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return len(u.sessions)
}

// primeSession sends the current difficulty and job to a freshly bound rig.
//
// The difficulty MUST go first. A gateway only pushes mining.set_difficulty
// when the value changes, so a rig that misses it never hears the value again
// -- and a gateway pinned at a fixed vardiff_min never changes it at all.
func (u *upstream) primeSession(sess *rigSession) {
	u.mu.Lock()
	diff, notify := u.lastDiff, u.lastNotify
	u.mu.Unlock()
	if diff != nil {
		sess.send(diff)
		sess.logf("primed with %s", truncate(diff, 120))
	} else {
		sess.logf("WARNING: gateway %s never announced a difficulty; rig will default to 1", u.pool.Name)
	}
	if notify != nil {
		sess.send(notify)
	}
}

func (u *upstream) detach(sess *rigSession) {
	u.mu.Lock()
	delete(u.sessions, sess)
	if len(u.sessions) == 0 {
		u.boundAt = time.Time{}
	}
	// Shares still in flight for a session that just went away have nowhere
	// to land; drop their bookkeeping rather than leaking the map.
	for id, p := range u.pending {
		if p.sess == sess {
			delete(u.pending, id)
		}
	}
	u.mu.Unlock()
}

// grantedConfigure is the mining.configure result this upstream session
// actually negotiated, or nil if it negotiated none. A rig must never be told
// it has an extension the upstream does not hold.
func (u *upstream) grantedConfigure() json.RawMessage {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.configureResult
}

func (u *upstream) isReady() bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.ready
}

// statsAt snapshots everything the dashboard needs from one upstream under a
// single lock, so the numbers it renders are mutually consistent. The windowed
// rate needs a clock, which is why this takes one rather than being a field.
func (u *upstream) statsAt(now time.Time) upstreamStats {
	u.mu.Lock()
	defer u.mu.Unlock()
	st := upstreamStats{
		ready:     u.ready,
		diff:      u.diff,
		submitted: u.submitted,
		accepted:  u.accepted,
		rejected:  u.rejected,
		work:      u.acceptedWork,
		// The dwell in progress counts too, at whatever size it has reached.
		// Adding it here rather than mutating state keeps a read a read: the
		// band grows smoothly through a dwell instead of stepping at each
		// rotation.
		chunkSq:   u.chunkSq + sq(u.acceptedWork-u.dwellBase),
		lastShare: u.lastShare,
	}
	st.nowThs = u.recentThsLocked(now)
	return st
}

// sealDwell closes the current dwell chunk and starts a new one. It is called
// on every rotation, for every upstream -- including the ones that were idle,
// whose chunk is zero and contributes nothing.
func (u *upstream) sealDwell() {
	u.mu.Lock()
	u.chunkSq += sq(u.acceptedWork - u.dwellBase)
	u.dwellBase = u.acceptedWork
	u.mu.Unlock()
}

func sq(n uint64) float64 { return float64(n) * float64(n) }

// resetStats zeroes everything the dashboard measures, leaving the live
// session -- extranonce, difficulty, the socket itself -- untouched.
// Rebalancing hardware should not cost a reconnect.
func (u *upstream) resetStats() {
	u.mu.Lock()
	u.submitted, u.accepted, u.rejected = 0, 0, 0
	u.acceptedWork, u.chunkSq, u.dwellBase = 0, 0, 0
	u.lastShare = time.Time{}
	u.buckets = [rateBuckets]uint64{}
	u.bucketAt, u.bucketStart = 0, time.Time{}
	u.mu.Unlock()
}

// rateWindow is how far back the "right now" rate looks.
//
// It is a genuine tension, not an arbitrary constant. At difficulty 4096 a
// 0.5 TH/s rig lands an accepted share about every 35 seconds, so a short
// window reports mostly Poisson noise -- a 60-second window would routinely
// read 0.00 or double the true rate on a perfectly healthy link. Five minutes
// buys roughly 8 shares, which is still noisy (about +/-35%) but no longer
// meaningless, while staying short enough to fall to zero within one rotation
// of a link going idle.
const (
	rateBuckets    = 30
	rateBucketSecs = 10
	rateWindow     = rateBuckets * rateBucketSecs * time.Second
)

// addRecentLocked advances the ring to now and credits work to the current
// slice. Advancing on write AND on read is what makes an idle link decay to
// zero on its own instead of freezing at its last value.
func (u *upstream) addRecentLocked(now time.Time, d uint64) {
	u.advanceLocked(now)
	u.buckets[u.bucketAt] += d
}

func (u *upstream) advanceLocked(now time.Time) {
	if u.bucketStart.IsZero() {
		u.bucketStart = now
		return
	}
	steps := int(now.Sub(u.bucketStart) / (rateBucketSecs * time.Second))
	if steps <= 0 {
		return
	}
	if steps >= rateBuckets {
		u.buckets = [rateBuckets]uint64{}
		u.bucketAt = 0
	} else {
		for i := 0; i < steps; i++ {
			u.bucketAt = (u.bucketAt + 1) % rateBuckets
			u.buckets[u.bucketAt] = 0
		}
	}
	u.bucketStart = u.bucketStart.Add(time.Duration(steps) * rateBucketSecs * time.Second)
}

// recentThsLocked is what this link is carrying at this moment.
//
// An upstream with no session attached is carrying exactly nothing -- only the
// bound rig can submit through it -- so that case is reported as zero rather
// than estimated. This is not a fudge covering for a slow window: it is the
// one value here that is known exactly rather than sampled.
//
// While bound, the denominator is the time since binding, clamped. The upper
// clamp is the window itself; the lower clamp matters more, because for the
// first half-minute of a visit almost no shares have landed and dividing by a
// few seconds would turn one early share into an absurd number. Erring low on
// a fresh binding is the safe direction -- it converges upward within a
// minute, whereas erring high looks like a fault that is not there.
const minRateSpan = 60 * time.Second

func (u *upstream) recentThsLocked(now time.Time) float64 {
	if len(u.sessions) == 0 || u.boundAt.IsZero() {
		return 0
	}
	u.advanceLocked(now)
	var sum uint64
	for _, b := range u.buckets {
		sum += b
	}
	span := now.Sub(u.boundAt)
	if span > rateWindow {
		span = rateWindow
	}
	if span < minRateSpan {
		span = minRateSpan
	}
	return thsFromWork(sum, span)
}

type upstreamStats struct {
	ready     bool
	diff      uint64
	submitted uint64
	accepted  uint64
	rejected  uint64
	work      uint64
	chunkSq   float64
	nowThs    float64
	lastShare time.Time
}

// thsFromWork converts summed share difficulty into terahashes per second.
//
// One difficulty-1 share is 2^32 expected hashes, so total hashes is
// work * 2^32 and the rate is that over the elapsed wall time. Note the
// denominator is the WHOLE elapsed time, not the time this rig spent on this
// pool -- a pool carrying a 0.5 TH/s rig for a third of the time really did
// receive 0.17 TH/s on average, and that average is the thing being compared
// against an even split.
func thsFromWork(work uint64, elapsed time.Duration) float64 {
	if elapsed <= 0 {
		return 0
	}
	return float64(work) * 4294967296.0 / elapsed.Seconds() / 1e12
}

func truncate(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "..."
}
