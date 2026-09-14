package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// subscribeTimeout bounds how long a connection may stay silent before it
// must identify itself with mining.subscribe. These miners open a silent
// probe connection alongside the real one; this keeps such sockets from
// accumulating.
const subscribeTimeout = 30 * time.Second

// rigSession is one live connection from a physical miner.
//
// A session is bound to exactly one gateway for its whole lifetime, chosen
// when the miner connects. That binding is deliberately immutable: the
// extranonce1 handed out during mining.subscribe is folded into the coinbase
// and therefore into the merkle root, so a share mined under one gateway's
// extranonce1 is not translatable to another. Rotating a rig means ending its
// session, not redirecting it.
type rigSession struct {
	rig    rigConfig
	rigIdx int
	co     *coordinator
	conn   net.Conn
	w      *connWriter
	up     *upstream

	once sync.Once
	done chan struct{}

	// rotated records that switchyard closed this session deliberately, to
	// move the rig to another gateway, rather than the miner going away on
	// its own. Set by rotate() and read by clearSession(), both under the
	// coordinator's mutex; it exists so the wait that follows can be counted
	// as a rotation's cost or excluded from it. A session nobody rotated
	// keeps the zero value, which is the honest answer for a shutdown, a
	// config apply, or a miner that simply hung up.
	rotated bool

	// open gates unsolicited upstream pushes. A gateway pushes jobs
	// continuously, so the instant a session is published to an upstream a
	// mining.notify can reach the rig -- possibly before the rig has been told
	// what difficulty to work at. Firmware that receives a job first starts
	// hashing at its default difficulty of 1 and floods the gateway with
	// shares that are four thousand times too easy.
	//
	// Pushes are DROPPED rather than queued while closed: the only two things
	// upstream pushes carry are the current difficulty and the current job,
	// and priming sends both anyway. A dropped job is superseded, never lost.
	open atomic.Bool

	// claimedUser is whatever the miner asked to authorise as. Read by the
	// status document from another goroutine, so it takes a lock of its own
	// rather than riding on the coordinator's.
	mu          sync.Mutex
	claimedUser string
}

// claimedUserSafe reports the username this miner offered, or "" if it has not
// authorised yet.
func (s *rigSession) claimedUserSafe() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.claimedUser
}

func newRigSession(co *coordinator, rig rigConfig, rigIdx int, conn net.Conn) *rigSession {
	return &rigSession{
		rig:    rig,
		rigIdx: rigIdx,
		co:     co,
		conn:   conn,
		w:      newConnWriter(conn),
		done:   make(chan struct{}),
	}
}

func (s *rigSession) logf(format string, args ...any) {
	log.Printf("[%s] "+format, append([]any{s.co.rigLabel(s.rigIdx)}, args...)...)
}

func (s *rigSession) send(line []byte) {
	if err := s.w.writeLine(line); err != nil {
		s.close()
	}
}

// push is how an upstream delivers a job or a difficulty change. It differs
// from send only in that it respects the open gate, so a gateway cannot hand
// the rig work before the rig has been handed a difficulty.
func (s *rigSession) push(line []byte) {
	if !s.open.Load() {
		return
	}
	s.send(line)
}

// close is the single rotation primitive. Everything that moves a rig from
// one pool to another ultimately calls this; the miner notices the dropped
// socket, reconnects within seconds, and gets bound to whichever gateway is
// active by then.
func (s *rigSession) close() {
	s.once.Do(func() {
		// done is closed FIRST, before the socket. Closing the connection
		// wakes the read loop immediately, and if it reached its "was this
		// our own doing?" check before done was closed it would report a
		// routine rotation as a connection error. Ordering, not locking, is
		// what makes that check reliable.
		close(s.done)
		s.w.close()
		_ = s.conn.Close()
	})
}

func (s *rigSession) run() {
	defer s.close()

	// Binding is DEFERRED until the rig actually sends mining.subscribe.
	//
	// These miners open a second, silent TCP connection alongside the real
	// one -- it sends no stratum at all and closes after a few seconds.
	// Binding at accept time made that probe attach to the upstream, which
	// evicted the real session (one session slot per upstream), which made
	// the miner reconnect, which opened another probe. The result was a rig
	// that reconnected every three seconds and never hashed.
	//
	// A connection that never subscribes is not a miner, so it never gets to
	// displace one.
	var (
		up       *upstream
		en1      string
		en2      int
		attached bool
		// introducing marks a session that exists only to learn the miner's
		// worker name. It is never bound to a gateway and never carries work.
		introducing bool
	)
	defer func() {
		if attached {
			up.detach(s)
			s.co.clearSession(s.rigIdx, s)
		}
	}()

	// Bound only the pre-subscribe phase: a probe that connects and says
	// nothing must not hold a socket open forever.
	_ = s.conn.SetReadDeadline(time.Now().Add(subscribeTimeout))

	subID := randomHex(8)
	sc := bufio.NewScanner(s.conn)
	sc.Buffer(make([]byte, 0, 16<<10), maxLine)

	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var m message
		if err := json.Unmarshal(line, &m); err != nil {
			s.logf("undecodable line from rig dropped: %s", truncate(line, 160))
			continue
		}

		// Everything except submits, which would flood. Firmware varies a lot
		// in what it sends and in what order, and guessing is how you get a
		// reconnect loop you cannot explain.
		if m.Method != "mining.submit" {
			s.logf("<- %s %s", m.Method, truncate(m.Params, 200))
		}

		switch m.Method {
		case "mining.configure":
			// Replay only what our upstream session actually negotiated.
			// Claiming an extension the upstream does not hold would make the
			// gateway reject every share -- see VersionRollingMask.
			res := `{"version-rolling":false}`
			if peek, ok := s.co.upstreamForRig(s.rigIdx); ok {
				if granted := peek.grantedConfigure(); len(granted) > 0 {
					res = string(granted)
				}
			}
			s.send([]byte(fmt.Sprintf(`{"id":%s,"result":%s,"error":null}`, rawID(m.ID), res)))

		case "mining.subscribe":
			if !attached {
				chosen, ok := s.co.upstreamForRig(s.rigIdx)
				if !ok {
					// THE INTRODUCTION CASE, and the reason it needs handling
					// rather than dropping.
					//
					// Stratum's order is subscribe, then authorize. A rig
					// configured only by port has not told us who it is yet, so
					// there is no identity to authorise upstream with and no
					// gateway session to bind to -- and dropping here is a
					// deadlock: the connection dies before the authorize that
					// would have unblocked it, and the miner retries into the
					// same wall forever.
					//
					// So this connection is answered locally and used purely to
					// learn the miner's name. Once it arrives, the gateway
					// sessions come up, this session is closed, and the miner's
					// own reconnect lands in the ordinary path with a real
					// extranonce from a real gateway.
					if !s.co.credsKnown(s.rigIdx) {
						s.logf("miner has not introduced itself yet; waiting for its worker name")
						s.send([]byte(fmt.Sprintf(
							`{"id":%s,"result":[[["mining.set_difficulty",%q],["mining.notify",%q]],%q,%d],"error":null}`,
							rawID(m.ID), subID, subID, introExtranonce1, introExtranonce2Size)))
						introducing = true
						_ = s.conn.SetReadDeadline(time.Now().Add(introTimeout))
						break
					}
					s.logf("no gateway is ready; dropping connection")
					return
				}
				e1, e2, _, ok := chosen.attach(s)
				if !ok {
					s.logf("gateway %s went away during bind; dropping connection", chosen.pool.Name)
					return
				}
				up, en1, en2, attached = chosen, e1, e2, true
				s.up = chosen
				s.co.setSession(s.rigIdx, s)
				s.logf("bound to %s (extranonce1=%s)", chosen.pool.Name, en1)
				// Real miner: the pre-subscribe guard has done its job.
				_ = s.conn.SetReadDeadline(time.Time{})
			}
			s.send([]byte(fmt.Sprintf(
				`{"id":%s,"result":[[["mining.set_difficulty",%q],["mining.notify",%q]],%q,%d],"error":null}`,
				rawID(m.ID), subID, subID, en1, en2)))
			// Difficulty goes out HERE, immediately behind the subscribe
			// response and before mining.authorize, because that is the first
			// moment the rig can legally be sent anything and because the very
			// next thing it may receive is a job. Waiting for authorize leaves
			// a window in which a pushed job arrives first and the rig starts
			// hashing at its default difficulty of 1.
			if attached {
				up.primeSession(s)
				s.open.Store(true)
			}

		case "mining.authorize":
			// The miner's own name and password are what switchyard presents
			// upstream. Recording them here is what makes every gateway
			// session possible: until a rig has authorised there is no
			// identity to authorise WITH, and inventing one is exactly what
			// this design refuses to do.
			//
			// Answering true immediately is still correct. The downstream
			// session is switchyard's own, and the upstream handshake this
			// triggers happens on another goroutine; a miner made to wait for
			// three gateways before it could start would be slower for no
			// benefit.
			if u, ok := paramStringAt(m.Params, 0); ok {
				pw, _ := paramStringAt(m.Params, 1)
				s.mu.Lock()
				s.claimedUser = u
				s.mu.Unlock()
				// THIS is where a rig's identity enters switchyard, and the
				// coordinator decides what it means: a first miner, a fleet
				// member back from a rotation, a lone miner renaming itself,
				// or a stranger joining a port that already has a name.
				s.co.noteAuthorise(s.rigIdx, s, u, pw)
				if introducing {
					// The introduction is over. Answer the authorize so the
					// miner does not sit waiting, then close: its reconnect
					// will find gateway sessions up and bind normally.
					//
					// A reconnect rather than an upgrade in place because the
					// extranonce this session was given is switchyard's own,
					// and the real one comes from whichever gateway ends up
					// carrying the rig. Stratum has no way to change it on a
					// live session -- which is exactly why extranonce.subscribe
					// is declined elsewhere in this file.
					s.send([]byte(fmt.Sprintf(`{"id":%s,"result":true,"error":null}`, rawID(m.ID))))
					s.logf("learned worker name %q; reconnect will bind to a gateway", u)
					return
				}
			}
			s.send([]byte(fmt.Sprintf(`{"id":%s,"result":true,"error":null}`, rawID(m.ID))))
			if attached {
				up.primeSession(s)
			}

		case "mining.submit":
			if !attached {
				s.send([]byte(fmt.Sprintf(
					`{"id":%s,"result":null,"error":[25,"not subscribed",null]}`, rawID(m.ID))))
				break
			}
			if err := up.submit(s, m.ID, m.Params); err != nil {
				s.logf("submit to %s failed: %v", up.pool.Name, err)
				s.send([]byte(fmt.Sprintf(
					`{"id":%s,"result":null,"error":[20,"upstream unavailable",null]}`, rawID(m.ID))))
			}

		case "mining.extranonce.subscribe":
			// Declining is the honest answer: we drop and rebind a session
			// when extranonce changes rather than pushing an update.
			s.send([]byte(fmt.Sprintf(`{"id":%s,"result":false,"error":null}`, rawID(m.ID))))

		default:
			// Unknown request with an id still needs an answer or some
			// firmware stalls waiting for one.
			if !m.isNotification() && m.Method != "" {
				s.send([]byte(fmt.Sprintf(`{"id":%s,"result":null,"error":[20,"unsupported",null]}`, rawID(m.ID))))
			}
		}
	}
	// A rotation closes the socket underneath this loop, so an error here is
	// the normal path out, not a fault worth shouting about. Only log it when
	// the session was still supposed to be live.
	if err := sc.Err(); err != nil {
		select {
		case <-s.done:
		default:
			s.logf("rig connection ended: %v", err)
		}
	}
}

// serveRig accepts miner connections on one rig's dedicated port.
//
// Each rig gets its own listener rather than sharing one, because the whole
// scheme depends on addressing rigs independently -- that is what lets two
// rigs cover three pools without ever doubling up.
func serveRig(ctx context.Context, co *coordinator, rigIdx int) error {
	rig := co.cfg.Rigs[rigIdx]
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", rig.Listen)
	if err != nil {
		return fmt.Errorf("listening for %s on %s: %w", co.rigLabel(rigIdx), rig.Listen, err)
	}
	log.Printf("[%s] listening on %s", co.rigLabel(rigIdx), rig.Listen)

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			log.Printf("[%s] accept failed: %v", co.rigLabel(rigIdx), err)
			continue
		}
		// Deliberately does NOT close the current session here. Accepting a
		// socket proves nothing -- these miners open silent probe connections
		// -- and tearing down a hashing session for one is how the reconnect
		// loop started. Eviction happens in attach(), which only real
		// subscribers reach.
		//
		// Any number of miners per port: each gets its own slice of the
		// gateway's extranonce at subscribe (see upstream.attach). Nothing
		// is ever evicted; a dead socket is reaped by keepalive or the next
		// rotation.
		s := newRigSession(co, rig, rigIdx, conn)
		go s.run()
	}
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "switchyard"
	}
	return hex.EncodeToString(b)
}
