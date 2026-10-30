package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"

	"github.com/Insulince/switchyard/sv2/common"
	"github.com/Insulince/switchyard/sv2/mining"
)

// sv2DownstreamCertValidity bounds the authority-signed certificate switchyard
// presents to a connecting translator. A fresh certificate is minted on every
// handshake, so this window never limits how long the process or a session runs.
const sv2DownstreamCertValidity = time.Hour

// serveRigSV2 accepts SV2 miner connections (a translator on the box) on one
// rig's port, terminating Noise and binding each to the mesh's active SV2 link.
// It is the downstream analogue of serveRigSV1 for a rig that speaks SV2.
func serveRigSV2(ctx context.Context, co *coordinator, rigIdx int) error {
	rig := co.cfg.Rigs[rigIdx]
	// switchyard's OWN downstream authority identity -- the key the translator
	// pins to know it reached switchyard. Not the miner's, and not a pool's.
	authority, err := rig.authorityPriv()
	if err != nil {
		return fmt.Errorf("[%s] sv2 listener: %w", co.rigLabel(rigIdx), err)
	}
	// One Noise static key per listener; the certificate over it is minted fresh
	// on each handshake, so its validity window is never a limit.
	static, err := btcec.NewPrivateKey()
	if err != nil {
		return fmt.Errorf("[%s] sv2 listener static key: %w", co.rigLabel(rigIdx), err)
	}

	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", rig.listenAddr())
	if err != nil {
		return fmt.Errorf("listening for %s on %s: %w", co.rigLabel(rigIdx), rig.listenAddr(), err)
	}
	log.Printf("[%s] listening on %s (sv2)", co.rigLabel(rigIdx), rig.listenAddr())

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
		s := newSv2RigSession(co, rigIdx, conn, authority, static)
		go s.run(ctx)
	}
}

// sv2RigSession is one SV2 miner connection: the Noise responder side, bound to
// the mesh's active SV2 link in canonical terms. It is the SV2 counterpart of
// rigSession and implements canonDownstream so the link can push it work.
//
// It binds to the active link of EITHER protocol through the canonical surface:
// an SV2 pool relays its work and shares unchanged, an SV1 pool synthesises an
// sv2Work from its stratum state and translates the share back to a mining.submit
// (upstream.attachCanon/submitCanon). So both bottom-row cells run through this
// one session type, and it rotates and renders like any rig (downstreamSession).
type sv2RigSession struct {
	co        *coordinator
	rigIdx    int
	conn      net.Conn
	authority *btcec.PrivateKey
	static    *btcec.PrivateKey

	ds        *dsConn
	link      poolLink
	cancel    context.CancelFunc
	channelID uint32
	user      string // the miner's own identity, for the dashboard label

	once sync.Once
	done chan struct{}
	// rotated marks a session switchyard closed deliberately to rotate it,
	// read/written under the coordinator's mutex like *rigSession.rotated.
	rotated bool
}

func newSv2RigSession(co *coordinator, rigIdx int, conn net.Conn, authority, static *btcec.PrivateKey) *sv2RigSession {
	return &sv2RigSession{co: co, rigIdx: rigIdx, conn: conn, authority: authority, static: static,
		done: make(chan struct{})}
}

var (
	_ canonDownstream   = (*sv2RigSession)(nil)
	_ downstreamSession = (*sv2RigSession)(nil)
)

// --- downstreamSession: what the coordinator needs to rotate and render it ---

func (s *sv2RigSession) doneChan() <-chan struct{} { return s.done }
func (s *sv2RigSession) label() string             { return s.user }
func (s *sv2RigSession) markRotated()              { s.rotated = true }
func (s *sv2RigSession) rotatedByUs() bool         { return s.rotated }

// boundLink returns the link this session is bound to, or nil. s.link is already
// interface-typed, so an unset value is a true nil poolLink.
func (s *sv2RigSession) boundLink() poolLink { return s.link }

// close is the single teardown primitive, the SV2 mirror of rigSession.close:
// it ends the read loop (cancel + socket close) and signals done exactly once.
// Everything that rotates or drops this session ends up here.
func (s *sv2RigSession) close() {
	s.once.Do(func() {
		close(s.done)
		if s.cancel != nil {
			s.cancel()
		}
		_ = s.conn.Close()
	})
}

// stop is the canonDownstream teardown; it is the same thing as close.
func (s *sv2RigSession) stop() { s.close() }

func (s *sv2RigSession) logf(format string, args ...any) {
	log.Printf("[%s] "+format, append([]any{s.co.rigLabel(s.rigIdx)}, args...)...)
}

func (s *sv2RigSession) run(parent context.Context) {
	ctx, cancel := context.WithCancel(parent)
	s.cancel = cancel
	// close() cancels, drops the socket and signals done; the read loop blocks on
	// the socket, not ctx, so this is what lets a rotation or reload drop it.
	defer s.close()
	context.AfterFunc(ctx, func() { _ = s.conn.Close() })

	tr, err := sv2AcceptResponder(s.conn, s.authority, s.static, sv2DownstreamCertValidity, 10*time.Second)
	if err != nil {
		if ctx.Err() == nil {
			s.logf("sv2 miner handshake failed: %v", err)
		}
		return
	}
	s.ds = &dsConn{conn: s.conn, tr: tr}

	// --- SetupConnection ---
	f, err := tr.ReadFrame(s.conn)
	if err != nil {
		return
	}
	if _, err := common.ParseSetupConnection(f); err != nil {
		s.logf("sv2 miner setup parse: %v", err)
		return
	}
	scs, _ := common.SetupConnectionSuccess{UsedVersion: 2, Flags: 0}.ToFrame()
	if err := s.ds.write(scs); err != nil {
		return
	}

	// --- OpenExtendedMiningChannel (carries the miner's identity) ---
	f, err = tr.ReadFrame(s.conn)
	if err != nil {
		return
	}
	oc, err := mining.ParseOpenExtendedMiningChannel(f)
	if err != nil {
		s.logf("sv2 miner openchannel parse: %v", err)
		return
	}
	// The miner's own identity goes upstream unchanged -- the same promise as the
	// SV1 path. Routed through the SAME roster gate as SV1 (noteAuthorise, not
	// noteCredentials directly): a second miner arriving on a port that already has
	// a live identity must NOT be able to change it or drop everyone for a re-auth
	// -- the money-losing trap documented in CLAUDE.md. For the first/lone miner the
	// gate still sets the identity, which releases this rig's pool links to dial
	// (they wait on credState).
	s.user = oc.UserIdentity
	s.co.noteAuthorise(s.rigIdx, s, oc.UserIdentity, "")
	s.logf("sv2 miner identified as %q", oc.UserIdentity)

	// --- Bind to a ready link for this rig (either protocol, via canonical) ---
	link, ok := s.waitForLink(ctx)
	if !ok {
		return
	}
	work, ok := link.attachCanon(s)
	if !ok {
		s.logf("sv2 link went away during bind; dropping")
		return
	}
	s.link = link
	s.channelID = work.ChannelID
	// Registered with the coordinator exactly like an SV1 session, so a rotation
	// drops it, its reconnect binds to the newly-scheduled pool, and the gap is
	// attributed. detach before clear, matching rigSession.run's teardown.
	s.co.setSession(s.rigIdx, s)
	defer func() {
		link.detachCanon(s)
		s.co.clearSession(s.rigIdx, s)
	}()

	// --- OpenExtendedMiningChannel.Success, mirroring the upstream channel ---
	ocs, err := mining.OpenExtendedMiningChannelSuccess{
		RequestID:        oc.RequestID,
		ChannelID:        work.ChannelID,
		Target:           work.Target,
		ExtranonceSize:   uint16(xbtExtranonceSize),
		ExtranoncePrefix: work.ExtranoncePrefix,
		GroupChannelID:   0,
	}.ToFrame()
	if err != nil {
		return
	}
	if err := s.ds.write(ocs); err != nil {
		return
	}
	s.pushWork(work)
	s.logf("sv2 miner bound to %s", link.displayName())

	// --- Read loop: miner submits -> relay upstream -> ack back by sequence ---
	for {
		f, err := tr.ReadFrame(s.conn)
		if err != nil {
			return
		}
		switch f.MsgType {
		case mining.TypeSubmitSharesExtended:
			sub, err := mining.ParseSubmitSharesExtended(f)
			if err != nil {
				s.logf("sv2 submit parse: %v", err)
				return
			}
			resCh, err := link.submitCanon(sub.JobID, sub.Nonce, sub.Ntime, sub.Extranonce)
			if err != nil {
				_ = sendSubmitError(s.ds, s.channelID, sub.SequenceNumber, err.Error())
				continue
			}
			go s.routeAck(ctx, sub.SequenceNumber, resCh)
		default:
			// SetupConnection errors, pings, etc. -- nothing else to relay.
		}
	}
}

func (s *sv2RigSession) routeAck(ctx context.Context, seq uint32, resCh <-chan sv2SubmitResult) {
	select {
	case r := <-resCh:
		if r.OK {
			_ = sendSubmitSuccess(s.ds, s.channelID, seq)
		} else {
			_ = sendSubmitError(s.ds, s.channelID, seq, r.Code)
		}
	case <-ctx.Done():
	}
}

// pushWork renders a canonical work snapshot onto the SV2 wire for the miner. It
// is the canonDownstream method the bound link calls on each update. (The
// package-level pushWork does the framing; this is the session's own method.)
func (s *sv2RigSession) pushWork(w sv2Work) {
	if s.ds == nil {
		return
	}
	if err := pushWork(s.ds, w); err != nil && s.cancel != nil {
		s.cancel()
	}
}

// waitForLink holds a freshly connected miner until a ready link for its rig
// exists, rather than dropping it into a reconnect loop while the gateway session
// is still coming up. Either pool protocol will do: both implement the canonical
// downstream surface, so an SV2 rig can bind to an SV1 pool (translated) or an
// SV2 pool (relayed) through the same path.
func (s *sv2RigSession) waitForLink(ctx context.Context) (poolLink, bool) {
	t := time.NewTicker(250 * time.Millisecond)
	defer t.Stop()
	deadline := time.Now().Add(30 * time.Second)
	for {
		if l, ok := s.co.upstreamForRig(s.rigIdx); ok {
			return l, true
		}
		if time.Now().After(deadline) {
			s.logf("no pool became ready; dropping (translator will reconnect)")
			return nil, false
		}
		select {
		case <-ctx.Done():
			return nil, false
		case <-t.C:
		}
	}
}
