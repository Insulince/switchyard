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
	"github.com/Insulince/switchyard/sv2/framing"
	"github.com/Insulince/switchyard/sv2/mining"
	"github.com/Insulince/switchyard/sv2/noise"
)

// sv2Proxy is an SV2 -> SV2 pass-through relay: it is the Noise responder to a downstream
// miner (which pins the proxy's authority key) and, per miner, an SV2 initiator to an
// upstream gateway. Because both sides are XBT extended channels, the relay keeps the
// channel/job/extranonce namespaces identical (the gateway's extranonce_prefix is handed
// straight to the miner, so the miner's shares are valid upstream unchanged); the only
// real work is terminating the two independent Noise sessions and routing share acks.
//
// This is the SV2<->SV2 cell of the four-way matrix, exercised end to end. Rotation across
// multiple upstreams (the always-on mesh) is layered on top of this per-connection relay.
type sv2Proxy struct {
	listen       string
	authority    *btcec.PrivateKey // the proxy's authority identity (miners pin its pubkey)
	static       *btcec.PrivateKey // the proxy's Noise static key
	certValidity time.Duration

	gatewayAddr      string
	gatewayAuthority *btcec.PublicKey
	nominal          float32
}

func newSv2Proxy(listen string, authority, static *btcec.PrivateKey, gatewayAddr string, gatewayAuthority *btcec.PublicKey, nominal float32) *sv2Proxy {
	return &sv2Proxy{
		listen:           listen,
		authority:        authority,
		static:           static,
		certValidity:     time.Hour,
		gatewayAddr:      gatewayAddr,
		gatewayAuthority: gatewayAuthority,
		nominal:          nominal,
	}
}

// Serve listens for downstream miners until ctx is cancelled, relaying each to the gateway.
func (p *sv2Proxy) Serve(ctx context.Context) error {
	ln, err := net.Listen("tcp", p.listen)
	if err != nil {
		return err
	}
	context.AfterFunc(ctx, func() { _ = ln.Close() })
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			continue
		}
		go func() {
			if err := p.handleConn(ctx, conn); err != nil && ctx.Err() == nil {
				log.Printf("sv2proxy: miner %s: %v", conn.RemoteAddr(), err)
			}
		}()
	}
}

// dsConn is one downstream miner connection and its write serialisation.
type dsConn struct {
	conn net.Conn
	tr   *noise.Transport
	mu   sync.Mutex
}

func (d *dsConn) write(f framing.Frame) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.tr.WriteFrame(d.conn, f)
}

func (p *sv2Proxy) handleConn(ctx context.Context, conn net.Conn) error {
	defer conn.Close()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	context.AfterFunc(ctx, func() { _ = conn.Close() })

	// --- Noise responder handshake (miner pins our authority key) ---
	tr, err := sv2AcceptResponder(conn, p.authority, p.static, p.certValidity, 10*time.Second)
	if err != nil {
		return fmt.Errorf("responder handshake: %w", err)
	}
	ds := &dsConn{conn: conn, tr: tr}

	// --- SetupConnection ---
	f, err := tr.ReadFrame(conn)
	if err != nil {
		return fmt.Errorf("read setup: %w", err)
	}
	if _, err := common.ParseSetupConnection(f); err != nil {
		return fmt.Errorf("parse setup: %w", err)
	}
	scsFrame, _ := common.SetupConnectionSuccess{UsedVersion: 2, Flags: 0}.ToFrame()
	if err := ds.write(scsFrame); err != nil {
		return err
	}

	// --- OpenExtendedMiningChannel from the miner ---
	f, err = tr.ReadFrame(conn)
	if err != nil {
		return fmt.Errorf("read openchannel: %w", err)
	}
	oc, err := mining.ParseOpenExtendedMiningChannel(f)
	if err != nil {
		return fmt.Errorf("parse openchannel: %w", err)
	}

	// --- Bring up the upstream session to the gateway for this miner ---
	up := newSv2Upstream(p.gatewayAddr, p.gatewayAuthority, oc.UserIdentity, p.nominal)
	firstReady := make(chan sv2Work, 1)
	var pushEnabled bool
	var pushMu sync.Mutex
	up.onUpdate = func(w sv2Work) {
		if !w.Ready {
			return
		}
		select {
		case firstReady <- w:
		default:
		}
		pushMu.Lock()
		en := pushEnabled
		pushMu.Unlock()
		if en {
			if err := pushWork(ds, w); err != nil {
				cancel()
			}
		}
	}
	go func() {
		if err := up.run(ctx); err != nil && ctx.Err() == nil {
			log.Printf("sv2proxy: upstream %s: %v", p.gatewayAddr, err)
			cancel()
		}
	}()

	// Wait for the gateway to hand us an open channel + ready work.
	var w sv2Work
	select {
	case w = <-firstReady:
	case <-time.After(15 * time.Second):
		return fmt.Errorf("upstream not ready")
	case <-ctx.Done():
		return ctx.Err()
	}

	// --- OpenExtendedMiningChannel.Success downstream, mirroring the upstream channel ---
	ocsFrame, err := mining.OpenExtendedMiningChannelSuccess{
		RequestID:        oc.RequestID,
		ChannelID:        w.ChannelID,
		Target:           w.Target,
		ExtranonceSize:   uint16(8),
		ExtranoncePrefix: w.ExtranoncePrefix,
		GroupChannelID:   0,
	}.ToFrame()
	if err != nil {
		return err
	}
	if err := ds.write(ocsFrame); err != nil {
		return err
	}
	// Enable live pushes, then push the current work so the miner starts immediately.
	pushMu.Lock()
	pushEnabled = true
	pushMu.Unlock()
	if err := pushWork(ds, up.snapshot()); err != nil {
		return err
	}

	// --- Downstream read loop: miner submits -> relay upstream -> ack back ---
	for {
		f, err := tr.ReadFrame(conn)
		if err != nil {
			return err
		}
		switch f.MsgType {
		case mining.TypeSubmitSharesExtended:
			sub, err := mining.ParseSubmitSharesExtended(f)
			if err != nil {
				return fmt.Errorf("parse submit: %w", err)
			}
			resCh, err := up.Submit(sub.JobID, sub.Nonce, sub.Ntime, sub.Extranonce)
			if err != nil {
				_ = sendSubmitError(ds, w.ChannelID, sub.SequenceNumber, err.Error())
				continue
			}
			// Route the ack back to the miner using its own sequence number.
			go func(seq uint32) {
				select {
				case r := <-resCh:
					if r.OK {
						_ = sendSubmitSuccess(ds, w.ChannelID, seq)
					} else {
						_ = sendSubmitError(ds, w.ChannelID, seq, r.Code)
					}
				case <-ctx.Done():
				}
			}(sub.SequenceNumber)
		default:
			// ignore other downstream messages
		}
	}
}

// pushWork sends the current XBT work to the miner: a future job, the prev-hash that
// activates it, and the target. Mirrors how the gateway feeds us.
func pushWork(ds *dsConn, w sv2Work) error {
	jobFrame, err := mining.NewExtendedMiningJob{
		ChannelID: w.ChannelID, JobID: w.JobID, NtimeStart: nil, Root: w.Commitment,
	}.ToFrame()
	if err != nil {
		return err
	}
	if err := ds.write(jobFrame); err != nil {
		return err
	}
	prevFrame, err := mining.SetNewPrevHash{
		ChannelID: w.ChannelID, JobID: w.JobID, PrevHash: w.PrevHash, NtimeStart: w.Ntime, Nbits: w.Nbits,
	}.ToFrame()
	if err != nil {
		return err
	}
	if err := ds.write(prevFrame); err != nil {
		return err
	}
	tFrame, err := mining.SetTarget{ChannelID: w.ChannelID, MaximumTarget: w.Target}.ToFrame()
	if err != nil {
		return err
	}
	return ds.write(tFrame)
}

func sendSubmitSuccess(ds *dsConn, channelID, lastSeq uint32) error {
	f, err := mining.SubmitSharesSuccess{ChannelID: channelID, LastSequenceNumber: lastSeq, NewSubmitsAcceptedCount: 1}.ToFrame()
	if err != nil {
		return err
	}
	return ds.write(f)
}

func sendSubmitError(ds *dsConn, channelID, seq uint32, code string) error {
	f, err := mining.SubmitSharesError{ChannelID: channelID, SequenceNumber: seq, ErrorCode: code}.ToFrame()
	if err != nil {
		return err
	}
	return ds.write(f)
}
