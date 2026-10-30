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

// sv2Work is a snapshot of the current XBT work on an upstream extended channel.
type sv2Work struct {
	ChannelID        uint32
	ExtranoncePrefix []byte
	JobID            uint32
	Commitment       [32]byte
	PrevHash         [32]byte
	Ntime            uint64
	Nbits            uint32
	Target           [32]byte
	Clean            bool // the last update was a new block (clean jobs)
	Ready            bool // prevhash + an active job are both known
}

type sv2SubmitResult struct {
	OK   bool
	Code string
}

// sv2Upstream maintains one SV2 extended-channel session to a gateway: the Noise
// handshake (certificate pinned to the gateway's authority key), SetupConnection,
// OpenExtendedMiningChannel, then a read loop tracking jobs / prevhash / target and
// routing share acknowledgements. It is the SV2 analogue of the SV1 upstream.
type sv2Upstream struct {
	addr      string
	authority *btcec.PublicKey
	user      string
	nominal   float32
	onUpdate  func(sv2Work) // invoked (outside the lock) whenever the work changes

	mu       sync.Mutex
	writeMu  sync.Mutex
	conn     net.Conn
	tr       *noise.Transport
	work     sv2Work
	open     bool
	jobNtime map[uint32]*uint64  // jobID -> its own ntime_start (nil for a future job)
	jobComm  map[uint32][32]byte // jobID -> commitment
	seq      uint32
	pending  map[uint32]chan sv2SubmitResult // seq -> result waiter
}

func newSv2Upstream(addr string, authority *btcec.PublicKey, user string, nominal float32) *sv2Upstream {
	return &sv2Upstream{
		addr:      addr,
		authority: authority,
		user:      user,
		nominal:   nominal,
		jobNtime:  map[uint32]*uint64{},
		jobComm:   map[uint32][32]byte{},
		pending:   map[uint32]chan sv2SubmitResult{},
	}
}

// snapshot returns the current work under the lock.
func (u *sv2Upstream) snapshot() sv2Work {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.work
}

// closeConn drops the underlying socket so a caller's run loop returns and
// reconnects. Used by sv2Link.dropForReauth, the SV2 analogue of
// upstream.dropForReauth: stratum-v2 cannot change the channel's user_identity
// in place, so a miner arriving under a new name requires a fresh channel.
func (u *sv2Upstream) closeConn() {
	u.mu.Lock()
	conn := u.conn
	u.mu.Unlock()
	if conn != nil {
		_ = conn.Close()
	}
}

// Submit sends a SubmitSharesExtended upstream for the given job and returns a channel
// that receives the gateway's accept/reject for this share. jobID is the SV2 job id.
func (u *sv2Upstream) Submit(jobID uint32, nonce, ntime uint64, extranonce []byte) (<-chan sv2SubmitResult, error) {
	u.mu.Lock()
	if !u.open {
		u.mu.Unlock()
		return nil, fmt.Errorf("sv2upstream: channel not open")
	}
	u.seq++
	seq := u.seq
	ch := make(chan sv2SubmitResult, 1)
	u.pending[seq] = ch
	channelID := u.work.ChannelID
	u.mu.Unlock()

	f, err := mining.SubmitSharesExtended{
		ChannelID:      channelID,
		SequenceNumber: seq,
		JobID:          jobID,
		Nonce:          nonce,
		Ntime:          ntime,
		Extranonce:     extranonce,
	}.ToFrame()
	if err != nil {
		u.resolve(seq, sv2SubmitResult{OK: false, Code: err.Error()})
		return ch, err
	}
	u.writeMu.Lock()
	err = u.tr.WriteFrame(u.conn, f)
	u.writeMu.Unlock()
	if err != nil {
		u.resolve(seq, sv2SubmitResult{OK: false, Code: err.Error()})
		return ch, err
	}
	return ch, nil
}

func (u *sv2Upstream) resolve(seq uint32, r sv2SubmitResult) {
	u.mu.Lock()
	ch := u.pending[seq]
	delete(u.pending, seq)
	u.mu.Unlock()
	if ch != nil {
		ch <- r
	}
}

// failAllPending releases every in-flight share waiter with a failure, used when
// the socket drops so no caller blocks forever on an ack that can never come.
func (u *sv2Upstream) failAllPending(code string) {
	u.mu.Lock()
	chans := make([]chan sv2SubmitResult, 0, len(u.pending))
	for seq, ch := range u.pending {
		chans = append(chans, ch)
		delete(u.pending, seq)
	}
	u.mu.Unlock()
	for _, ch := range chans {
		ch <- sv2SubmitResult{OK: false, Code: code}
	}
}

// run connects once and serves until the connection drops or ctx is cancelled. The
// caller is responsible for reconnect/backoff (runForever does that).
func (u *sv2Upstream) run(ctx context.Context) error {
	conn, tr, err := sv2DialInitiator(u.addr, u.authority, 10*time.Second)
	if err != nil {
		return fmt.Errorf("handshake: %w", err)
	}
	// Close the socket on cancel; the read loop blocks on the socket, not ctx.
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	defer conn.Close()

	u.mu.Lock()
	u.conn, u.tr = conn, tr
	u.mu.Unlock()

	// SetupConnection (Mining protocol, v2).
	scFrame, err := common.SetupConnection{
		Protocol: 0, MinVersion: 2, MaxVersion: 2, Flags: 0,
		EndpointHost: "x", EndpointPort: 0, Vendor: "switchyard",
	}.ToFrame()
	if err != nil {
		return err
	}
	if err := u.writeFrame(scFrame); err != nil {
		return err
	}
	f, err := tr.ReadFrame(conn)
	if err != nil {
		return fmt.Errorf("read setup reply: %w", err)
	}
	if f.MsgType == common.TypeSetupConnectionError {
		e, _ := common.ParseSetupConnectionError(f)
		return fmt.Errorf("SetupConnection.Error: %s", e.ErrorCode)
	}
	if _, err := common.ParseSetupConnectionSuccess(f); err != nil {
		return fmt.Errorf("setup success: %w", err)
	}

	// OpenExtendedMiningChannel.
	var maxT [32]byte
	for i := range maxT {
		maxT[i] = 0xff
	}
	ocFrame, err := mining.OpenExtendedMiningChannel{
		RequestID: 1, UserIdentity: u.user, NominalHashRate: u.nominal, MaxTarget: maxT, MinExtranonceSize: 8,
	}.ToFrame()
	if err != nil {
		return err
	}
	if err := u.writeFrame(ocFrame); err != nil {
		return err
	}

	return u.readLoop(conn, tr)
}

// writeFrame serialises a frame onto the transport under the write mutex. Reads happen
// only in the run loop and writes only here, so the two Noise cipher directions never race.
func (u *sv2Upstream) writeFrame(f framing.Frame) error {
	u.writeMu.Lock()
	defer u.writeMu.Unlock()
	return u.tr.WriteFrame(u.conn, f)
}

func (u *sv2Upstream) readLoop(conn net.Conn, tr *noise.Transport) error {
	for {
		f, err := tr.ReadFrame(conn)
		if err != nil {
			u.mu.Lock()
			u.open = false
			u.mu.Unlock()
			// A dropped socket leaves every in-flight share unanswered. Fail them
			// so each submit's waiter is released rather than blocking forever --
			// a share in flight when the gateway vanished is lost, not accepted.
			u.failAllPending(err.Error())
			return err
		}
		switch f.MsgType {
		case mining.TypeOpenExtendedMiningChannelSuccess:
			s, err := mining.ParseOpenExtendedMiningChannelSuccess(f)
			if err != nil {
				return fmt.Errorf("open success: %w", err)
			}
			u.mu.Lock()
			u.work.ChannelID = s.ChannelID
			u.work.ExtranoncePrefix = s.ExtranoncePrefix
			u.work.Target = s.Target
			u.open = true
			u.mu.Unlock()
		case mining.TypeOpenMiningChannelError:
			e, _ := mining.ParseOpenMiningChannelError(f)
			return fmt.Errorf("OpenMiningChannel.Error: %s", e.ErrorCode)
		case mining.TypeNewExtendedMiningJob:
			j, err := mining.ParseNewExtendedMiningJob(f)
			if err != nil {
				return fmt.Errorf("new job: %w", err)
			}
			u.applyJob(j)
		case mining.TypeSetNewPrevHash:
			p, err := mining.ParseSetNewPrevHash(f)
			if err != nil {
				return fmt.Errorf("set prevhash: %w", err)
			}
			u.applyPrevHash(p)
		case mining.TypeSetTarget:
			s, err := mining.ParseSetTarget(f)
			if err != nil {
				return fmt.Errorf("set target: %w", err)
			}
			u.mu.Lock()
			u.work.Target = s.MaximumTarget
			w := u.work
			u.mu.Unlock()
			u.fire(w)
		case mining.TypeSubmitSharesSuccess:
			s, _ := mining.ParseSubmitSharesSuccess(f)
			u.resolveUpTo(s.LastSequenceNumber)
		case mining.TypeSubmitSharesError:
			s, _ := mining.ParseSubmitSharesError(f)
			// The SV2 upstream has no accepted/rejected accounting of its own
			// (unlike the SV1 upstream), so the pool's own reason for a reject is
			// otherwise invisible: it is relayed straight back to the miner and
			// never seen here. Surface it -- a target/difficulty mismatch, a stale
			// share and a bad job id all reject, and only the code tells them apart.
			log.Printf("sv2upstream %s (user=%s): share REJECTED seq=%d code=%q",
				u.addr, u.user, s.SequenceNumber, s.ErrorCode)
			u.resolve(s.SequenceNumber, sv2SubmitResult{OK: false, Code: s.ErrorCode})
		default:
			// ignore unknown message types
		}
	}
}

func (u *sv2Upstream) applyJob(j mining.NewExtendedMiningJob) {
	u.mu.Lock()
	u.jobNtime[j.JobID] = j.NtimeStart
	u.jobComm[j.JobID] = j.Root
	var fire bool
	var w sv2Work
	if j.NtimeStart != nil {
		// A job carrying its own ntime is immediately active on the current prevhash.
		u.work.JobID = j.JobID
		u.work.Commitment = j.Root
		u.work.Ntime = *j.NtimeStart
		u.work.Clean = false
		u.work.Ready = u.work.PrevHash != [32]byte{} || u.work.Ready
		w = u.work
		fire = u.work.Ready
	}
	u.mu.Unlock()
	if fire {
		u.fire(w)
	}
}

func (u *sv2Upstream) applyPrevHash(p mining.SetNewPrevHash) {
	u.mu.Lock()
	u.work.PrevHash = p.PrevHash
	u.work.Nbits = p.Nbits
	u.work.JobID = p.JobID
	u.work.Commitment = u.jobComm[p.JobID]
	u.work.Ntime = p.NtimeStart
	u.work.Clean = true
	u.work.Ready = true
	w := u.work
	u.mu.Unlock()
	u.fire(w)
}

func (u *sv2Upstream) fire(w sv2Work) {
	if u.onUpdate != nil {
		u.onUpdate(w)
	}
}

func (u *sv2Upstream) resolveUpTo(last uint32) {
	u.mu.Lock()
	var seqs []uint32
	for s := range u.pending {
		if s <= last {
			seqs = append(seqs, s)
		}
	}
	chans := make([]chan sv2SubmitResult, 0, len(seqs))
	for _, s := range seqs {
		chans = append(chans, u.pending[s])
		delete(u.pending, s)
	}
	u.mu.Unlock()
	for _, ch := range chans {
		ch <- sv2SubmitResult{OK: true}
	}
}
