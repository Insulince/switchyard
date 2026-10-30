// Package mining implements the XBT (BLAKE2b) variant of the SV2 Mining Protocol
// messages switchyard exchanges as an extended-channel client (upstream, to a DATUM
// gateway) and as a responder (downstream, to a miner).
//
// Layouts follow the XBT wire format, not the SHA256 one: U64 nonce and ntime,
// OPTION[U64] ntime_start, a 32-byte coinbase commitment as the extended-channel job
// "root", and no version field. XBT is header-v2: the block timestamp is folded into
// the commitment, so the on-wire ntime is a time-offset that is zero when the miner
// does not roll time. Only the extended channel is implemented (standard channels do
// not map to an SV1 miner's extranonce rolling).
package mining

import (
	"fmt"

	"github.com/Insulince/switchyard/sv2/framing"
	"github.com/Insulince/switchyard/sv2/types"
)

// Mining Protocol message types (sub-protocol 0). These match the SV2 spec and the
// CONVOY gateway's wire values.
const (
	TypeOpenExtendedMiningChannel        uint8 = 0x13
	TypeOpenExtendedMiningChannelSuccess uint8 = 0x14
	TypeOpenMiningChannelError           uint8 = 0x12
	TypeNewExtendedMiningJob             uint8 = 0x1f
	TypeSetNewPrevHash                   uint8 = 0x20
	TypeSetTarget                        uint8 = 0x21
	TypeSubmitSharesExtended             uint8 = 0x1b
	TypeSubmitSharesSuccess              uint8 = 0x1c
	TypeSubmitSharesError                uint8 = 0x1d
)

func frame(msgType uint8, channel bool, e *types.Encoder) framing.Frame {
	return framing.Frame{ChannelMsg: channel, MsgType: msgType, Payload: e.Bytes()}
}

func expectType(f framing.Frame, want uint8) error {
	if f.MsgType != want {
		return fmt.Errorf("sv2/mining: want msg type %#x, got %#x", want, f.MsgType)
	}
	return nil
}

// Coinb1 builds the SV1 "coinb1" for an XBT extended channel so that the SV1 miner's
// merkle root, BLAKE2b-256(0x00 || coinb1 || en1 || en2) with en1 = the 4-byte
// extranonce_prefix, is byte-identical to the SV2 extended leaf,
// BLAKE2b-256(0x00000000 || commitment || 0x00000000 || extranonce_prefix || extranonce).
// coinb1 = 0x000000 || commitment(32) || 0x00000000 (39 bytes); prepending the single
// 0x00 of the SV1 leaf makes the leading run four zero bytes, matching the SV2 leaf.
func Coinb1(commitment [32]byte) []byte {
	out := make([]byte, 0, 39)
	out = append(out, 0, 0, 0)
	out = append(out, commitment[:]...)
	out = append(out, 0, 0, 0, 0)
	return out
}

// --- OpenExtendedMiningChannel (Client -> Server) ---

type OpenExtendedMiningChannel struct {
	RequestID         uint32
	UserIdentity      string
	NominalHashRate   float32
	MaxTarget         [32]byte
	MinExtranonceSize uint16
}

func (m OpenExtendedMiningChannel) ToFrame() (framing.Frame, error) {
	e := types.NewEncoder()
	e.PutU32(m.RequestID)
	if err := e.PutStr0_255(m.UserIdentity); err != nil {
		return framing.Frame{}, fmt.Errorf("user_identity: %w", err)
	}
	e.PutF32(m.NominalHashRate)
	e.PutU256(m.MaxTarget)
	e.PutU16(m.MinExtranonceSize)
	return frame(TypeOpenExtendedMiningChannel, false, e), nil
}

func ParseOpenExtendedMiningChannel(f framing.Frame) (OpenExtendedMiningChannel, error) {
	var m OpenExtendedMiningChannel
	if err := expectType(f, TypeOpenExtendedMiningChannel); err != nil {
		return m, err
	}
	d := types.NewDecoder(f.Payload)
	var err error
	if m.RequestID, err = d.U32(); err != nil {
		return m, err
	}
	if m.UserIdentity, err = d.Str0_255(); err != nil {
		return m, err
	}
	if m.NominalHashRate, err = d.F32(); err != nil {
		return m, err
	}
	if m.MaxTarget, err = d.U256(); err != nil {
		return m, err
	}
	if m.MinExtranonceSize, err = d.U16(); err != nil {
		return m, err
	}
	return m, nil
}

// --- OpenExtendedMiningChannel.Success (Server -> Client) ---

type OpenExtendedMiningChannelSuccess struct {
	RequestID        uint32
	ChannelID        uint32
	Target           [32]byte
	ExtranonceSize   uint16
	ExtranoncePrefix []byte
	GroupChannelID   uint32
}

func (m OpenExtendedMiningChannelSuccess) ToFrame() (framing.Frame, error) {
	e := types.NewEncoder()
	e.PutU32(m.RequestID)
	e.PutU32(m.ChannelID)
	e.PutU256(m.Target)
	e.PutU16(m.ExtranonceSize)
	if err := e.PutB0_32(m.ExtranoncePrefix); err != nil {
		return framing.Frame{}, fmt.Errorf("extranonce_prefix: %w", err)
	}
	e.PutU32(m.GroupChannelID)
	return frame(TypeOpenExtendedMiningChannelSuccess, false, e), nil
}

func ParseOpenExtendedMiningChannelSuccess(f framing.Frame) (OpenExtendedMiningChannelSuccess, error) {
	var m OpenExtendedMiningChannelSuccess
	if err := expectType(f, TypeOpenExtendedMiningChannelSuccess); err != nil {
		return m, err
	}
	d := types.NewDecoder(f.Payload)
	var err error
	if m.RequestID, err = d.U32(); err != nil {
		return m, err
	}
	if m.ChannelID, err = d.U32(); err != nil {
		return m, err
	}
	if m.Target, err = d.U256(); err != nil {
		return m, err
	}
	if m.ExtranonceSize, err = d.U16(); err != nil {
		return m, err
	}
	if m.ExtranoncePrefix, err = d.B0_32(); err != nil {
		return m, err
	}
	if m.GroupChannelID, err = d.U32(); err != nil {
		return m, err
	}
	return m, nil
}

// --- OpenMiningChannel.Error (Server -> Client) ---

type OpenMiningChannelError struct {
	RequestID uint32
	ErrorCode string
}

func (m OpenMiningChannelError) ToFrame() (framing.Frame, error) {
	e := types.NewEncoder()
	e.PutU32(m.RequestID)
	if err := e.PutStr0_255(m.ErrorCode); err != nil {
		return framing.Frame{}, fmt.Errorf("error_code: %w", err)
	}
	return frame(TypeOpenMiningChannelError, false, e), nil
}

func ParseOpenMiningChannelError(f framing.Frame) (OpenMiningChannelError, error) {
	var m OpenMiningChannelError
	if err := expectType(f, TypeOpenMiningChannelError); err != nil {
		return m, err
	}
	d := types.NewDecoder(f.Payload)
	var err error
	if m.RequestID, err = d.U32(); err != nil {
		return m, err
	}
	if m.ErrorCode, err = d.Str0_255(); err != nil {
		return m, err
	}
	return m, nil
}

// --- NewExtendedMiningJob (Server -> Client), XBT layout ---
//
// On an extended channel Root is the 32-byte coinbase commitment (not a final merkle
// root). NtimeStart is OPTION[U64]: nil means a future job whose time arrives with
// SetNewPrevHash; a present value means the job is immediately active.
type NewExtendedMiningJob struct {
	ChannelID  uint32
	JobID      uint32
	NtimeStart *uint64
	Root       [32]byte
}

func (m NewExtendedMiningJob) ToFrame() (framing.Frame, error) {
	e := types.NewEncoder()
	e.PutU32(m.ChannelID)
	e.PutU32(m.JobID)
	if m.NtimeStart != nil {
		e.PutU8(1)
		e.PutU64(*m.NtimeStart)
	} else {
		e.PutU8(0)
	}
	e.PutU256(m.Root)
	return frame(TypeNewExtendedMiningJob, true, e), nil
}

func ParseNewExtendedMiningJob(f framing.Frame) (NewExtendedMiningJob, error) {
	var m NewExtendedMiningJob
	if err := expectType(f, TypeNewExtendedMiningJob); err != nil {
		return m, err
	}
	d := types.NewDecoder(f.Payload)
	var err error
	if m.ChannelID, err = d.U32(); err != nil {
		return m, err
	}
	if m.JobID, err = d.U32(); err != nil {
		return m, err
	}
	has, err := d.U8()
	if err != nil {
		return m, err
	}
	if has != 0 {
		v, err := d.U64()
		if err != nil {
			return m, err
		}
		m.NtimeStart = &v
	}
	if m.Root, err = d.U256(); err != nil {
		return m, err
	}
	return m, nil
}

// --- SetNewPrevHash (Server -> Client), XBT layout ---

type SetNewPrevHash struct {
	ChannelID  uint32
	JobID      uint32
	PrevHash   [32]byte
	NtimeStart uint64
	Nbits      uint32
}

func (m SetNewPrevHash) ToFrame() (framing.Frame, error) {
	e := types.NewEncoder()
	e.PutU32(m.ChannelID)
	e.PutU32(m.JobID)
	e.PutU256(m.PrevHash)
	e.PutU64(m.NtimeStart)
	e.PutU32(m.Nbits)
	return frame(TypeSetNewPrevHash, true, e), nil
}

func ParseSetNewPrevHash(f framing.Frame) (SetNewPrevHash, error) {
	var m SetNewPrevHash
	if err := expectType(f, TypeSetNewPrevHash); err != nil {
		return m, err
	}
	d := types.NewDecoder(f.Payload)
	var err error
	if m.ChannelID, err = d.U32(); err != nil {
		return m, err
	}
	if m.JobID, err = d.U32(); err != nil {
		return m, err
	}
	if m.PrevHash, err = d.U256(); err != nil {
		return m, err
	}
	if m.NtimeStart, err = d.U64(); err != nil {
		return m, err
	}
	if m.Nbits, err = d.U32(); err != nil {
		return m, err
	}
	return m, nil
}

// --- SetTarget (Server -> Client) ---

type SetTarget struct {
	ChannelID     uint32
	MaximumTarget [32]byte
}

func (m SetTarget) ToFrame() (framing.Frame, error) {
	e := types.NewEncoder()
	e.PutU32(m.ChannelID)
	e.PutU256(m.MaximumTarget)
	return frame(TypeSetTarget, true, e), nil
}

func ParseSetTarget(f framing.Frame) (SetTarget, error) {
	var m SetTarget
	if err := expectType(f, TypeSetTarget); err != nil {
		return m, err
	}
	d := types.NewDecoder(f.Payload)
	var err error
	if m.ChannelID, err = d.U32(); err != nil {
		return m, err
	}
	if m.MaximumTarget, err = d.U256(); err != nil {
		return m, err
	}
	return m, nil
}

// --- SubmitSharesExtended (Client -> Server), XBT layout ---

type SubmitSharesExtended struct {
	ChannelID      uint32
	SequenceNumber uint32
	JobID          uint32
	Nonce          uint64
	Ntime          uint64
	Extranonce     []byte
}

func (m SubmitSharesExtended) ToFrame() (framing.Frame, error) {
	e := types.NewEncoder()
	e.PutU32(m.ChannelID)
	e.PutU32(m.SequenceNumber)
	e.PutU32(m.JobID)
	e.PutU64(m.Nonce)
	e.PutU64(m.Ntime)
	if err := e.PutB0_32(m.Extranonce); err != nil {
		return framing.Frame{}, fmt.Errorf("extranonce: %w", err)
	}
	return frame(TypeSubmitSharesExtended, true, e), nil
}

func ParseSubmitSharesExtended(f framing.Frame) (SubmitSharesExtended, error) {
	var m SubmitSharesExtended
	if err := expectType(f, TypeSubmitSharesExtended); err != nil {
		return m, err
	}
	d := types.NewDecoder(f.Payload)
	var err error
	if m.ChannelID, err = d.U32(); err != nil {
		return m, err
	}
	if m.SequenceNumber, err = d.U32(); err != nil {
		return m, err
	}
	if m.JobID, err = d.U32(); err != nil {
		return m, err
	}
	if m.Nonce, err = d.U64(); err != nil {
		return m, err
	}
	if m.Ntime, err = d.U64(); err != nil {
		return m, err
	}
	if m.Extranonce, err = d.B0_32(); err != nil {
		return m, err
	}
	return m, nil
}

// --- SubmitShares.Success (Server -> Client) ---

type SubmitSharesSuccess struct {
	ChannelID               uint32
	LastSequenceNumber      uint32
	NewSubmitsAcceptedCount uint32
	NewSharesSum            uint64
}

func (m SubmitSharesSuccess) ToFrame() (framing.Frame, error) {
	e := types.NewEncoder()
	e.PutU32(m.ChannelID)
	e.PutU32(m.LastSequenceNumber)
	e.PutU32(m.NewSubmitsAcceptedCount)
	e.PutU64(m.NewSharesSum)
	return frame(TypeSubmitSharesSuccess, true, e), nil
}

func ParseSubmitSharesSuccess(f framing.Frame) (SubmitSharesSuccess, error) {
	var m SubmitSharesSuccess
	if err := expectType(f, TypeSubmitSharesSuccess); err != nil {
		return m, err
	}
	d := types.NewDecoder(f.Payload)
	var err error
	if m.ChannelID, err = d.U32(); err != nil {
		return m, err
	}
	if m.LastSequenceNumber, err = d.U32(); err != nil {
		return m, err
	}
	if m.NewSubmitsAcceptedCount, err = d.U32(); err != nil {
		return m, err
	}
	if m.NewSharesSum, err = d.U64(); err != nil {
		return m, err
	}
	return m, nil
}

// --- SubmitShares.Error (Server -> Client) ---

type SubmitSharesError struct {
	ChannelID      uint32
	SequenceNumber uint32
	ErrorCode      string
}

func (m SubmitSharesError) ToFrame() (framing.Frame, error) {
	e := types.NewEncoder()
	e.PutU32(m.ChannelID)
	e.PutU32(m.SequenceNumber)
	if err := e.PutStr0_255(m.ErrorCode); err != nil {
		return framing.Frame{}, fmt.Errorf("error_code: %w", err)
	}
	return frame(TypeSubmitSharesError, true, e), nil
}

func ParseSubmitSharesError(f framing.Frame) (SubmitSharesError, error) {
	var m SubmitSharesError
	if err := expectType(f, TypeSubmitSharesError); err != nil {
		return m, err
	}
	d := types.NewDecoder(f.Payload)
	var err error
	if m.ChannelID, err = d.U32(); err != nil {
		return m, err
	}
	if m.SequenceNumber, err = d.U32(); err != nil {
		return m, err
	}
	if m.ErrorCode, err = d.Str0_255(); err != nil {
		return m, err
	}
	return m, nil
}
