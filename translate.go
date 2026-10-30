package main

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/Insulince/switchyard/sv2/mining"
)

// This file is the protocol-neutral middle of switchyard's SV1/SV2 translation.
// Every upstream (SV1 or SV2) converts the work it receives into a canonJob and a
// returning share back from a canonShare; every downstream renders a canonJob onto
// its own wire and parses its own wire's submits into a canonShare. With a neutral
// middle, the four cells of the rig×gateway matrix need two converters per side,
// not one bespoke relay per pair.
//
// It is commitment-centric because XBT (BLAKE2b) is header-v2: the whole
// transaction tree is folded into a single 32-byte commitment, so SV1 and SV2
// carry the SAME work and translating between them is a repackaging, not a
// reconstruction. This was verified against a live gateway -- an XBT SV1
// mining.notify ships coinb1 = 0x000000 || commitment || 0x00000000, with an empty
// coinb2 and empty merkle branch -- so the commitment sits at coinb1[3:35] and
// sv2/mining.Coinb1 writes it back. The root-equivalence proof (translate_test.go,
// and sv2/mining) then guarantees a share valid on one wire is valid on the other.

// xbtVersion is the XBT header-v2 block version, as it appears in an XBT SV1
// mining.notify ("a0000000"). SV2 extended work carries no version field -- the
// value is implied by the chain -- so this is what a job translated FROM SV2 uses
// when it must be rendered back onto an SV1 wire.
const xbtVersion uint32 = 0xa0000000

// xbtExtranonceSize is the extranonce2 size an XBT gateway hands out (8 bytes),
// of which switchyard keeps 0 in the one-miner-per-port case. SV1 reports it in
// the subscribe result; SV2 reports it in OpenExtendedMiningChannel.Success. It is
// named here as the default for a job built from a source that did not carry it.
const xbtExtranonceSize = 8

// canonJob is one unit of mineable XBT work, protocol-neutral.
type canonJob struct {
	PrevHash         [32]byte
	Commitment       [32]byte
	Ntime            uint64 // XBT time-offset; 0 unless the miner rolls time
	Nbits            uint32
	Version          uint32 // xbtVersion; carried so an SV1 wire can be rendered
	ExtranoncePrefix []byte // SV1 extranonce1 == SV2 extranonce_prefix (4 bytes)
	ExtranonceSize   int    // SV1 extranonce2_size == SV2 extranonce size
	Clean            bool
}

// canonShare is one share a miner submitted, protocol-neutral. Extranonce is the
// miner's own roll (SV1 extranonce2 == SV2 extranonce); any per-miner prefix byte
// switchyard inserts for multi-miner ports is re-added at the upstream, not here.
type canonShare struct {
	Nonce      uint64
	Ntime      uint64
	Extranonce []byte
}

// commitmentFromSV1Coinb1 pulls the 32-byte XBT commitment out of the coinb1 an
// XBT SV1 gateway sends. XBT's coinbase is branch-free and fixed-form -- coinb1 is
// exactly Coinb1(commitment) = 0x000000 || commitment || 0x00000000 -- so the
// commitment is the middle 32 bytes. Anything that is not that shape is not XBT
// SV1 work this can translate, and is rejected rather than guessed at (a wrong
// commitment mines the wrong block and every share is rejected).
func commitmentFromSV1Coinb1(coinb1 []byte) ([32]byte, error) {
	var c [32]byte
	if len(coinb1) != 39 {
		return c, fmt.Errorf("coinb1 is %d bytes, want 39 (XBT 0x000000||commitment||0x00000000)", len(coinb1))
	}
	for i := 0; i < 3; i++ {
		if coinb1[i] != 0 {
			return c, fmt.Errorf("coinb1[%d]=%#x, want 0 (not XBT fixed-form coinbase)", i, coinb1[i])
		}
	}
	for i := 35; i < 39; i++ {
		if coinb1[i] != 0 {
			return c, fmt.Errorf("coinb1[%d]=%#x, want 0 (not XBT fixed-form coinbase)", i, coinb1[i])
		}
	}
	copy(c[:], coinb1[3:35])
	return c, nil
}

// --- SV1 upstream/downstream <-> canonJob ---

// sv1NotifyToJob parses an XBT SV1 mining.notify into a canonJob. The extranonce
// prefix and size are not in the notify -- they come from the subscribe result --
// so the caller passes them in. Returns the gateway's own job id (an opaque SV1
// string) alongside, which the share path needs to address a submit back upstream.
func sv1NotifyToJob(params json.RawMessage, en1 []byte, en2size int) (jobID string, j canonJob, err error) {
	var p []json.RawMessage
	if err = json.Unmarshal(params, &p); err != nil {
		return "", j, fmt.Errorf("notify params: %w", err)
	}
	// [job_id, prevhash, coinb1, coinb2, merkle_branch, version, nbits, ntime, clean]
	if len(p) < 9 {
		return "", j, fmt.Errorf("notify has %d params, want 9", len(p))
	}
	if err = json.Unmarshal(p[0], &jobID); err != nil {
		return "", j, fmt.Errorf("job_id: %w", err)
	}
	if j.PrevHash, err = hexToArr32(p[1]); err != nil {
		return "", j, fmt.Errorf("prevhash: %w", err)
	}
	coinb1, err := hexBytes(p[2])
	if err != nil {
		return "", j, fmt.Errorf("coinb1: %w", err)
	}
	if j.Commitment, err = commitmentFromSV1Coinb1(coinb1); err != nil {
		return "", j, err
	}
	// XBT's coinbase is branch-free; a non-empty coinb2 or merkle branch would
	// mean this is not work this translator understands, so refuse rather than
	// silently drop it.
	if cb2, e := hexBytes(p[3]); e == nil && len(cb2) != 0 {
		return "", j, fmt.Errorf("coinb2 is %d bytes, want empty for XBT", len(cb2))
	}
	var branch []json.RawMessage
	if e := json.Unmarshal(p[4], &branch); e == nil && len(branch) != 0 {
		return "", j, fmt.Errorf("merkle_branch has %d entries, want empty for XBT", len(branch))
	}
	if j.Version, err = hexToU32(p[5]); err != nil {
		return "", j, fmt.Errorf("version: %w", err)
	}
	if j.Nbits, err = hexToU32(p[6]); err != nil {
		return "", j, fmt.Errorf("nbits: %w", err)
	}
	if j.Ntime, err = hexToU64(p[7]); err != nil {
		return "", j, fmt.Errorf("ntime: %w", err)
	}
	if err = json.Unmarshal(p[8], &j.Clean); err != nil {
		return "", j, fmt.Errorf("clean_jobs: %w", err)
	}
	j.ExtranoncePrefix = append([]byte(nil), en1...)
	j.ExtranonceSize = en2size
	return jobID, j, nil
}

// jobToSV1NotifyParams renders a canonJob as the params array of an XBT SV1
// mining.notify. The downstream-facing job id is supplied by the caller (switchyard
// assigns it; it need not match any upstream's). coinb2 and the merkle branch are
// empty by construction, and coinb1 is Coinb1(commitment).
func jobToSV1NotifyParams(jobID string, j canonJob) (json.RawMessage, error) {
	coinb1 := mining.Coinb1(j.Commitment)
	arr := []any{
		jobID,
		hex.EncodeToString(j.PrevHash[:]),
		hex.EncodeToString(coinb1),
		"",
		[]any{},
		u32Hex(j.Version),
		u32Hex(j.Nbits),
		u64Hex(j.Ntime),
		j.Clean,
	}
	return json.Marshal(arr)
}

// --- SV2 upstream work <-> canonJob ---

// sv2WorkToJob converts the snapshot an sv2Upstream tracks into a canonJob. SV2
// carries no version, so the XBT constant is used.
func sv2WorkToJob(w sv2Work) canonJob {
	size := xbtExtranonceSize
	return canonJob{
		PrevHash:         w.PrevHash,
		Commitment:       w.Commitment,
		Ntime:            w.Ntime,
		Nbits:            w.Nbits,
		Version:          xbtVersion,
		ExtranoncePrefix: append([]byte(nil), w.ExtranoncePrefix...),
		ExtranonceSize:   size,
		Clean:            w.Clean,
	}
}

// --- shares ---

// sv1SubmitToShare parses an XBT SV1 mining.submit's params into a canonShare.
// Params are [worker, job_id, extranonce2, ntime, nonce], all after the first two
// as hex. Returns the SV1 job id the share names so the caller can map it to the
// upstream it must go to.
func sv1SubmitToShare(params json.RawMessage) (jobID string, s canonShare, err error) {
	var p []json.RawMessage
	if err = json.Unmarshal(params, &p); err != nil {
		return "", s, fmt.Errorf("submit params: %w", err)
	}
	if len(p) < 5 {
		return "", s, fmt.Errorf("submit has %d params, want 5", len(p))
	}
	if err = json.Unmarshal(p[1], &jobID); err != nil {
		return "", s, fmt.Errorf("job_id: %w", err)
	}
	if s.Extranonce, err = hexBytes(p[2]); err != nil {
		return "", s, fmt.Errorf("extranonce2: %w", err)
	}
	if s.Ntime, err = hexToU64(p[3]); err != nil {
		return "", s, fmt.Errorf("ntime: %w", err)
	}
	if s.Nonce, err = hexToU64(p[4]); err != nil {
		return "", s, fmt.Errorf("nonce: %w", err)
	}
	return jobID, s, nil
}

// shareToSV1SubmitParams renders a canonShare as an XBT SV1 mining.submit params
// array for the given worker and upstream job id.
func shareToSV1SubmitParams(worker, jobID string, s canonShare) (json.RawMessage, error) {
	arr := []any{
		worker,
		jobID,
		hex.EncodeToString(s.Extranonce),
		u64Hex(s.Ntime),
		u64Hex(s.Nonce),
	}
	return json.Marshal(arr)
}

// sv2SubmitToShare converts an SV2 SubmitSharesExtended into a canonShare.
func sv2SubmitToShare(m mining.SubmitSharesExtended) canonShare {
	return canonShare{
		Nonce:      m.Nonce,
		Ntime:      m.Ntime,
		Extranonce: append([]byte(nil), m.Extranonce...),
	}
}

// shareToSV2Submit renders a canonShare as a SubmitSharesExtended for the given
// channel, sequence and upstream job id.
func shareToSV2Submit(channelID, seq, jobID uint32, s canonShare) mining.SubmitSharesExtended {
	return mining.SubmitSharesExtended{
		ChannelID:      channelID,
		SequenceNumber: seq,
		JobID:          jobID,
		Nonce:          s.Nonce,
		Ntime:          s.Ntime,
		Extranonce:     append([]byte(nil), s.Extranonce...),
	}
}

// --- hex helpers ---
//
// The 32-bit fields (version) are big-endian hex. The 64-bit share fields -- nonce
// and ntime -- are LITTLE-endian hex: XBT's BLAKE2b work preimage serialises them
// with pk_u64le, so the wire bytes ARE the little-endian u64. Parse and emit are
// symmetric, so a same-protocol path round-trips a field's bytes unchanged no
// matter which endianness is used -- which is why a wrong choice here stayed
// invisible until a share crossed SV1<->SV2, where one side parses and the other
// emits. Big-endian here reversed nonce/ntime on every crossed share and the pool
// rejected all of them difficulty-too-low -- the bug a live run caught.

func unquote(raw json.RawMessage) (string, error) {
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", err
	}
	return s, nil
}

func hexBytes(raw json.RawMessage) ([]byte, error) {
	s, err := unquote(raw)
	if err != nil {
		return nil, err
	}
	return hex.DecodeString(s)
}

func hexToArr32(raw json.RawMessage) ([32]byte, error) {
	var a [32]byte
	b, err := hexBytes(raw)
	if err != nil {
		return a, err
	}
	if len(b) != 32 {
		return a, fmt.Errorf("want 32 bytes, got %d", len(b))
	}
	copy(a[:], b)
	return a, nil
}

func hexToU32(raw json.RawMessage) (uint32, error) {
	b, err := hexBytes(raw)
	if err != nil {
		return 0, err
	}
	if len(b) != 4 {
		return 0, fmt.Errorf("want 4 bytes, got %d", len(b))
	}
	return binary.BigEndian.Uint32(b), nil
}

func hexToU64(raw json.RawMessage) (uint64, error) {
	b, err := hexBytes(raw)
	if err != nil {
		return 0, err
	}
	// XBT ntime/nonce are 8 bytes; tolerate a 4-byte field, since some SV1 encoders
	// still emit a 32-bit ntime. These are LITTLE-endian: XBT's BLAKE2b work header
	// places nonce and ntime with pk_u64le (datum_pow.c / datum_protocol.c), and the
	// gateway's 16-hex-char submit path copies the wire bytes straight into that
	// little-endian slot. See u64Hex for the inverse and why this matters only on a
	// cross-protocol hop.
	switch len(b) {
	case 8:
		return binary.LittleEndian.Uint64(b), nil
	case 4:
		return uint64(binary.LittleEndian.Uint32(b)), nil
	default:
		return 0, fmt.Errorf("want 4 or 8 bytes, got %d", len(b))
	}
}

func u32Hex(v uint32) string {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return hex.EncodeToString(b[:])
}

func u64Hex(v uint64) string {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], v)
	return hex.EncodeToString(b[:])
}
