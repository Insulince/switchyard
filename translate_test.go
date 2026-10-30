package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"testing"

	"golang.org/x/crypto/blake2b"

	"github.com/Insulince/switchyard/sv2/mining"
)

// A real XBT SV1 mining.notify captured from the Lazarus DATUM gateway (SV1 port
// 23338) on 2026-10-21. This is the ground truth the whole translation rests on:
// branch-free, fixed-form coinbase, commitment in coinb1[3:35].
const realSV1Notify = `["6ad8e4ac79c0a604",` +
	`"000000000000689a0efd725a088f0408dce3cf45f033764458963928c68c3ce3",` +
	`"0000005b8ff4ff19a8fbf107cdc12f5fc90ca3e66ee0e843e041589e0237db2523134400000000",` +
	`"",[],"a0000000","1b0fffff","0000000000000000",true]`

const realCommitmentHex = "5b8ff4ff19a8fbf107cdc12f5fc90ca3e66ee0e843e041589e0237db25231344"

var realEn1 = []byte{0xb1, 0x0c, 0xf0, 0x0d}

// The gateway's own job hands us a commitment where we expect it, and the other
// header fields decode to the values on the wire.
func TestSV1NotifyToJobRealCapture(t *testing.T) {
	jobID, j, err := sv1NotifyToJob(json.RawMessage(realSV1Notify), realEn1, 8)
	if err != nil {
		t.Fatalf("parsing a real gateway notify failed: %v", err)
	}
	if jobID != "6ad8e4ac79c0a604" {
		t.Errorf("job id = %q", jobID)
	}
	if got := hex.EncodeToString(j.Commitment[:]); got != realCommitmentHex {
		t.Errorf("commitment = %s\n          want %s", got, realCommitmentHex)
	}
	if j.Version != 0xa0000000 {
		t.Errorf("version = %08x, want a0000000", j.Version)
	}
	if j.Nbits != 0x1b0fffff {
		t.Errorf("nbits = %08x, want 1b0fffff", j.Nbits)
	}
	if j.Ntime != 0 {
		t.Errorf("ntime = %d, want 0", j.Ntime)
	}
	if !j.Clean {
		t.Error("clean = false, want true")
	}
	if !bytes.Equal(j.ExtranoncePrefix, realEn1) || j.ExtranonceSize != 8 {
		t.Errorf("extranonce = %x/%d, want %x/8", j.ExtranoncePrefix, j.ExtranonceSize, realEn1)
	}
}

// A coinb2 or a merkle branch that is not empty is not XBT work we can translate,
// and must be refused rather than silently mis-mined.
func TestSV1NotifyRejectsNonXBTCoinbase(t *testing.T) {
	for _, tc := range []struct{ name, notify string }{
		{"non-empty coinb2", `["j","` + hex32() + `","` + hex.EncodeToString(mining.Coinb1(z32())) + `","ab",[],"a0000000","1b0fffff","0000000000000000",true]`},
		{"non-empty branch", `["j","` + hex32() + `","` + hex.EncodeToString(mining.Coinb1(z32())) + `","",["aa"],"a0000000","1b0fffff","0000000000000000",true]`},
		{"short coinb1", `["j","` + hex32() + `","0000","",[],"a0000000","1b0fffff","0000000000000000",true]`},
	} {
		if _, _, err := sv1NotifyToJob(json.RawMessage(tc.notify), realEn1, 8); err == nil {
			t.Errorf("%s: parsed without error, want rejection", tc.name)
		}
	}
}

// commitment -> coinb1 -> commitment survives, and coinb1 is the 39-byte XBT form.
func TestCommitmentCoinb1RoundTrip(t *testing.T) {
	var c [32]byte
	for i := range c {
		c[i] = byte(i * 7)
	}
	coinb1 := mining.Coinb1(c)
	if len(coinb1) != 39 {
		t.Fatalf("coinb1 len = %d, want 39", len(coinb1))
	}
	got, err := commitmentFromSV1Coinb1(coinb1)
	if err != nil {
		t.Fatal(err)
	}
	if got != c {
		t.Fatalf("round trip changed commitment:\n got %x\nwant %x", got, c)
	}
}

// A canonJob rendered to an SV1 notify and parsed back is unchanged.
func TestSV1NotifyRoundTrip(t *testing.T) {
	want := sampleJob()
	params, err := jobToSV1NotifyParams("deadbeef", want)
	if err != nil {
		t.Fatal(err)
	}
	_, got, err := sv1NotifyToJob(params, want.ExtranoncePrefix, want.ExtranonceSize)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("round trip changed the job\n got %+v\nwant %+v", got, want)
	}
}

// THE CROSS-PROTOCOL CORRECTNESS PROOF. A job's SV1 coinbase leaf (what an SV1
// miner computes) and its SV2 extended leaf (what an SV2 miner commits to) are
// byte-identical for the same extranonce -- so a share found on either wire is a
// valid share on the other. This is the whole reason the four cells can share one
// canonJob. Proven here at the canonJob level, including against the real gateway's
// commitment, not just a synthetic one.
func TestLeafEquivalence(t *testing.T) {
	jobs := []canonJob{sampleJob()}
	if _, j, err := sv1NotifyToJob(json.RawMessage(realSV1Notify), realEn1, 8); err == nil {
		jobs = append(jobs, j)
	} else {
		t.Fatalf("real notify: %v", err)
	}
	en2 := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	for i, j := range jobs {
		if sv1Leaf(j, en2) != sv2Leaf(j, en2) {
			t.Errorf("job %d: SV1 leaf != SV2 leaf", i)
		}
	}
}

// sv2Work from an upstream maps straight across (SV2 carries no version, so the
// XBT constant stands in).
func TestSV2WorkToJob(t *testing.T) {
	var ph, comm, tgt [32]byte
	for i := range ph {
		ph[i], comm[i], tgt[i] = byte(i), byte(i+1), 0xff
	}
	w := sv2Work{
		PrevHash: ph, Commitment: comm, Ntime: 0, Nbits: 0x1b0fffff,
		ExtranoncePrefix: realEn1, Target: tgt, Clean: true,
	}
	j := sv2WorkToJob(w)
	if j.Commitment != comm || j.PrevHash != ph || j.Nbits != 0x1b0fffff || j.Version != xbtVersion || !j.Clean {
		t.Fatalf("sv2WorkToJob wrong: %+v", j)
	}
	if !bytes.Equal(j.ExtranoncePrefix, realEn1) {
		t.Fatalf("extranonce prefix = %x", j.ExtranoncePrefix)
	}
}

// SV1 submit params and SV2 SubmitSharesExtended both carry the same share, and
// each converts to the canonical form and back unchanged.
func TestShareConversions(t *testing.T) {
	s := canonShare{Nonce: 0x0102030405060708, Ntime: 0, Extranonce: []byte{0xaa, 0xbb, 0xcc, 0xdd, 1, 2, 3, 4}}

	// SV1 round trip.
	p1, err := shareToSV1SubmitParams("worker1", "job9", s)
	if err != nil {
		t.Fatal(err)
	}
	jobID, got1, err := sv1SubmitToShare(p1)
	if err != nil {
		t.Fatal(err)
	}
	if jobID != "job9" || !reflect.DeepEqual(got1, s) {
		t.Fatalf("SV1 share round trip: job=%q got=%+v want=%+v", jobID, got1, s)
	}

	// SV2 round trip.
	m := shareToSV2Submit(7, 42, 5, s)
	if m.ChannelID != 7 || m.SequenceNumber != 42 || m.JobID != 5 {
		t.Fatalf("SV2 framing lost: %+v", m)
	}
	got2 := sv2SubmitToShare(m)
	if !reflect.DeepEqual(got2, s) {
		t.Fatalf("SV2 share round trip: got=%+v want=%+v", got2, s)
	}
}

// A share that crosses SV1<->SV2 must hash to the same preimage on both wires.
// XBT's BLAKE2b work places nonce and ntime little-endian (pk_u64le), and the
// gateway copies the SV1 submit's 16-hex-char field straight into that slot, so
// the SV1 wire bytes of nonce/ntime must BE the little-endian u64. The old code
// emitted them big-endian; that round-trips within one protocol (so the symmetric
// TestShareConversions passed) but reverses the bytes on a crossing, which the
// gateway rejects as difficulty-too-low. This pins the byte order so it cannot
// silently regress.
func TestShareFieldsAreLittleEndianOnTheWire(t *testing.T) {
	const nonce uint64 = 0x0102030405060708
	const ntime uint64 = 0x1122334455667788
	s := canonShare{Nonce: nonce, Ntime: ntime, Extranonce: []byte{1, 2, 3, 4, 5, 6, 7, 8}}

	raw, err := shareToSV1SubmitParams("w", "j", s)
	if err != nil {
		t.Fatal(err)
	}
	var p []string
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatal(err)
	}
	// params = [worker, jobID, extranonce2, ntime, nonce]
	gotNtime, _ := hex.DecodeString(p[3])
	gotNonce, _ := hex.DecodeString(p[4])

	var wantNtime, wantNonce [8]byte
	binary.LittleEndian.PutUint64(wantNtime[:], ntime) // == pk_u64le(ntime)
	binary.LittleEndian.PutUint64(wantNonce[:], nonce) // == pk_u64le(nonce)

	if !bytes.Equal(gotNonce, wantNonce[:]) {
		t.Errorf("SV1 wire nonce = %x, want little-endian %x (pk_u64le)", gotNonce, wantNonce)
	}
	if !bytes.Equal(gotNtime, wantNtime[:]) {
		t.Errorf("SV1 wire ntime = %x, want little-endian %x (pk_u64le)", gotNtime, wantNtime)
	}
}

// --- test helpers ---

func sampleJob() canonJob {
	var ph, comm [32]byte
	for i := range ph {
		ph[i] = byte(255 - i)
		comm[i] = byte(i * 3)
	}
	return canonJob{
		PrevHash: ph, Commitment: comm, Ntime: 0, Nbits: 0x1b0fffff,
		Version: xbtVersion, ExtranoncePrefix: []byte{0xb1, 0x0c, 0xf0, 0x0d},
		ExtranonceSize: 8, Clean: true,
	}
}

// sv1Leaf and sv2Leaf are the two wire forms' coinbase leaves, as a miner on each
// protocol computes them. They must be equal for a translated share to validate.
func sv1Leaf(j canonJob, en2 []byte) [32]byte {
	buf := []byte{0x00}
	buf = append(buf, mining.Coinb1(j.Commitment)...)
	buf = append(buf, j.ExtranoncePrefix...)
	buf = append(buf, en2...)
	return blake2b.Sum256(buf)
}

func sv2Leaf(j canonJob, en2 []byte) [32]byte {
	buf := make([]byte, 0, 52)
	buf = append(buf, 0, 0, 0, 0)
	buf = append(buf, j.Commitment[:]...)
	buf = append(buf, 0, 0, 0, 0)
	buf = append(buf, j.ExtranoncePrefix...)
	buf = append(buf, en2...)
	return blake2b.Sum256(buf)
}

func z32() [32]byte { var z [32]byte; return z }

func hex32() string { return hex.EncodeToString(make([]byte, 32)) }
