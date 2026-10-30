package mining

import (
	"bytes"
	"testing"

	"golang.org/x/crypto/blake2b"
)

// The crux correctness proof, ported from the translator: the merkle root an SV1 miner
// computes from the coinb1 we hand it, BLAKE2b-256(0x00 || coinb1 || en1 || en2) with
// en1 = the 4-byte extranonce_prefix, must be byte-identical to the SV2 extended leaf,
// BLAKE2b-256(0x00000000 || commitment || 0x00000000 || extranonce_prefix || extranonce).
// If this holds, every valid SV1 share the miner finds is a valid SV2 extended share.
func TestRootMatchesBetweenSV1AndSV2(t *testing.T) {
	var commitment [32]byte
	for i := range commitment {
		commitment[i] = 0x42
	}
	enPrefix := []byte{0xaa, 0xbb, 0xcc, 0xdd}
	en2 := []byte{1, 2, 3, 4, 5, 6, 7, 8}

	// SV2 extended leaf, as sv2mine/the translator build it (52 bytes).
	sv2 := make([]byte, 0, 52)
	sv2 = append(sv2, 0, 0, 0, 0)
	sv2 = append(sv2, commitment[:]...)
	sv2 = append(sv2, 0, 0, 0, 0)
	sv2 = append(sv2, enPrefix...)
	sv2 = append(sv2, en2...)
	sv2Root := blake2b.Sum256(sv2)

	// SV1 leaf as the miner computes it: 0x00 || coinb1 || en1 || en2.
	sv1 := []byte{0x00}
	sv1 = append(sv1, Coinb1(commitment)...)
	sv1 = append(sv1, enPrefix...)
	sv1 = append(sv1, en2...)
	sv1Root := blake2b.Sum256(sv1)

	if sv1Root != sv2Root {
		t.Fatalf("root mismatch:\n sv1=%x\n sv2=%x", sv1Root, sv2Root)
	}
	if len(Coinb1(commitment)) != 39 {
		t.Fatalf("coinb1 must be 39 bytes, got %d", len(Coinb1(commitment)))
	}
}

func TestNewExtendedMiningJobRoundTrip(t *testing.T) {
	var root [32]byte
	for i := range root {
		root[i] = byte(i)
	}
	// future job: no ntime_start
	f, err := NewExtendedMiningJob{ChannelID: 7, JobID: 3, Root: root}.ToFrame()
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseNewExtendedMiningJob(f)
	if err != nil {
		t.Fatal(err)
	}
	if got.ChannelID != 7 || got.JobID != 3 || got.NtimeStart != nil || got.Root != root {
		t.Fatalf("future job round-trip wrong: %+v", got)
	}
	// 41 bytes on the wire: chan(4)+job(4)+option(1)+root(32)
	if len(f.Payload) != 41 {
		t.Fatalf("future job payload = %d bytes, want 41", len(f.Payload))
	}

	// active job: ntime_start present
	nt := uint64(0x6ad57dfa00000000)
	f, err = NewExtendedMiningJob{ChannelID: 7, JobID: 4, NtimeStart: &nt, Root: root}.ToFrame()
	if err != nil {
		t.Fatal(err)
	}
	got, err = ParseNewExtendedMiningJob(f)
	if err != nil {
		t.Fatal(err)
	}
	if got.NtimeStart == nil || *got.NtimeStart != nt {
		t.Fatalf("active job ntime round-trip wrong: %+v", got)
	}
	if len(f.Payload) != 49 {
		t.Fatalf("active job payload = %d bytes, want 49", len(f.Payload))
	}
}

func TestSetNewPrevHashRoundTrip(t *testing.T) {
	var prev [32]byte
	for i := range prev {
		prev[i] = byte(255 - i)
	}
	f, err := SetNewPrevHash{ChannelID: 1, JobID: 2, PrevHash: prev, NtimeStart: 0x6ad57dfa00000000, Nbits: 0x1b0fffff}.ToFrame()
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseSetNewPrevHash(f)
	if err != nil {
		t.Fatal(err)
	}
	if got.ChannelID != 1 || got.JobID != 2 || got.PrevHash != prev || got.NtimeStart != 0x6ad57dfa00000000 || got.Nbits != 0x1b0fffff {
		t.Fatalf("prevhash round-trip wrong: %+v", got)
	}
	if len(f.Payload) != 52 {
		t.Fatalf("prevhash payload = %d bytes, want 52", len(f.Payload))
	}
}

func TestSubmitSharesExtendedRoundTrip(t *testing.T) {
	en2 := []byte{0xde, 0xad, 0xbe, 0xef, 1, 2, 3, 4}
	f, err := SubmitSharesExtended{ChannelID: 9, SequenceNumber: 100, JobID: 5, Nonce: 0x1122334455667788, Ntime: 0, Extranonce: en2}.ToFrame()
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseSubmitSharesExtended(f)
	if err != nil {
		t.Fatal(err)
	}
	if got.ChannelID != 9 || got.SequenceNumber != 100 || got.JobID != 5 || got.Nonce != 0x1122334455667788 || got.Ntime != 0 || !bytes.Equal(got.Extranonce, en2) {
		t.Fatalf("submit round-trip wrong: %+v", got)
	}
}
