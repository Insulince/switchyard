package noise

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

// TestChaChaPolyRFC8439 pins the underlying AEAD (and our use of it) against the
// RFC 8439 section 2.8.2 worked example. This is the cipher the SV2 Noise suite
// names ChaChaPoly.
func TestChaChaPolyRFC8439(t *testing.T) {
	key := mustHex(t, "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
	nonce := mustHex(t, "070000004041424344454647")
	aad := mustHex(t, "50515253c0c1c2c3c4c5c6c7")
	plaintext := []byte("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.")
	want := mustHex(t,
		"d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"+
			"3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"+
			"92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"+
			"3ff4def08e4b7a9de576d26586cec64b6116"+
			"1ae10b594f09e26a7e902ecbd0600691")

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		t.Fatalf("new aead: %v", err)
	}
	got := aead.Seal(nil, nonce, plaintext, aad)
	if !bytes.Equal(got, want) {
		t.Fatalf("seal = %x\nwant %x", got, want)
	}
}

// TestNoiseNonce pins the Noise ChaChaPoly nonce construction: 4 zero bytes
// followed by the 8-byte little-endian counter.
func TestNoiseNonce(t *testing.T) {
	cases := []struct {
		n    uint64
		want string
	}{
		{0, "000000000000000000000000"},
		{1, "000000000100000000000000"},
		{0x0102030405060708, "000000000807060504030201"},
	}
	for _, tc := range cases {
		got := noiseNonce(tc.n)
		if hex.EncodeToString(got[:]) != tc.want {
			t.Fatalf("noiseNonce(%d) = %x, want %s", tc.n, got, tc.want)
		}
	}
}

// TestNoiseHKDF_Ordering pins that noiseHKDF treats the chaining key as the HKDF
// salt and the supplied material as the IKM (the easy-to-invert convention),
// by reproducing Noise's HMAC chain by hand.
func TestNoiseHKDF_Ordering(t *testing.T) {
	ck := sha256.Sum256([]byte("chaining-key"))
	ikm := []byte("input-key-material")

	o1, o2 := noiseHKDF2(ck, ikm)

	// Noise: temp_key = HMAC(ck, ikm); out1 = HMAC(temp_key, 0x01);
	// out2 = HMAC(temp_key, out1 || 0x02).
	tk := hmacSHA256(ck[:], ikm)
	want1 := hmacSHA256(tk, []byte{0x01})
	want2 := hmacSHA256(tk, append(append([]byte{}, want1...), 0x02))

	if !bytes.Equal(o1[:], want1) {
		t.Fatalf("out1 = %x, want %x", o1, want1)
	}
	if !bytes.Equal(o2[:], want2) {
		t.Fatalf("out2 = %x, want %x", o2, want2)
	}
}

func hmacSHA256(key, data []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(data)
	return m.Sum(nil)
}

func TestCipherStateRoundTrip(t *testing.T) {
	var k [32]byte
	copy(k[:], bytes.Repeat([]byte{0x42}, 32))

	enc := newCipherState(k)
	dec := newCipherState(k)

	ad := []byte("associated")
	msgs := [][]byte{[]byte("first"), []byte("second"), {}, []byte("fourth")}
	for i, pt := range msgs {
		ct, err := enc.encrypt(ad, pt)
		if err != nil {
			t.Fatalf("encrypt %d: %v", i, err)
		}
		got, err := dec.decrypt(ad, ct)
		if err != nil {
			t.Fatalf("decrypt %d: %v", i, err)
		}
		if !bytes.Equal(got, pt) {
			t.Fatalf("round trip %d = %q, want %q", i, got, pt)
		}
	}
	if enc.n != uint64(len(msgs)) {
		t.Fatalf("nonce = %d, want %d", enc.n, len(msgs))
	}
}

func TestCipherStateTamperRejected(t *testing.T) {
	var k [32]byte
	enc := newCipherState(k)
	dec := newCipherState(k)
	ct, err := enc.encrypt(nil, []byte("secret"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	ct[0] ^= 0xff
	if _, err := dec.decrypt(nil, ct); err == nil {
		t.Fatal("expected auth failure on tampered ciphertext")
	}
}

// TestSymmetricStateTwoParty exercises the full symmetric state the way the
// handshake will: two parties initialize with the same protocol name, mix the
// same key material and handshake bytes, and an EncryptAndHash on one side
// decrypts on the other with the running hash staying in lock-step.
func TestSymmetricStateTwoParty(t *testing.T) {
	const proto = "Noise_NX_Secp256k1+EllSwift_ChaChaPoly_SHA256"
	a := newSymmetricState(proto)
	b := newSymmetricState(proto)
	if a.h != b.h {
		t.Fatalf("init h mismatch")
	}

	a.mixHash([]byte("prologue"))
	b.mixHash([]byte("prologue"))

	var ikm [32]byte
	copy(ikm[:], bytes.Repeat([]byte{0x07}, 32))
	a.mixKey(ikm)
	b.mixKey(ikm)
	if a.ck != b.ck {
		t.Fatalf("chaining key mismatch after mixKey")
	}

	ct, err := a.encryptAndHash([]byte("static-key-payload"))
	if err != nil {
		t.Fatalf("encryptAndHash: %v", err)
	}
	pt, err := b.decryptAndHash(ct)
	if err != nil {
		t.Fatalf("decryptAndHash: %v", err)
	}
	if !bytes.Equal(pt, []byte("static-key-payload")) {
		t.Fatalf("payload = %q", pt)
	}
	if a.h != b.h {
		t.Fatalf("running hash diverged after encrypt/decrypt")
	}

	// Split must yield transport keys that are swapped between the two roles:
	// initiator's send key is responder's receive key.
	a1, a2 := a.split()
	b1, b2 := b.split()
	if a1.k != b1.k || a2.k != b2.k {
		t.Fatalf("split keys disagree between parties")
	}
}

func TestSymmetricStateLongProtocolName(t *testing.T) {
	// The SV2 protocol name exceeds 32 bytes, so init must hash it rather than
	// zero-pad it.
	const proto = "Noise_NX_Secp256k1+EllSwift_ChaChaPoly_SHA256"
	if len(proto) <= 32 {
		t.Fatalf("test premise wrong: name is %d bytes", len(proto))
	}
	s := newSymmetricState(proto)
	wantCk := sha256.Sum256([]byte(proto))
	wantH := sha256.Sum256(wantCk[:])
	if s.ck != wantCk {
		t.Fatalf("init ck = %x, want HASH(name) %x", s.ck, wantCk)
	}
	if s.h != wantH {
		t.Fatalf("init h = %x, want HASH(HASH(name)) %x", s.h, wantH)
	}
}

// guard against accidental removal of the LE assumption in noiseNonce.
func TestNoiseNonceLE(t *testing.T) {
	got := noiseNonce(1)
	var le [8]byte
	binary.LittleEndian.PutUint64(le[:], 1)
	if !bytes.Equal(got[4:], le[:]) {
		t.Fatalf("counter not little-endian in nonce tail: %x", got[4:])
	}
}

var _ = errors.Is
