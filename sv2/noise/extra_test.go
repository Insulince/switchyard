package noise

import (
	"bytes"
	"crypto/sha256"
	"io"
	"testing"
	"time"

	"github.com/Insulince/switchyard/sv2/framing"
	"github.com/btcsuite/btcd/btcec/v2"
)

// budgetWriter accepts up to budget bytes total, then fails. Used to drive the
// write-error branches of Transport.WriteFrame.
type budgetWriter struct{ budget int }

func (w *budgetWriter) Write(p []byte) (int, error) {
	if w.budget <= 0 {
		return 0, io.ErrClosedPipe
	}
	n := len(p)
	if n > w.budget {
		n = w.budget
	}
	w.budget -= n
	if n < len(p) {
		return n, io.ErrShortWrite
	}
	return n, nil
}

func TestSaturatingArithmetic(t *testing.T) {
	if got := saturatingSubU32(5, 10); got != 0 {
		t.Fatalf("saturatingSubU32(5,10) = %d, want 0 (clamped)", got)
	}
	if got := saturatingSubU32(20, 10); got != 10 {
		t.Fatalf("saturatingSubU32(20,10) = %d, want 10", got)
	}
	if got := saturatingAddU32(^uint32(0), 10); got != ^uint32(0) {
		t.Fatalf("saturatingAddU32(max,10) = %d, want max (clamped)", got)
	}
	if got := saturatingAddU32(5, 10); got != 15 {
		t.Fatalf("saturatingAddU32(5,10) = %d, want 15", got)
	}
}

// TestCertValidFromBelowLeeway exercises the saturatingSub clamp inside verify:
// a certificate whose valid_from is below the leeway must still validate at t=0.
func TestCertValidFromBelowLeeway(t *testing.T) {
	authority, _ := btcec.NewPrivateKey()
	static, _ := btcec.NewPrivateKey()
	staticXOnly := xOnlyFromPriv(static)
	cert, err := buildSignatureNoiseMessage(authority, staticXOnly, 1, 1000)
	if err != nil {
		t.Fatal(err)
	}
	m, _ := parseSignatureNoiseMessage(cert)
	if err := m.verify(staticXOnly, authority.PubKey(), 0); err != nil {
		t.Fatalf("cert with valid_from below leeway rejected at t=0: %v", err)
	}
}

func TestParseSignatureNoiseMessageWrongSize(t *testing.T) {
	if _, err := parseSignatureNoiseMessage([]byte{0x01, 0x02}); err == nil {
		t.Fatal("expected error on wrong-size certificate")
	}
}

// TestVerifyMalformedSignature exercises the ParseSignature error path in verify:
// an all-0xff signature is not a valid BIP340 signature (r exceeds the field).
func TestVerifyMalformedSignature(t *testing.T) {
	authority, _ := btcec.NewPrivateKey()
	static, _ := btcec.NewPrivateKey()
	staticXOnly := xOnlyFromPriv(static)
	m := signatureNoiseMessage{version: certVersion, validFrom: 1, notValidAfter: 1000}
	for i := range m.signature {
		m.signature[i] = 0xff
	}
	if err := m.verify(staticXOnly, authority.PubKey(), 500); err == nil {
		t.Fatal("expected error on malformed signature bytes")
	}
}

func TestTransportReadFrameCorruptHeader(t *testing.T) {
	rt, it := establishedPair(t)
	var buf bytes.Buffer
	if err := rt.WriteFrame(&buf, framing.Frame{MsgType: 0x01, Payload: []byte{1, 2, 3}}); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	b := buf.Bytes()
	b[2] ^= 0xff // corrupt a byte inside the encrypted header record
	if _, err := it.ReadFrame(bytes.NewReader(b)); err == nil {
		t.Fatal("expected AEAD failure decrypting a corrupted header record")
	}
}

func TestTransportWriteFrameMarshalError(t *testing.T) {
	rt, _ := establishedPair(t)
	// Invalid frame (channel_msg bit inside ExtensionType) fails to marshal.
	bad := framing.Frame{ExtensionType: 0x8000, MsgType: 0x01, Payload: []byte{1}}
	if err := rt.WriteFrame(&bytes.Buffer{}, bad); err == nil {
		t.Fatal("expected marshal error for invalid frame")
	}
}

func TestTransportWriteFrameWriterErrors(t *testing.T) {
	rt, _ := establishedPair(t)
	f := framing.Frame{MsgType: 0x1f, ChannelMsg: true, Payload: bytes.Repeat([]byte{0xab}, 50)}

	// Fail on the header record (budget 0).
	if err := rt.WriteFrame(&budgetWriter{budget: 0}, f); err == nil {
		t.Fatal("expected error when header record write fails")
	}
	// Fail on the payload record (header fits, payload does not).
	rt2, _ := establishedPair(t)
	if err := rt2.WriteFrame(&budgetWriter{budget: encryptedHeaderSize}, f); err == nil {
		t.Fatal("expected error when payload record write fails")
	}
}

// TestEllswiftEncodeDecodeInverse pins that ellswiftFromPriv and xOnlyFromEllswift
// are inverses: encoding a key's public point as ElligatorSwift and recovering its
// x-only key yields the same key the BIP340 serializer produces. This is the
// path the initiator uses to recover (and then verify the certificate over) the
// responder's static key.
func TestEllswiftEncodeDecodeInverse(t *testing.T) {
	for i := 0; i < 20; i++ {
		priv, err := btcec.NewPrivateKey()
		if err != nil {
			t.Fatal(err)
		}
		ell, err := ellswiftFromPriv(priv)
		if err != nil {
			t.Fatalf("ellswiftFromPriv: %v", err)
		}
		gotX, err := xOnlyFromEllswift(ell)
		if err != nil {
			t.Fatalf("xOnlyFromEllswift: %v", err)
		}
		if want := xOnlyFromPriv(priv); gotX != want {
			t.Fatalf("ellswift inverse mismatch:\n got  %x\n want %x", gotX, want)
		}
	}
}

// TestSymmetricStatePreKeyPassthrough covers the pre-key branch of
// encryptAndHash/decryptAndHash (before any mixKey): the plaintext passes through
// unencrypted but is still mixed into the handshake hash on both sides.
func TestSymmetricStatePreKeyPassthrough(t *testing.T) {
	const proto = "Noise_NX_Secp256k1+EllSwift_ChaChaPoly_SHA256"
	a := newSymmetricState(proto)
	b := newSymmetricState(proto)

	pt := []byte("pre-key payload")
	ct, err := a.encryptAndHash(pt)
	if err != nil {
		t.Fatalf("encryptAndHash: %v", err)
	}
	if !bytes.Equal(ct, pt) {
		t.Fatalf("pre-key encrypt should pass plaintext through, got % x", ct)
	}
	out, err := b.decryptAndHash(ct)
	if err != nil {
		t.Fatalf("decryptAndHash: %v", err)
	}
	if !bytes.Equal(out, pt) {
		t.Fatalf("pre-key decrypt = % x, want % x", out, pt)
	}
	if a.h != b.h {
		t.Fatal("handshake hash diverged across pre-key passthrough")
	}
}

// TestNewSymmetricStateShortName covers the (unused in production but spec-defined)
// short-protocol-name branch: names <= 32 bytes are zero-padded into the chaining
// key rather than hashed.
func TestNewSymmetricStateShortName(t *testing.T) {
	const name = "short"
	var wantCk [32]byte
	copy(wantCk[:], name)
	wantH := sha256.Sum256(wantCk[:])

	s := newSymmetricState(name)
	if s.ck != wantCk {
		t.Fatalf("ck = %x, want zero-padded name %x", s.ck, wantCk)
	}
	if s.h != wantH {
		t.Fatalf("h = %x, want HASH(ck) %x", s.h, wantH)
	}
}

// TestCipherStateRejectsOutOfOrder pins that the AEAD nonce is strictly positional:
// a record encrypted at nonce n only decrypts when the receiver is also at n.
func TestCipherStateRejectsOutOfOrder(t *testing.T) {
	var k [32]byte
	enc := newCipherState(k)
	rec0, _ := enc.encrypt(nil, []byte("first"))
	rec1, _ := enc.encrypt(nil, []byte("second"))

	dec := newCipherState(k)
	// Receiver is at nonce 0; the second record (nonce 1) must not decrypt.
	if _, err := dec.decrypt(nil, rec1); err == nil {
		t.Fatal("out-of-order record decrypted (nonce not enforced)")
	}
	// Nonce did not advance on failure, so the first record still decrypts.
	if _, err := dec.decrypt(nil, rec0); err != nil {
		t.Fatalf("in-order record failed after a rejected one: %v", err)
	}
}

func TestProcessAct2WrongSize(t *testing.T) {
	init, _, err := NewInitiator(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := init.ProcessAct2(make([]byte, actTwoSize-1), 0); err == nil {
		t.Fatal("expected error on short act2")
	}
	if _, err := init.ProcessAct2(make([]byte, actTwoSize+1), 0); err == nil {
		t.Fatal("expected error on long act2")
	}
}

// TestProcessAct2NilAuthoritySkipsCertVerify pins that an initiator created with a
// nil authority establishes the transport without verifying the certificate
// (useful for opportunistic encryption / testing), and the channel still works.
func TestProcessAct2NilAuthoritySkipsCertVerify(t *testing.T) {
	authority, _ := btcec.NewPrivateKey()
	static, _ := btcec.NewPrivateKey()
	resp := NewResponder(authority, static, time.Minute)

	init, act1, err := NewInitiator(nil)
	if err != nil {
		t.Fatal(err)
	}
	// now far outside any sane cert window: still fine, since verification is off.
	act2, rt, err := resp.Respond(act1, 1_000_000)
	if err != nil {
		t.Fatalf("Respond: %v", err)
	}
	it, err := init.ProcessAct2(act2, 9_000_000)
	if err != nil {
		t.Fatalf("ProcessAct2 with nil authority: %v", err)
	}
	ct, _ := rt.EncryptMessage([]byte("ping"))
	pt, err := it.DecryptMessage(ct)
	if err != nil || !bytes.Equal(pt, []byte("ping")) {
		t.Fatalf("transport after nil-authority handshake: pt=%q err=%v", pt, err)
	}
}

func TestHandshakeTamperCertRegionRejected(t *testing.T) {
	authority, _ := btcec.NewPrivateKey()
	static, _ := btcec.NewPrivateKey()
	resp := NewResponder(authority, static, time.Minute)
	init, act1, err := NewInitiator(authority.PubKey())
	if err != nil {
		t.Fatal(err)
	}
	act2, _, err := resp.Respond(act1, 1_000_000)
	if err != nil {
		t.Fatalf("Respond: %v", err)
	}
	// Corrupt a byte inside the encrypted certificate record (offset 144..234).
	act2[encCertOffset+10] ^= 0xff
	if _, err := init.ProcessAct2(act2, 1_000_000); err == nil {
		t.Fatal("expected AEAD failure on tampered certificate record")
	}
}

func TestHandshakeTamperEphemeralRejected(t *testing.T) {
	authority, _ := btcec.NewPrivateKey()
	static, _ := btcec.NewPrivateKey()
	resp := NewResponder(authority, static, time.Minute)
	init, act1, err := NewInitiator(authority.PubKey())
	if err != nil {
		t.Fatal(err)
	}
	act2, _, err := resp.Respond(act1, 1_000_000)
	if err != nil {
		t.Fatalf("Respond: %v", err)
	}
	// Corrupt the responder ephemeral key (offset 0..64): ee diverges, so the
	// handshake hash diverges and the encrypted static key fails to authenticate.
	act2[10] ^= 0xff
	if _, err := init.ProcessAct2(act2, 1_000_000); err == nil {
		t.Fatal("expected failure when responder ephemeral is corrupted")
	}
}
