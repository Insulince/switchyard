package noise

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
)

// TestProtocolNameConstant pins our protocol-name string against SRI's
// precomputed NOISE_HASHED_PROTOCOL_NAME_CHACHA, guaranteeing the exact suite
// name "Noise_NX_Secp256k1+EllSwift_ChaChaPoly_SHA256".
func TestProtocolNameConstant(t *testing.T) {
	want := []byte{
		46, 180, 120, 129, 32, 142, 158, 238, 31, 102, 159, 103, 198, 110, 231, 14,
		169, 234, 136, 9, 13, 80, 63, 232, 48, 220, 75, 200, 62, 41, 191, 16,
	}
	got := sha256.Sum256([]byte(protocolName))
	if !bytes.Equal(got[:], want) {
		t.Fatalf("SHA256(protocolName) = %v\nwant %v", got[:], want)
	}
}

func TestSignatureNoiseMessageRoundTrip(t *testing.T) {
	authority, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	static, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	staticXOnly := xOnlyFromPriv(static)

	const now = uint32(1_000_000)
	cert, err := buildSignatureNoiseMessage(authority, staticXOnly, now, now+60)
	if err != nil {
		t.Fatalf("build cert: %v", err)
	}
	if len(cert) != sigNoiseMessageSize {
		t.Fatalf("cert size %d, want %d", len(cert), sigNoiseMessageSize)
	}

	m, err := parseSignatureNoiseMessage(cert)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := m.verify(staticXOnly, authority.PubKey(), now+30); err != nil {
		t.Fatalf("valid cert rejected: %v", err)
	}
	if err := m.verify(staticXOnly, authority.PubKey(), now+1000); err == nil {
		t.Fatal("expired cert accepted")
	}
	if err := m.verify(staticXOnly, authority.PubKey(), now-1000); err == nil {
		t.Fatal("not-yet-valid cert accepted")
	}

	other, _ := btcec.NewPrivateKey()
	if err := m.verify(xOnlyFromPriv(other), authority.PubKey(), now+30); err == nil {
		t.Fatal("cert verified against wrong static key")
	}
	otherAuth, _ := btcec.NewPrivateKey()
	if err := m.verify(staticXOnly, otherAuth.PubKey(), now+30); err == nil {
		t.Fatal("cert verified against wrong authority")
	}
}

func newPair(t *testing.T) (resp *Responder, init *Initiator, act1 [actOneSize]byte) {
	t.Helper()
	authority, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	static, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	resp = NewResponder(authority, static, time.Minute)
	init, act1, err = NewInitiator(authority.PubKey())
	if err != nil {
		t.Fatal(err)
	}
	return resp, init, act1
}

func TestHandshakeRoundTrip(t *testing.T) {
	resp, init, act1 := newPair(t)
	const now = uint32(1_000_000)

	act2, rt, err := resp.Respond(act1, now)
	if err != nil {
		t.Fatalf("Respond: %v", err)
	}
	if len(act2) != actTwoSize {
		t.Fatalf("act2 size %d, want %d", len(act2), actTwoSize)
	}

	it, err := init.ProcessAct2(act2, now)
	if err != nil {
		t.Fatalf("ProcessAct2: %v", err)
	}

	// Responder -> initiator and initiator -> responder, several messages each,
	// to confirm both directions and that the per-direction nonces stay in sync.
	for i := 0; i < 4; i++ {
		down := []byte("job from pool")
		ct, err := rt.Encrypt(nil, down)
		if err != nil {
			t.Fatalf("resp encrypt %d: %v", i, err)
		}
		got, err := it.Decrypt(nil, ct)
		if err != nil {
			t.Fatalf("init decrypt %d: %v", i, err)
		}
		if !bytes.Equal(got, down) {
			t.Fatalf("downstream %d = %q", i, got)
		}

		up := []byte("share from miner")
		ct2, err := it.Encrypt(nil, up)
		if err != nil {
			t.Fatalf("init encrypt %d: %v", i, err)
		}
		got2, err := rt.Decrypt(nil, ct2)
		if err != nil {
			t.Fatalf("resp decrypt %d: %v", i, err)
		}
		if !bytes.Equal(got2, up) {
			t.Fatalf("upstream %d = %q", i, got2)
		}
	}
}

func TestHandshakeRejectsExpiredCert(t *testing.T) {
	authority, _ := btcec.NewPrivateKey()
	static, _ := btcec.NewPrivateKey()
	resp := NewResponder(authority, static, time.Second)
	init, act1, err := NewInitiator(authority.PubKey())
	if err != nil {
		t.Fatal(err)
	}
	const now = uint32(1_000_000)
	act2, _, err := resp.Respond(act1, now)
	if err != nil {
		t.Fatalf("Respond: %v", err)
	}
	_, err = init.ProcessAct2(act2, now+100)
	if err == nil {
		t.Fatal("expected expired-certificate rejection")
	}
	// The dashboard's key-test probe keys off this sentinel to say "clocks, not
	// a wrong key", so an expired cert must stay distinguishable from a bad one.
	if !errors.Is(err, ErrCertWindow) {
		t.Fatalf("expired cert: got %v, want ErrCertWindow", err)
	}
}

// TestProcessAct2WrongAuthorityIsSentinel is the case the dashboard's "test this
// key against the gateway" probe turns into "the gateway is using a different
// authority key": a responder signs with one authority, the initiator pins
// another, and the mismatch must come back as ErrCertSignatureInvalid (not some
// text-matched string) so the probe can report a wrong key with confidence.
func TestProcessAct2WrongAuthorityIsSentinel(t *testing.T) {
	authority, _ := btcec.NewPrivateKey()
	static, _ := btcec.NewPrivateKey()
	resp := NewResponder(authority, static, time.Minute)
	wrongAuth, _ := btcec.NewPrivateKey()
	init, act1, err := NewInitiator(wrongAuth.PubKey())
	if err != nil {
		t.Fatal(err)
	}
	const now = uint32(1_000_000)
	act2, _, err := resp.Respond(act1, now)
	if err != nil {
		t.Fatalf("Respond: %v", err)
	}
	if _, err := init.ProcessAct2(act2, now); !errors.Is(err, ErrCertSignatureInvalid) {
		t.Fatalf("wrong authority: got %v, want ErrCertSignatureInvalid", err)
	}
}

func TestHandshakeRejectsTamperedStatic(t *testing.T) {
	resp, init, act1 := newPair(t)
	const now = uint32(1_000_000)
	act2, _, err := resp.Respond(act1, now)
	if err != nil {
		t.Fatalf("Respond: %v", err)
	}
	act2[actOneSize+5] ^= 0xff // corrupt the encrypted static key
	if _, err := init.ProcessAct2(act2, now); err == nil {
		t.Fatal("expected AEAD failure on tampered handshake")
	}
}

func TestHandshakeWrongAuthorityRejected(t *testing.T) {
	authority, _ := btcec.NewPrivateKey()
	static, _ := btcec.NewPrivateKey()
	resp := NewResponder(authority, static, time.Minute)

	wrongAuth, _ := btcec.NewPrivateKey()
	init, act1, err := NewInitiator(wrongAuth.PubKey())
	if err != nil {
		t.Fatal(err)
	}
	const now = uint32(1_000_000)
	act2, _, err := resp.Respond(act1, now)
	if err != nil {
		t.Fatalf("Respond: %v", err)
	}
	if _, err := init.ProcessAct2(act2, now); err == nil {
		t.Fatal("expected wrong-authority rejection")
	}
}
