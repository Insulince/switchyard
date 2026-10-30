package main

import (
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

// A key survives the encode -> decode round trip as the same x-only public key.
// This is the property the whole format exists to provide: switchyard must pin
// exactly the key the gateway proves it holds.
func TestAuthorityKeyRoundTrip(t *testing.T) {
	for i := 0; i < 50; i++ {
		priv, err := btcec.NewPrivateKey()
		if err != nil {
			t.Fatal(err)
		}
		enc := authorityKeyEncode(priv.PubKey())
		got, err := authorityKeyDecode(enc)
		if err != nil {
			t.Fatalf("decode(%s): %v", enc, err)
		}
		if a, b := schnorr.SerializePubKey(got), schnorr.SerializePubKey(priv.PubKey()); string(a) != string(b) {
			t.Fatalf("round trip changed the key:\n got %x\nwant %x", a, b)
		}
	}
}

// The SRI layout is pinned here against drift: base58check over a two-byte
// {0x01, 0x00} prefix followed by the 32-byte x-only key. This exact shape was
// reverse-verified against a live CONVOY gateway's printed authority key; if a
// refactor changes the prefix, the checksum scheme or the key length, real
// gateways stop verifying -- silently -- and only this test would catch it.
func TestAuthorityKeyIsSRIFormat(t *testing.T) {
	var sk [32]byte
	for i := range sk {
		sk[i] = 0x01
	}
	priv, _ := btcec.PrivKeyFromBytes(sk[:])

	enc := authorityKeyEncode(priv.PubKey())
	payload, err := base58CheckDecode(enc)
	if err != nil {
		t.Fatalf("not valid base58check: %v", err)
	}
	if len(payload) != 34 {
		t.Fatalf("payload len = %d, want 34 (2-byte prefix + 32-byte key)", len(payload))
	}
	if payload[0] != 0x01 || payload[1] != 0x00 {
		t.Fatalf("prefix = %x, want 0100", payload[:2])
	}
	if got := payload[2:]; string(got) != string(schnorr.SerializePubKey(priv.PubKey())) {
		t.Fatalf("body = %x, want the x-only key %x", got, schnorr.SerializePubKey(priv.PubKey()))
	}
}

func TestAuthorityKeyDecodeRejects(t *testing.T) {
	priv, _ := btcec.NewPrivateKey()
	good := authorityKeyEncode(priv.PubKey())

	// Flip one character to break the checksum (keep it in-alphabet).
	bad := []byte(good)
	if bad[5] == 'a' {
		bad[5] = 'b'
	} else {
		bad[5] = 'a'
	}

	for _, tc := range []struct {
		name, in, wantSub string
	}{
		{"empty", "", "too short"},
		{"not base58 (0)", "0" + good[1:], "invalid base58"},
		{"not base58 (O)", "O" + good[1:], "invalid base58"},
		{"corrupted checksum", string(bad), "bad checksum"},
		{"valid b58 wrong layout", base58CheckEncode([]byte{0x02, 0x00, 0x01, 0x02}), "unexpected layout"},
	} {
		if _, err := authorityKeyDecode(tc.in); err == nil {
			t.Errorf("%s: decoded without error, want failure", tc.name)
		} else if !strings.Contains(err.Error(), tc.wantSub) {
			t.Errorf("%s: err = %v, want it to mention %q", tc.name, err, tc.wantSub)
		}
	}
}

func TestAuthoritySecretDecode(t *testing.T) {
	// A valid 32-byte hex scalar decodes to a usable key.
	const ok = "5300a042c44499ec5d09d222043ec4af04bfc6bb5403c8aa9f6195c89523aa5d"
	if _, err := authoritySecretDecode(ok); err != nil {
		t.Fatalf("valid secret rejected: %v", err)
	}
	// Surrounding whitespace is tolerated (copy-paste).
	if _, err := authoritySecretDecode("  " + ok + "\n"); err != nil {
		t.Fatalf("whitespace-padded secret rejected: %v", err)
	}
	for _, tc := range []struct{ name, in, wantSub string }{
		{"empty", "", "32 bytes"},
		{"too short", "5300a0", "32 bytes"},
		{"too long", ok + "ff", "32 bytes"},
		{"not hex", "zz00a042c44499ec5d09d222043ec4af04bfc6bb5403c8aa9f6195c89523aa5d", "not hex"},
	} {
		if _, err := authoritySecretDecode(tc.in); err == nil {
			t.Errorf("%s: decoded without error, want failure", tc.name)
		} else if !strings.Contains(err.Error(), tc.wantSub) {
			t.Errorf("%s: err = %v, want it to mention %q", tc.name, err, tc.wantSub)
		}
	}
}
