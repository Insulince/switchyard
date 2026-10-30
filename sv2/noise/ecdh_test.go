package noise

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex %q: %v", s, err)
	}
	return b
}

func hex64(t *testing.T, s string) [64]byte {
	t.Helper()
	var a [64]byte
	b := mustHex(t, s)
	if len(b) != 64 {
		t.Fatalf("want 64 bytes, got %d", len(b))
	}
	copy(a[:], b)
	return a
}

// TestV2ECDH_BIP324Vectors pins v2_ecdh against the official BIP324 packet
// encoding test vectors (mid_shared_secret column).
func TestV2ECDH_BIP324Vectors(t *testing.T) {
	cases := []struct {
		name       string
		priv       string
		ours       string
		theirs     string
		initiating bool
		want       string
	}{
		{
			name:       "row in_idx=1 initiator",
			priv:       "61062ea5071d800bbfd59e2e8b53d47d194b095ae5a4df04936b49772ef0d4d7",
			ours:       "ec0adff257bbfe500c188c80b4fdd640f6b45a482bbc15fc7cef5931deff0aa186f6eb9bba7b85dc4dcc28b28722de1e3d9108b985e2967045668f66098e475b",
			theirs:     "a4a94dfce69b4a2a0a099313d10f9f7e7d649d60501c9e1d274c300e0d89aafaffffffffffffffffffffffffffffffffffffffffffffffffffffffff8faf88d5",
			initiating: true,
			want:       "c6992a117f5edbea70c3f511d32d26b9798be4b81a62eaee1a5acaa8459a3592",
		},
		{
			name:       "row in_idx=999 responder",
			priv:       "6f312890ec83bbb26798abaadd574684a53e74ccef7953b790fcc29409080246",
			ours:       "a8785af31c029efc82fa9fc677d7118031358d7c6a25b5779a9b900e5ccd94aac97eb36a3c5dbcdb2ca5843cc4c2fe0aaa46d10eb3d233a81c3dde476da00eef",
			theirs:     "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f0000000000000000000000000000000000000000000000000000000000000000",
			initiating: false,
			want:       "a6f79eb08243b6f65dbe42bfe4a6cf3f131d6963fa5d06c770a18f7b9c489b78",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			priv, _ := btcec.PrivKeyFromBytes(mustHex(t, tc.priv))
			ours := hex64(t, tc.ours)
			theirs := hex64(t, tc.theirs)
			got, err := v2ECDH(priv, theirs, ours, tc.initiating)
			if err != nil {
				t.Fatalf("v2ECDH: %v", err)
			}
			if want := mustHex(t, tc.want); !bytes.Equal(got[:], want) {
				t.Fatalf("shared secret = %x, want %x", got, want)
			}
		})
	}
}

// TestEphemeralAgreement verifies the two-party property: the initiator and the
// responder derive the same shared secret from each other's ellswift ephemeral
// keys, with the initiating flag distinguishing roles.
func TestEphemeralAgreement(t *testing.T) {
	a, err := generateEphemeral()
	if err != nil {
		t.Fatalf("generateEphemeral A: %v", err)
	}
	b, err := generateEphemeral()
	if err != nil {
		t.Fatalf("generateEphemeral B: %v", err)
	}
	if len(a.ellswift) != 64 || len(b.ellswift) != 64 {
		t.Fatalf("ellswift not 64 bytes")
	}

	secA, err := v2ECDH(a.priv, b.ellswift, a.ellswift, true) // A initiates
	if err != nil {
		t.Fatalf("ecdh A: %v", err)
	}
	secB, err := v2ECDH(b.priv, a.ellswift, b.ellswift, false) // B responds
	if err != nil {
		t.Fatalf("ecdh B: %v", err)
	}
	if secA != secB {
		t.Fatalf("shared secrets disagree:\n A %x\n B %x", secA, secB)
	}
}
