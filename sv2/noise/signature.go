package noise

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

// Certificate verification failures an initiator can tell apart. They are
// exported as sentinels (wrapped with %w below) so a caller doing a handshake
// purely to CHECK a pinned authority key -- the dashboard's "test this key
// against the gateway" probe -- can distinguish "reached a gateway, but it is
// signed by a different authority key" (ErrCertSignatureInvalid: the key is
// wrong) from "reached a gateway, but its certificate is outside its validity
// window" (ErrCertWindow: clocks, not the key) without matching on error text.
var (
	ErrCertSignatureInvalid = errors.New("certificate signature invalid")
	ErrCertWindow           = errors.New("certificate outside its validity window")
)

// This file implements the SV2 SIGNATURE_NOISE_MESSAGE: the certificate the
// responder embeds in handshake act 2 to prove its static key is endorsed by an
// authority key for a bounded time window. Byte layout and signing scheme are
// taken from SRI noise-sv2 signature_message.rs (the oracle).

const (
	// certVersion is the SV2 certificate format version (SRI VERSION = 0).
	certVersion = 0
	// sigNoiseMessageSize is the plaintext certificate length: 2 (version) + 4
	// (valid_from) + 4 (not_valid_after) + 64 (Schnorr signature).
	sigNoiseMessageSize = 74
	// certTimeLeeway is the clock-drift tolerance applied on each edge of the
	// validity window, in seconds (SRI TIME_LEEWAY).
	certTimeLeeway = 10
)

// signatureNoiseMessage is the parsed certificate. All integers are little-endian
// on the wire.
type signatureNoiseMessage struct {
	version       uint16
	validFrom     uint32
	notValidAfter uint32
	signature     [64]byte
}

// certHeader serializes the 10-byte version+validity prefix that is both the wire
// prefix and the first half of the signed digest.
func certHeader(version uint16, validFrom, notValidAfter uint32) [10]byte {
	var h [10]byte
	binary.LittleEndian.PutUint16(h[0:2], version)
	binary.LittleEndian.PutUint32(h[2:6], validFrom)
	binary.LittleEndian.PutUint32(h[6:10], notValidAfter)
	return h
}

// certDigest is the 32-byte message the authority signs/verifies:
// SHA256(header10 || static_pub_xonly). SRI builds this via from_hashed_data,
// which is a single SHA-256 over the concatenation.
func certDigest(header [10]byte, staticXOnly [32]byte) [32]byte {
	buf := make([]byte, 0, len(header)+len(staticXOnly))
	buf = append(buf, header[:]...)
	buf = append(buf, staticXOnly[:]...)
	return sha256.Sum256(buf)
}

// buildSignatureNoiseMessage produces the 74-byte certificate: the authority key
// signs (header || responder static x-only key) and the signature is appended.
func buildSignatureNoiseMessage(authority *btcec.PrivateKey, staticXOnly [32]byte, validFrom, notValidAfter uint32) ([]byte, error) {
	h := certHeader(certVersion, validFrom, notValidAfter)
	digest := certDigest(h, staticXOnly)
	sig, err := schnorr.Sign(authority, digest[:])
	if err != nil {
		return nil, fmt.Errorf("sv2/noise: sign certificate: %w", err)
	}
	out := make([]byte, sigNoiseMessageSize)
	copy(out[0:10], h[:])
	copy(out[10:74], sig.Serialize())
	return out, nil
}

// parseSignatureNoiseMessage decodes a 74-byte certificate.
func parseSignatureNoiseMessage(b []byte) (signatureNoiseMessage, error) {
	if len(b) != sigNoiseMessageSize {
		return signatureNoiseMessage{}, fmt.Errorf("sv2/noise: certificate size %d, want %d", len(b), sigNoiseMessageSize)
	}
	var m signatureNoiseMessage
	m.version = binary.LittleEndian.Uint16(b[0:2])
	m.validFrom = binary.LittleEndian.Uint32(b[2:6])
	m.notValidAfter = binary.LittleEndian.Uint32(b[6:10])
	copy(m.signature[:], b[10:74])
	return m, nil
}

// verify checks the certificate's time window (with leeway) and that its Schnorr
// signature over (header || staticXOnly) validates under the authority key.
func (m signatureNoiseMessage) verify(staticXOnly [32]byte, authority *btcec.PublicKey, now uint32) error {
	if saturatingSubU32(m.validFrom, certTimeLeeway) > now || saturatingAddU32(m.notValidAfter, certTimeLeeway) < now {
		return fmt.Errorf("sv2/noise: %w: not valid at %d (window %d..%d)", ErrCertWindow, now, m.validFrom, m.notValidAfter)
	}
	h := certHeader(m.version, m.validFrom, m.notValidAfter)
	digest := certDigest(h, staticXOnly)
	sig, err := schnorr.ParseSignature(m.signature[:])
	if err != nil {
		return fmt.Errorf("sv2/noise: parse certificate signature: %w", err)
	}
	if !sig.Verify(digest[:], authority) {
		return fmt.Errorf("sv2/noise: %w", ErrCertSignatureInvalid)
	}
	return nil
}

func saturatingSubU32(a, b uint32) uint32 {
	if a < b {
		return 0
	}
	return a - b
}

func saturatingAddU32(a, b uint32) uint32 {
	if a > ^uint32(0)-b {
		return ^uint32(0)
	}
	return a + b
}
