package noise

import (
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// This file is the Noise cipher/hash half of the SV2 transport suite
// Noise_NX_Secp256k1+EllSwift_ChaChaPoly_SHA256: the cipher state (ChaCha20-
// Poly1305 keyed by a single key with a monotonic 64-bit nonce) and the
// symmetric state (HKDF-SHA256 MixKey, SHA-256 MixHash, EncryptAndHash /
// DecryptAndHash, and Split). The DH function is supplied separately in ecdh.go
// and woven in by the handshake layer; nothing here depends on secp256k1, which
// is exactly why this half is identical to the reference Curve25519 suite and
// can be pinned against RFC 8439 / RFC 5869 vectors on its own.

const (
	hashLen = 32 // SHA-256 output, also the key length.
	tagLen  = 16 // Poly1305 authentication tag.
)

// noiseNonce builds the 12-byte ChaChaPoly nonce Noise prescribes: four zero
// bytes followed by the 8-byte little-endian counter.
func noiseNonce(n uint64) [chacha20poly1305.NonceSize]byte {
	var nonce [chacha20poly1305.NonceSize]byte
	binary.LittleEndian.PutUint64(nonce[4:], n)
	return nonce
}

// noiseHKDF2 is HKDF(chaining_key, input_key_material) with two outputs, as
// defined by the Noise spec. It maps exactly onto RFC 5869 with the chaining
// key as the salt, the material as the IKM, and empty info; the two HASHLEN
// outputs are the first two expansion blocks.
func noiseHKDF2(chainingKey [hashLen]byte, ikm []byte) (out1, out2 [hashLen]byte) {
	r := hkdf.New(sha256.New, ikm, chainingKey[:], nil)
	var buf [2 * hashLen]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		// HKDF over SHA-256 cannot fail for two blocks; treat as fatal.
		panic(fmt.Sprintf("sv2/noise: hkdf: %v", err))
	}
	copy(out1[:], buf[:hashLen])
	copy(out2[:], buf[hashLen:])
	return out1, out2
}

// cipherState is a Noise CipherState: a symmetric key plus a monotonically
// increasing nonce. The zero value is "no key"; callers use newCipherState.
type cipherState struct {
	aead cipher.AEAD
	k    [hashLen]byte
	n    uint64
}

// newCipherState initializes a cipher state with key k and nonce 0.
func newCipherState(k [hashLen]byte) *cipherState {
	aead, err := chacha20poly1305.New(k[:])
	if err != nil {
		// 32-byte key is always valid for ChaCha20-Poly1305.
		panic(fmt.Sprintf("sv2/noise: chacha20poly1305: %v", err))
	}
	return &cipherState{aead: aead, k: k}
}

// encrypt seals plaintext with the current nonce and associated data, then
// advances the nonce. The returned slice is ciphertext || 16-byte tag.
func (c *cipherState) encrypt(ad, plaintext []byte) ([]byte, error) {
	nonce := noiseNonce(c.n)
	ct := c.aead.Seal(nil, nonce[:], plaintext, ad)
	c.n++
	return ct, nil
}

// decrypt opens ciphertext (ciphertext || tag) with the current nonce and
// associated data, then advances the nonce only on success. An auth failure
// leaves the nonce untouched so the caller may abort the session cleanly.
func (c *cipherState) decrypt(ad, ciphertext []byte) ([]byte, error) {
	nonce := noiseNonce(c.n)
	pt, err := c.aead.Open(nil, nonce[:], ciphertext, ad)
	if err != nil {
		return nil, fmt.Errorf("sv2/noise: decrypt: %w", err)
	}
	c.n++
	return pt, nil
}

// symmetricState is a Noise SymmetricState: a chaining key, a running handshake
// hash, and (once keyed) a cipher state for handshake payload encryption.
type symmetricState struct {
	ck     [hashLen]byte
	h      [hashLen]byte
	cipher *cipherState // nil until the first mixKey
}

// newSymmetricState performs InitializeSymmetric(protocolName) the way SRI's
// noise-sv2 does: ck = (name padded to 32 if short, else HASH(name)); h =
// HASH(ck). The second hash is exactly the standard Noise empty-prologue MixHash
// (MixHash("") == HASH(h)) folded into init, so this matches reference Noise as
// well as SRI byte-for-byte. The SV2 suite name exceeds 32 bytes, so the hash
// branch is the live one; the short branch is kept for completeness.
func newSymmetricState(protocolName string) *symmetricState {
	var ck [hashLen]byte
	if len(protocolName) <= hashLen {
		copy(ck[:], protocolName)
	} else {
		ck = sha256.Sum256([]byte(protocolName))
	}
	h := sha256.Sum256(ck[:])
	return &symmetricState{ck: ck, h: h}
}

// mixKey folds new key material into the chaining key and (re)initializes the
// cipher state from the second HKDF output.
func (s *symmetricState) mixKey(ikm [hashLen]byte) {
	ck, tempK := noiseHKDF2(s.ck, ikm[:])
	s.ck = ck
	s.cipher = newCipherState(tempK)
}

// mixHash absorbs data into the running handshake hash.
func (s *symmetricState) mixHash(data []byte) {
	s.h = sha256.Sum256(append(append([]byte{}, s.h[:]...), data...))
}

// encryptAndHash encrypts plaintext with the current handshake hash as
// associated data, then mixes the ciphertext into the hash. Before the first
// mixKey there is no cipher, so the plaintext passes through (still hashed).
func (s *symmetricState) encryptAndHash(plaintext []byte) ([]byte, error) {
	if s.cipher == nil {
		s.mixHash(plaintext)
		return plaintext, nil
	}
	ct, err := s.cipher.encrypt(s.h[:], plaintext)
	if err != nil {
		return nil, err
	}
	s.mixHash(ct)
	return ct, nil
}

// decryptAndHash decrypts ciphertext with the current handshake hash as
// associated data, then mixes the original ciphertext into the hash.
func (s *symmetricState) decryptAndHash(ciphertext []byte) ([]byte, error) {
	if s.cipher == nil {
		s.mixHash(ciphertext)
		return ciphertext, nil
	}
	pt, err := s.cipher.decrypt(s.h[:], ciphertext)
	if err != nil {
		return nil, err
	}
	s.mixHash(ciphertext)
	return pt, nil
}

// split derives the two transport cipher states from the final chaining key.
// The first is the initiator-to-responder direction, the second the reverse;
// both parties compute the identical pair and pick by role.
func (s *symmetricState) split() (c1, c2 *cipherState) {
	k1, k2 := noiseHKDF2(s.ck, nil)
	return newCipherState(k1), newCipherState(k2)
}
