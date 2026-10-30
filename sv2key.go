package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

// SV2 authority keys travel as the Stratum V2 reference (SRI) key_utils format:
// base58check over a two-byte prefix {0x01, 0x00} followed by the 32-byte x-only
// secp256k1 public key. This is exactly the string a CONVOY gateway prints
// ("Stratum V2 authority public key (configure this on miners): 9b...") and the
// string the translator already takes on its command line, so it is the one an
// operator actually has in hand -- not a raw hex key they would have to derive.
//
// There is no Go implementation of this format anywhere in this project or the
// toolkit; the only reference is SRI's Rust key_utils crate. It is reimplemented
// here, and the exact layout -- the 0x01 0x00 prefix and standard double-SHA256
// base58check -- was reverse-verified byte for byte against a live CONVOY
// gateway's printed authority key. That matters because getting the prefix or
// checksum wrong does NOT fail loudly: it yields a key that simply never
// completes a Noise handshake. The format is therefore pinned by test
// (sv2key_test.go), so a refactor cannot drift it without a red test.
var sv2AuthorityPrefix = [2]byte{0x01, 0x00}

// The Bitcoin base58 alphabet (no 0, O, I, l), which SRI's bs58 also uses.
const b58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

func base58Encode(input []byte) string {
	n := new(big.Int).SetBytes(input)
	base := big.NewInt(58)
	mod := new(big.Int)
	var out []byte
	for n.Sign() > 0 {
		n.DivMod(n, base, mod)
		out = append(out, b58Alphabet[mod.Int64()])
	}
	// Each leading zero byte is one leading '1', which the big.Int above drops.
	for _, c := range input {
		if c != 0 {
			break
		}
		out = append(out, b58Alphabet[0])
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return string(out)
}

func base58Decode(s string) ([]byte, error) {
	n := new(big.Int)
	base := big.NewInt(58)
	for i := 0; i < len(s); i++ {
		idx := strings.IndexByte(b58Alphabet, s[i])
		if idx < 0 {
			return nil, fmt.Errorf("invalid base58 character %q", string(s[i]))
		}
		n.Mul(n, base)
		n.Add(n, big.NewInt(int64(idx)))
	}
	dec := n.Bytes()
	// Restore the leading zero bytes the '1' prefix encodes.
	var lead int
	for i := 0; i < len(s) && s[i] == b58Alphabet[0]; i++ {
		lead++
	}
	out := make([]byte, lead+len(dec))
	copy(out[lead:], dec)
	return out, nil
}

func doubleSHA(b []byte) [32]byte {
	h1 := sha256.Sum256(b)
	return sha256.Sum256(h1[:])
}

func base58CheckEncode(payload []byte) string {
	chk := doubleSHA(payload)
	return base58Encode(append(append([]byte{}, payload...), chk[:4]...))
}

func base58CheckDecode(s string) ([]byte, error) {
	raw, err := base58Decode(s)
	if err != nil {
		return nil, err
	}
	if len(raw) < 4 {
		return nil, fmt.Errorf("too short for a checksum")
	}
	payload, chk := raw[:len(raw)-4], raw[len(raw)-4:]
	exp := doubleSHA(payload)
	if !bytes.Equal(chk, exp[:4]) {
		return nil, fmt.Errorf("bad checksum")
	}
	return payload, nil
}

// authorityKeyEncode renders a gateway authority public key in the SRI format an
// operator would recognise. Used by tests and, later, the dashboard.
func authorityKeyEncode(pub *btcec.PublicKey) string {
	payload := append(sv2AuthorityPrefix[:len(sv2AuthorityPrefix):len(sv2AuthorityPrefix)], schnorr.SerializePubKey(pub)...)
	return base58CheckEncode(payload)
}

// authorityKeyDecode parses an SRI-format authority public key string into the
// x-only public key switchyard pins when it dials a gateway as an SV2 initiator.
func authorityKeyDecode(s string) (*btcec.PublicKey, error) {
	payload, err := base58CheckDecode(s)
	if err != nil {
		return nil, fmt.Errorf("authority key: %w", err)
	}
	if len(payload) != len(sv2AuthorityPrefix)+32 ||
		payload[0] != sv2AuthorityPrefix[0] || payload[1] != sv2AuthorityPrefix[1] {
		return nil, fmt.Errorf("authority key: unexpected layout (want %d-byte %x-prefixed payload, got %d bytes)",
			len(sv2AuthorityPrefix)+32, sv2AuthorityPrefix, len(payload))
	}
	pub, err := schnorr.ParsePubKey(payload[len(sv2AuthorityPrefix):])
	if err != nil {
		return nil, fmt.Errorf("authority key: %w", err)
	}
	return pub, nil
}

// authoritySecretDecode parses switchyard's OWN downstream authority secret: a
// 32-byte hex secp256k1 scalar, matching the gateway config's authority_secret_key
// convention. Its public half is what a downstream translator pins.
func authoritySecretDecode(s string) (*btcec.PrivateKey, error) {
	raw, err := hex.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, fmt.Errorf("authority secret: not hex: %w", err)
	}
	if len(raw) != 32 {
		return nil, fmt.Errorf("authority secret: want 32 bytes of hex, got %d", len(raw))
	}
	priv, _ := btcec.PrivKeyFromBytes(raw)
	return priv, nil
}

// newAuthoritySecret mints a fresh downstream authority secret, hex-encoded the
// way authoritySecretDecode expects. The crypto stays here with the rest of it;
// the config layer calls this to fill a rig that asked switchyard to generate
// its SV2 identity, instead of the operator running -genauthkey by hand.
//
// btcec.NewPrivateKey draws a scalar correctly in the secp256k1 range, which is
// the same reason main()'s -genauthkey mints through the library rather than
// hashing raw random bytes.
func newAuthoritySecret() (string, error) {
	priv, err := btcec.NewPrivateKey()
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(priv.Serialize()), nil
}
