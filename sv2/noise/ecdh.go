// Package noise implements the Stratum V2 encrypted transport: a Noise_NX
// handshake whose cipher suite is Noise_NX_Secp256k1+EllSwift_ChaChaPoly_SHA256
// (sv2-spec 04). The DH is BIP324's v2_ecdh over secp256k1 with ElligatorSwift
// encoding; server authentication is a BIP340 Schnorr certificate signed by an
// authority key.
//
// This file is the bottom layer: ephemeral key generation and the v2_ecdh DH
// function, both delegated to btcd's audited ellswift package and pinned to the
// official BIP324 test vectors.
package noise

import (
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ellswift"
)

// EllswiftSize is the length of an ElligatorSwift-encoded public key.
const EllswiftSize = 64

// ephemeralKey is a freshly generated key plus its ellswift encoding (the bytes
// sent in the clear during the handshake).
type ephemeralKey struct {
	priv     *btcec.PrivateKey
	ellswift [EllswiftSize]byte
}

// generateEphemeral creates a new ephemeral key with its ellswift encoding.
func generateEphemeral() (*ephemeralKey, error) {
	priv, ell, err := ellswift.EllswiftCreate()
	if err != nil {
		return nil, fmt.Errorf("ellswift create: %w", err)
	}
	return &ephemeralKey{priv: priv, ellswift: ell}, nil
}

// v2ECDH computes the BIP324 v2_ecdh shared secret. theirs/ours are the peers'
// ellswift-encoded public keys; initiating selects the role ordering folded into
// the tagged hash, so the initiator (true) and responder (false) agree.
func v2ECDH(priv *btcec.PrivateKey, theirs, ours [EllswiftSize]byte, initiating bool) ([32]byte, error) {
	h, err := ellswift.V2Ecdh(priv, theirs, ours, initiating)
	if err != nil {
		return [32]byte{}, fmt.Errorf("v2_ecdh: %w", err)
	}
	var out [32]byte
	copy(out[:], h[:])
	return out, nil
}
