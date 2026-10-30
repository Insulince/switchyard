package noise

import (
	"fmt"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ellswift"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

// This file implements the SV2 Noise_NX handshake on top of the ECDH primitive
// (ecdh.go), the symmetric/cipher state (cipher.go), and the authority
// certificate (signature.go). The message sequence follows SRI noise-sv2
// (responder.rs / initiator.rs), which is standard Noise NX:
//
//	-> e
//	<- e, ee, s, es, SIGNATURE_NOISE_MESSAGE
//
// Act 1 is the initiator's 64-byte ElligatorSwift ephemeral key (no payload).
// Act 2 is the responder's ephemeral (64), its encrypted static key (80), and
// the encrypted certificate (90): 234 bytes total. After act 2 both sides Split
// the symmetric state into a pair of transport ciphers.
//
// The responder is the role switchyard serves downstream (the SV2 gateway). A minimal
// initiator is included so the handshake can be exercised end-to-end in Go;
// real-world conformance is proven against stock SRI at the interop checkpoint.

const (
	// protocolName is the SV2 Noise suite. Pinned in handshake_test.go against
	// SRI's precomputed hash of this exact string.
	protocolName = "Noise_NX_Secp256k1+EllSwift_ChaChaPoly_SHA256"

	// actOneSize is the initiator's ElligatorSwift ephemeral key.
	actOneSize = EllswiftSize // 64
	// actTwoSize is responder ephemeral (64) + encrypted static (64+16) +
	// encrypted certificate (74+16).
	actTwoSize = EllswiftSize + (EllswiftSize + tagLen) + (sigNoiseMessageSize + tagLen) // 234

	encStaticOffset = EllswiftSize                           // 64
	encCertOffset   = EllswiftSize + (EllswiftSize + tagLen) // 144
)

// Responder holds the long-lived static key and the authority key that endorses
// it. One Responder serves many handshakes; each handshake draws a fresh
// ephemeral key internally.
type Responder struct {
	static       *btcec.PrivateKey
	authority    *btcec.PrivateKey
	certValidity time.Duration
}

// NewResponder builds a responder from its authority and static keypairs and the
// certificate validity window.
func NewResponder(authority, static *btcec.PrivateKey, certValidity time.Duration) *Responder {
	return &Responder{static: static, authority: authority, certValidity: certValidity}
}

// Respond consumes the initiator's act-1 ephemeral key and produces act 2 plus
// the established transport. now is the current unix time used to stamp the
// certificate window (injected so callers control the clock; no os/time here).
func (r *Responder) Respond(act1 [actOneSize]byte, now uint32) ([]byte, *Transport, error) {
	sym := newSymmetricState(protocolName)

	// Act 1: absorb the initiator ephemeral and its empty payload.
	sym.mixHash(act1[:])
	if _, err := sym.decryptAndHash(nil); err != nil {
		return nil, nil, fmt.Errorf("sv2/noise: act1 payload: %w", err)
	}

	// e: responder ephemeral.
	ePriv, eEll, err := ellswift.EllswiftCreate()
	if err != nil {
		return nil, nil, fmt.Errorf("sv2/noise: ephemeral: %w", err)
	}
	sym.mixHash(eEll[:])

	// ee: DH(responder ephemeral, initiator ephemeral). Party B => initiating=false.
	ee, err := v2ECDH(ePriv, act1, eEll, false)
	if err != nil {
		return nil, nil, fmt.Errorf("sv2/noise: ee: %w", err)
	}
	sym.mixKey(ee)

	// s: encrypted responder static key.
	sEll, err := ellswiftFromPriv(r.static)
	if err != nil {
		return nil, nil, fmt.Errorf("sv2/noise: static ellswift: %w", err)
	}
	encStatic, err := sym.encryptAndHash(sEll[:])
	if err != nil {
		return nil, nil, fmt.Errorf("sv2/noise: encrypt static: %w", err)
	}

	// es: DH(responder static, initiator ephemeral). Party B => initiating=false.
	es, err := v2ECDH(r.static, act1, sEll, false)
	if err != nil {
		return nil, nil, fmt.Errorf("sv2/noise: es: %w", err)
	}
	sym.mixKey(es)

	// SIGNATURE_NOISE_MESSAGE: encrypted authority certificate.
	validFrom := now
	notValidAfter := saturatingAddU32(now, uint32(r.certValidity.Seconds()))
	cert, err := buildSignatureNoiseMessage(r.authority, xOnlyFromPriv(r.static), validFrom, notValidAfter)
	if err != nil {
		return nil, nil, err
	}
	encCert, err := sym.encryptAndHash(cert)
	if err != nil {
		return nil, nil, fmt.Errorf("sv2/noise: encrypt certificate: %w", err)
	}

	out := make([]byte, 0, actTwoSize)
	out = append(out, eEll[:]...)
	out = append(out, encStatic...)
	out = append(out, encCert...)
	if len(out) != actTwoSize {
		return nil, nil, fmt.Errorf("sv2/noise: act2 assembled %d bytes, want %d", len(out), actTwoSize)
	}

	// Split: c1 = initiator->responder, c2 = responder->initiator.
	c1, c2 := sym.split()
	return out, &Transport{send: c2, recv: c1}, nil
}

// Initiator is the client side of the handshake. It is primarily a test/interop
// vehicle; production miners run stock SRI as the initiator.
type Initiator struct {
	ephemeral    *btcec.PrivateKey
	ephemeralEll [actOneSize]byte
	authority    *btcec.PublicKey // if nil, the certificate is not verified
}

// NewInitiator creates an initiator and returns the act-1 message to send. If
// authority is non-nil, ProcessAct2 verifies the responder certificate against
// it.
func NewInitiator(authority *btcec.PublicKey) (*Initiator, [actOneSize]byte, error) {
	priv, ell, err := ellswift.EllswiftCreate()
	if err != nil {
		return nil, [actOneSize]byte{}, fmt.Errorf("sv2/noise: ephemeral: %w", err)
	}
	return &Initiator{ephemeral: priv, ephemeralEll: ell, authority: authority}, ell, nil
}

// ProcessAct2 consumes the responder's act-2 message, verifies the certificate,
// and returns the established transport.
func (i *Initiator) ProcessAct2(act2 []byte, now uint32) (*Transport, error) {
	if len(act2) != actTwoSize {
		return nil, fmt.Errorf("sv2/noise: act2 size %d, want %d", len(act2), actTwoSize)
	}
	sym := newSymmetricState(protocolName)

	// Mirror act 1 (our own ephemeral + empty payload).
	sym.mixHash(i.ephemeralEll[:])
	if _, err := sym.decryptAndHash(nil); err != nil {
		return nil, fmt.Errorf("sv2/noise: act1 payload: %w", err)
	}

	// e: responder ephemeral.
	var re [EllswiftSize]byte
	copy(re[:], act2[:encStaticOffset])
	sym.mixHash(re[:])

	// ee: DH(initiator ephemeral, responder ephemeral). Party A => initiating=true.
	ee, err := v2ECDH(i.ephemeral, re, i.ephemeralEll, true)
	if err != nil {
		return nil, fmt.Errorf("sv2/noise: ee: %w", err)
	}
	sym.mixKey(ee)

	// s: decrypt responder static key.
	rsBytes, err := sym.decryptAndHash(act2[encStaticOffset:encCertOffset])
	if err != nil {
		return nil, fmt.Errorf("sv2/noise: decrypt static: %w", err)
	}
	var rsEll [EllswiftSize]byte
	copy(rsEll[:], rsBytes)

	// es: DH(initiator ephemeral, responder static). Party A => initiating=true.
	es, err := v2ECDH(i.ephemeral, rsEll, i.ephemeralEll, true)
	if err != nil {
		return nil, fmt.Errorf("sv2/noise: es: %w", err)
	}
	sym.mixKey(es)

	// SIGNATURE_NOISE_MESSAGE: decrypt and verify the certificate.
	certBytes, err := sym.decryptAndHash(act2[encCertOffset:])
	if err != nil {
		return nil, fmt.Errorf("sv2/noise: decrypt certificate: %w", err)
	}
	if i.authority != nil {
		staticXOnly, err := xOnlyFromEllswift(rsEll)
		if err != nil {
			return nil, fmt.Errorf("sv2/noise: recover static key: %w", err)
		}
		cert, err := parseSignatureNoiseMessage(certBytes)
		if err != nil {
			return nil, err
		}
		if err := cert.verify(staticXOnly, i.authority, now); err != nil {
			return nil, err
		}
	}

	// Split: c1 = initiator->responder, c2 = responder->initiator.
	c1, c2 := sym.split()
	return &Transport{send: c1, recv: c2}, nil
}

// Transport is a post-handshake encrypted channel: one cipher state per
// direction. send/recv are oriented from the local role's perspective.
type Transport struct {
	send *cipherState
	recv *cipherState
}

// Encrypt seals an outbound record.
func (t *Transport) Encrypt(ad, plaintext []byte) ([]byte, error) {
	return t.send.encrypt(ad, plaintext)
}

// Decrypt opens an inbound record.
func (t *Transport) Decrypt(ad, ciphertext []byte) ([]byte, error) {
	return t.recv.decrypt(ad, ciphertext)
}

// xOnlyFromPriv returns the 32-byte BIP340 x-only public key for a private key.
func xOnlyFromPriv(priv *btcec.PrivateKey) [32]byte {
	var out [32]byte
	copy(out[:], schnorr.SerializePubKey(priv.PubKey()))
	return out
}

// ellswiftFromPriv computes a fresh ElligatorSwift encoding of a private key's
// public key. The encoding is randomized, so each call yields different bytes
// for the same key (an x-only encoding; the recovered x-coordinate is stable).
func ellswiftFromPriv(priv *btcec.PrivateKey) ([EllswiftSize]byte, error) {
	var jac btcec.JacobianPoint
	btcec.ScalarBaseMultNonConst(&priv.Key, &jac)
	jac.ToAffine()
	u, t, err := ellswift.XElligatorSwift(&jac.X)
	if err != nil {
		return [EllswiftSize]byte{}, err
	}
	var out [EllswiftSize]byte
	ub := u.Bytes()
	tb := t.Bytes()
	copy(out[0:32], ub[:])
	copy(out[32:64], tb[:])
	return out, nil
}

// xOnlyFromEllswift recovers the 32-byte x-only public key encoded by an
// ElligatorSwift pair.
func xOnlyFromEllswift(ell [EllswiftSize]byte) ([32]byte, error) {
	var u, t btcec.FieldVal
	if u.SetByteSlice(ell[0:32]) {
		u.Normalize()
	}
	if t.SetByteSlice(ell[32:64]) {
		t.Normalize()
	}
	x, err := ellswift.XSwiftEC(&u, &t)
	if err != nil {
		return [32]byte{}, err
	}
	x.Normalize()
	return *x.Bytes(), nil
}
