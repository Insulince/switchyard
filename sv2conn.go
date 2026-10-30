package main

import (
	"io"
	"net"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"

	"github.com/Insulince/switchyard/sv2/noise"
)

// SV2 Noise NX handshake message sizes. Act 1 is the initiator's 64-byte ElligatorSwift
// ephemeral; act 2 is the responder's ephemeral + encrypted static key + certificate.
const (
	sv2Act1Size = 64
	sv2Act2Size = 234
)

// sv2DialInitiator dials a gateway and completes the SV2 Noise handshake as the initiator,
// verifying the gateway's certificate against the pinned authority public key. It returns
// the live connection and the post-handshake transport.
func sv2DialInitiator(addr string, authority *btcec.PublicKey, timeout time.Duration) (net.Conn, *noise.Transport, error) {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, nil, err
	}
	// The handshake must not hang forever; clear the deadline once it completes.
	_ = conn.SetDeadline(time.Now().Add(timeout))
	ini, act1, err := noise.NewInitiator(authority)
	if err != nil {
		_ = conn.Close()
		return nil, nil, err
	}
	if _, err := conn.Write(act1[:]); err != nil {
		_ = conn.Close()
		return nil, nil, err
	}
	act2 := make([]byte, sv2Act2Size)
	if _, err := io.ReadFull(conn, act2); err != nil {
		_ = conn.Close()
		return nil, nil, err
	}
	tr, err := ini.ProcessAct2(act2, uint32(time.Now().Unix()))
	if err != nil {
		_ = conn.Close()
		return nil, nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, tr, nil
}

// sv2AcceptResponder completes the SV2 Noise handshake as the responder on an accepted
// connection, presenting a certificate for the static key signed by the authority key.
// It returns the post-handshake transport.
func sv2AcceptResponder(conn net.Conn, authority, static *btcec.PrivateKey, certValidity, timeout time.Duration) (*noise.Transport, error) {
	_ = conn.SetDeadline(time.Now().Add(timeout))
	var act1 [sv2Act1Size]byte
	if _, err := io.ReadFull(conn, act1[:]); err != nil {
		return nil, err
	}
	r := noise.NewResponder(authority, static, certValidity)
	out, tr, err := r.Respond(act1, uint32(time.Now().Unix()))
	if err != nil {
		return nil, err
	}
	if _, err := conn.Write(out); err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	return tr, nil
}
