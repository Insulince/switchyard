package main

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
)

// TestProbeStratumSV2AcceptsRealResponder is the fix for the false "not a stratum
// server": a genuine SV2 gateway completes the Noise handshake, and the SV2 probe
// must recognise it (the SV1 subscribe probe cannot, which was the bug).
func TestProbeStratumSV2AcceptsRealResponder(t *testing.T) {
	authority, _ := btcec.NewPrivateKey()
	static, _ := btcec.NewPrivateKey()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		// Present a valid responder handshake, then idle briefly so the probe
		// has finished reading act 2 before the socket closes.
		if _, err := sv2AcceptResponder(conn, authority, static, time.Minute, 5*time.Second); err != nil {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}()

	if err := probeStratumSV2(context.Background(), ln.Addr().String()); err != nil {
		t.Fatalf("valid SV2 responder rejected: %v", err)
	}
}

// TestProbeStratumSV2RejectsSV1Endpoint confirms the probe does not call an SV1
// (line-JSON) stratum server an SV2 gateway, and that the message carries the
// "is this an SV1 endpoint?" nudge the operator needs.
func TestProbeStratumSV2RejectsSV1Endpoint(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		// Read whatever the probe writes, then answer like an SV1 subscribe
		// reply: a short JSON line, nothing resembling a 234-byte act 2.
		_, _ = conn.Read(make([]byte, 64))
		_, _ = conn.Write([]byte(`{"id":1,"result":[[],"00",4],"error":null}` + "\n"))
		time.Sleep(100 * time.Millisecond)
	}()

	err = probeStratumSV2(context.Background(), ln.Addr().String())
	if err == nil {
		t.Fatal("expected an SV1 endpoint to be rejected by the SV2 probe")
	}
	if !strings.Contains(err.Error(), "not as an SV2 gateway") {
		t.Fatalf("got %q, want it to mention 'not as an SV2 gateway'", err)
	}
}
