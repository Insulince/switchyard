//go:build sv2live

// End-to-end live test of the SV2<->SV2 relay: an in-process miner pins the proxy's
// authority key, connects through the proxy to the real gateway, receives XBT work, and
// submits a share so the full round-trip (responder handshake, channel, work push, submit
// relay, upstream handshake, ack routing) is exercised. A dummy nonce is used, so the
// gateway returns a reject -- that reject travelling back to the miner is the proof the
// bidirectional relay works; valid-share acceptance is proven separately (real ASIC).
//
//	SV2_GATEWAY_ADDR=<gateway host:port> \
//	SV2_GATEWAY_CONFIG=<path to the gateway's config.json> \
//	go test -tags sv2live -run TestSv2ProxyLive -v .
package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"

	"github.com/Insulince/switchyard/sv2/common"
	"github.com/Insulince/switchyard/sv2/mining"
)

func TestSv2ProxyLive(t *testing.T) {
	addr := os.Getenv("SV2_GATEWAY_ADDR")
	cfgPath := os.Getenv("SV2_GATEWAY_CONFIG")
	if addr == "" || cfgPath == "" {
		t.Skip("set SV2_GATEWAY_ADDR and SV2_GATEWAY_CONFIG to run the live test")
	}
	// Gateway authority pubkey from its config secret.
	var cfg struct {
		StratumV2 struct {
			AuthoritySecretKey string `json:"authority_secret_key"`
		} `json:"stratum_v2"`
	}
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	sk, _ := hex.DecodeString(cfg.StratumV2.AuthoritySecretKey)
	gwPriv, _ := btcec.PrivKeyFromBytes(sk)
	gatewayAuthority := gwPriv.PubKey()

	// The proxy's own identity (the miner pins proxyAuthority.PubKey()).
	proxyAuthority, _ := btcec.NewPrivateKey()
	proxyStatic, _ := btcec.NewPrivateKey()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const proxyAddr = "127.0.0.1:34250"
	px := newSv2Proxy(proxyAddr, proxyAuthority, proxyStatic, addr, gatewayAuthority, 2e12)
	go func() {
		if err := px.Serve(ctx); err != nil && ctx.Err() == nil {
			t.Logf("proxy serve ended: %v", err)
		}
	}()
	time.Sleep(300 * time.Millisecond) // let the listener come up

	// --- in-process miner: dial the proxy, pinning its authority key ---
	conn, tr, err := sv2DialInitiator(proxyAddr, proxyAuthority.PubKey(), 10*time.Second)
	if err != nil {
		t.Fatalf("miner handshake with proxy: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(25 * time.Second))
	t.Log("OK: miner completed Noise handshake with the proxy (pinned proxy authority key)")

	scFrame, _ := common.SetupConnection{Protocol: 0, MinVersion: 2, MaxVersion: 2, Vendor: "miner"}.ToFrame()
	if err := tr.WriteFrame(conn, scFrame); err != nil {
		t.Fatal(err)
	}
	f, err := tr.ReadFrame(conn)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := common.ParseSetupConnectionSuccess(f); err != nil {
		t.Fatalf("setup success from proxy: %v", err)
	}
	t.Log("OK: SetupConnection.Success from proxy")

	var maxT [32]byte
	for i := range maxT {
		maxT[i] = 0xff
	}
	ocFrame, _ := mining.OpenExtendedMiningChannel{RequestID: 1, UserIdentity: "miner", NominalHashRate: 1e9, MaxTarget: maxT, MinExtranonceSize: 8}.ToFrame()
	if err := tr.WriteFrame(conn, ocFrame); err != nil {
		t.Fatal(err)
	}

	// Collect work until we have a channel + prevhash, then submit a dummy share.
	var channelID, jobID uint32
	var haveChannel, havePrev, submitted bool
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		f, err := tr.ReadFrame(conn)
		if err != nil {
			if err == io.EOF {
				t.Fatal("proxy closed the connection")
			}
			t.Fatalf("read from proxy: %v", err)
		}
		switch f.MsgType {
		case mining.TypeOpenExtendedMiningChannelSuccess:
			s, err := mining.ParseOpenExtendedMiningChannelSuccess(f)
			if err != nil {
				t.Fatalf("open success: %v", err)
			}
			if len(s.ExtranoncePrefix) != 4 {
				t.Fatalf("extranonce_prefix via proxy = %x (want 4 bytes)", s.ExtranoncePrefix)
			}
			channelID = s.ChannelID
			haveChannel = true
			t.Logf("OK: channel via proxy: id=%d extranonce_prefix=%x", s.ChannelID, s.ExtranoncePrefix)
		case mining.TypeNewExtendedMiningJob:
			j, _ := mining.ParseNewExtendedMiningJob(f)
			jobID = j.JobID
		case mining.TypeSetNewPrevHash:
			p, _ := mining.ParseSetNewPrevHash(f)
			if p.PrevHash == [32]byte{} {
				t.Fatal("prevhash via proxy is zero")
			}
			jobID = p.JobID
			havePrev = true
			t.Logf("OK: work via proxy: job=%d nbits=%08x prevhash=%x", p.JobID, p.Nbits, p.PrevHash)
		case mining.TypeSubmitSharesSuccess:
			s, _ := mining.ParseSubmitSharesSuccess(f)
			t.Logf("OK (round-trip): gateway ACCEPTED the share, relayed back through proxy (seq<=%d)", s.LastSequenceNumber)
			return
		case mining.TypeSubmitSharesError:
			s, _ := mining.ParseSubmitSharesError(f)
			t.Logf("OK (round-trip): gateway REJECTED the dummy share (%q), relayed back through proxy -- the bidirectional relay works", s.ErrorCode)
			return
		}
		if haveChannel && havePrev && !submitted {
			submitted = true
			en2 := []byte{0, 0, 0, 0, 0, 0, 0, 0}
			subFrame, _ := mining.SubmitSharesExtended{ChannelID: channelID, SequenceNumber: 1, JobID: jobID, Nonce: 0x0102030405060708, Ntime: 0, Extranonce: en2}.ToFrame()
			if err := tr.WriteFrame(conn, subFrame); err != nil {
				t.Fatalf("submit via proxy: %v", err)
			}
			t.Log("submitted a dummy share through the proxy; awaiting the gateway's ack...")
		}
	}
	t.Fatal("timed out before a submit ack came back through the proxy")
}
