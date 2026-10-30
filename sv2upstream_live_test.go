//go:build sv2live

// Live interop test against a running CONVOY SV2 gateway. Excluded from the normal
// build/test (and CI) by the sv2live tag; run explicitly with:
//
//	SV2_GATEWAY_ADDR=<gateway host:port> \
//	SV2_GATEWAY_CONFIG=<path to the gateway's config.json> \
//	go test -tags sv2live -run TestSv2UpstreamLive -v .
//
// The gateway's authority public key is derived from its own config secret so the test
// pins a real key (never printed).
package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

func TestSv2UpstreamLive(t *testing.T) {
	addr := os.Getenv("SV2_GATEWAY_ADDR")
	cfgPath := os.Getenv("SV2_GATEWAY_CONFIG")
	if addr == "" || cfgPath == "" {
		t.Skip("set SV2_GATEWAY_ADDR and SV2_GATEWAY_CONFIG to run the live test")
	}
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
	sk, err := hex.DecodeString(cfg.StratumV2.AuthoritySecretKey)
	if err != nil || len(sk) != 32 {
		t.Fatalf("bad authority secret: %v", err)
	}
	priv, _ := btcec.PrivKeyFromBytes(sk)
	authority := priv.PubKey()
	t.Logf("authority x-only pubkey: %x", schnorr.SerializePubKey(authority))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	gotWork := make(chan sv2Work, 8)
	u := newSv2Upstream(addr, authority, "switchyard-livetest", 2e12)
	u.onUpdate = func(w sv2Work) {
		if w.Ready {
			select {
			case gotWork <- w:
			default:
			}
		}
	}
	go func() {
		if err := u.run(ctx); err != nil && ctx.Err() == nil {
			t.Logf("upstream run ended: %v", err)
		}
	}()

	select {
	case w := <-gotWork:
		if len(w.ExtranoncePrefix) != 4 {
			t.Fatalf("extranonce_prefix = %x (want 4 bytes)", w.ExtranoncePrefix)
		}
		if w.PrevHash == [32]byte{} {
			t.Fatal("prevhash is zero")
		}
		t.Logf("OK: channel=%d extranonce_prefix=%x job=%d nbits=%08x ntime=%016x",
			w.ChannelID, w.ExtranoncePrefix, w.JobID, w.Nbits, w.Ntime)
		t.Logf("prevhash=%x", w.PrevHash)
		t.Logf("commitment=%x", w.Commitment)
	case <-time.After(20 * time.Second):
		t.Fatal("timed out waiting for ready work from the gateway")
	}
}
