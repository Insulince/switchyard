package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
)

func main() {
	configPath := flag.String("config", "config.json", "path to config file")
	showVersion := flag.Bool("version", false, "print the version and exit")
	// SV2 authority-key helpers. An SV2 rig listener needs switchyard's own
	// authority secret in its rigConfig, and the downstream translator needs the
	// matching PUBLIC key on its command line. These two flags are the operator
	// path from one to the other, reusing the single pinned encoder
	// (authorityKeyEncode) so the string an operator pins can never drift from
	// the one switchyard presents.
	//
	// The secret is NEVER printed: genauthkey writes it (0600 hex) to a file and
	// prints only the public key, so a terminal, a log or a captured command
	// output can carry the public half without ever carrying the secret.
	genAuthKey := flag.String("genauthkey", "",
		"mint a fresh SV2 authority secret, write it (0600 hex) to this path, and print its public key")
	authPubOf := flag.String("authpub", "",
		"read an SV2 authority secret (hex) from this path and print its public key")
	flag.Parse()

	// Answerable without a browser. Someone running a downloaded binary needs
	// to be able to say which one it is before they trust it with hashrate,
	// and "start it and open the dashboard" is a poor way to ask.
	if *showVersion {
		fmt.Println("switchyard", versionString())
		return
	}

	// btcec.NewPrivateKey draws a scalar correctly in the secp256k1 range (never
	// zero or out of range), which raw random bytes would not guarantee -- the
	// reason to mint the key through the crypto library rather than /dev/urandom.
	if *genAuthKey != "" {
		priv, err := btcec.NewPrivateKey()
		if err != nil {
			log.Fatalf("genauthkey: %v", err)
		}
		secretHex := hex.EncodeToString(priv.Serialize())
		if err := os.WriteFile(*genAuthKey, []byte(secretHex+"\n"), 0o600); err != nil {
			log.Fatalf("genauthkey: writing secret to %s: %v", *genAuthKey, err)
		}
		fmt.Println(authorityKeyEncode(priv.PubKey()))
		return
	}
	if *authPubOf != "" {
		b, err := os.ReadFile(*authPubOf)
		if err != nil {
			log.Fatalf("authpub: %v", err)
		}
		priv, err := authoritySecretDecode(string(b))
		if err != nil {
			log.Fatalf("authpub: %v", err)
		}
		fmt.Println(authorityKeyEncode(priv.PubKey()))
		return
	}

	log.SetFlags(log.Ldate | log.Ltime)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	srv := newServer(*configPath)
	defer srv.close()

	// The supervisor loop. Each pass is one complete construction of the
	// mining machinery from the config FILE, and a reload is simply another
	// pass -- the same loadConfig, the same newCoordinator, the same
	// listeners, in the same order as the very first boot.
	//
	// This is why there is a loop at all rather than code that mutates the
	// running system in place. Applying a change in place means two ways to
	// arrive at a running switchyard, which sooner or later means two
	// different results from the same file. Here there is one way, and the
	// dashboard's save button is just a thing that writes the file and asks
	// for another pass.
	for {
		cfg, err := loadConfig(*configPath)
		if err != nil {
			// Only reachable at cold boot with a corrupt file: a reload can
			// only follow a config that was validated before being written.
			log.Fatalf("config: %v", err)
		}

		if err := srv.listen(cfg.dashboardAddr()); err != nil {
			log.Fatalf("%v", err)
		}

		genCtx, cancel := context.WithCancel(ctx)
		co := newCoordinator(cfg)
		co.feed = srv.feed
		srv.swap(co, cfg)

		// One refusal per generation is all anyone needs to hear; a second
		// from another gateway in the same pass is dropped, not queued.
		refusedC := make(chan error, 1)
		co.refuse = func(err error) {
			select {
			case refusedC <- err:
			default:
			}
		}
		// Closed once nothing in this generation can still be starting, so a
		// teardown never races the gate bringing the rigs up behind it.
		gateDone := make(chan struct{})

		if !cfg.configured() {
			// Nothing to mine with, which is the expected state of a fresh
			// install rather than an error. The dashboard notices the same
			// thing and shows a setup form instead of a dashboard.
			log.Printf("switchyard: not configured yet -- open %s to set up rigs and pools",
				browseURL(cfg.dashboardAddr()))
			close(gateDone)
		} else {
			log.Printf("switchyard: %d rigs %v across %d pools, dwell %ds-%ds",
				len(cfg.Rigs), co.rigLabels(), len(cfg.Pools),
				cfg.MinDwellSeconds, cfg.MaxDwellSeconds)
			// "At least", because the scheduler can double rigs up when their
			// deficits say so. A 0% pool is not counted: having no rig is what
			// it was asked for, not a consequence of the fleet's size.
			sharing := 0
			for _, tgt := range cfg.targets() {
				if tgt > 0 {
					sharing++
				}
			}
			if len(cfg.Rigs) < sharing {
				log.Printf("note: at least %d pool(s) will be dark at any moment -- unavoidable with fewer rigs than pools",
					sharing-len(cfg.Rigs))
			}
			go func() {
				defer close(gateDone)
				// Nothing -- not the upstream mesh, not a single rig port --
				// exists until every gateway has proven it is DATUM. See
				// datumgate.go.
				var said string
				err := verifyDatum(genCtx, cfg.Pools, func(why string) {
					srv.setGate(why, "")
					if why != said {
						log.Printf("waiting to verify gateways before starting: %s", why)
						said = why
					}
				})
				if err != nil {
					if genCtx.Err() == nil {
						co.refuse(err)
					}
					return
				}
				srv.setGate("", "")
				log.Printf("every gateway verified as DATUM")

				co.start(genCtx)
				go co.watchDwellCeiling(genCtx)
				go co.watchGateways(genCtx)
				go co.watchPoolShares(genCtx)

				for i := range cfg.Rigs {
					go func(idx int) {
						if err := serveRig(genCtx, co, idx); err != nil {
							// A listener that cannot bind is fatal to THIS
							// generation, not to the process. Reporting it on
							// the dashboard and staying up is what lets the
							// operator fix the port in the form; exiting would
							// leave them with no page to fix it from.
							log.Printf("rig listener failed: %v", err)
							srv.setErr(err.Error())
						}
					}(i)
				}
			}()
		}

		teardown := func() {
			cancel()
			<-gateDone
			co.shutdown()
		}

		select {
		case <-ctx.Done():
			teardown()
			log.Printf("shutting down")
			return
		case err := <-refusedC:
			teardown()
			log.Printf("REFUSING TO RUN: %v", err)
			srv.setGate("", err.Error())
			// Down until the config changes, not until the gateway does: the
			// setup is what is invalid. The dashboard stays up, because it
			// is where the offending entry gets removed.
			select {
			case <-ctx.Done():
				log.Printf("shutting down")
				return
			case <-srv.reloadC:
				log.Printf("reloading from %s", *configPath)
				time.Sleep(settleDelay)
			}
		case <-srv.reloadC:
			log.Printf("reloading from %s", *configPath)
			teardown()
			// Let listeners actually release their ports before the next
			// generation tries to bind them.
			time.Sleep(settleDelay)
		}
	}
}
