package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	configPath := flag.String("config", "config.json", "path to config file")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()

	// Answerable without a browser. Someone running a downloaded binary needs
	// to be able to say which one it is before they trust it with hashrate,
	// and "start it and open the dashboard" is a poor way to ask.
	if *showVersion {
		fmt.Println("switchyard", versionString())
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

		if err := srv.listen(cfg.StatusListen); err != nil {
			log.Fatalf("%v", err)
		}

		genCtx, cancel := context.WithCancel(ctx)
		co := newCoordinator(cfg)
		srv.swap(co, cfg)

		if !cfg.configured() {
			// Nothing to mine with, which is the expected state of a fresh
			// install rather than an error. The dashboard notices the same
			// thing and shows a setup form instead of a dashboard.
			log.Printf("switchyard: not configured yet -- open %s to set up rigs and pools",
				browseURL(cfg.StatusListen))
		} else {
			log.Printf("switchyard: %d rigs %v across %d pools, dwell %ds-%ds",
				len(cfg.Rigs), co.rigLabels(), len(cfg.Pools),
				cfg.MinDwellSeconds, cfg.MaxDwellSeconds)
			if len(cfg.Rigs) < len(cfg.Pools) {
				log.Printf("note: %d pool(s) will be dark at any moment -- unavoidable with fewer rigs than pools",
					len(cfg.Pools)-len(cfg.Rigs))
			}
			co.start(genCtx)
			go co.watchDwellCeiling(genCtx)
			go co.watchGateways(genCtx)

			for i := range cfg.Rigs {
				go func(idx int) {
					if err := serveRig(genCtx, co, idx); err != nil {
						// A listener that cannot bind is fatal to THIS
						// generation, not to the process. Reporting it on the
						// dashboard and staying up is what lets the operator
						// fix the port in the form; exiting would leave them
						// with no page to fix it from.
						log.Printf("rig listener failed: %v", err)
						srv.setErr(err.Error())
					}
				}(i)
			}
		}

		select {
		case <-ctx.Done():
			cancel()
			co.shutdown()
			log.Printf("shutting down")
			return
		case <-srv.reloadC:
			log.Printf("reloading from %s", *configPath)
			cancel()
			co.shutdown()
			// Let listeners actually release their ports before the next
			// generation tries to bind them.
			time.Sleep(settleDelay)
		}
	}
}
