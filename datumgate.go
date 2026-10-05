package main

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"time"
)

// THE DATUM GATE. This is policy, not a safety check, and it is deliberately
// scorched earth.
//
// switchyard exists to spread a sovereign miner's hashrate across DATUM pools:
// every gateway it routes to builds block templates from the operator's own
// node. It will not route a single hash to an upstream that is anything else --
// a pool that hands out its own templates, or any other stratum endpoint that
// lets someone mine without running a node. Not by leaving that one entry
// dark while the rest mine on, either: one foreign upstream in the config and
// NOTHING runs, every rig port stays closed, until it is removed. The setup as
// a whole is invalid, and a partially working one would be an invitation to
// live with it.
//
// Do not soften this into a warning, a per-pool exclusion or a config flag.
//
// The evidence is the gateway's own status page, which the config already
// requires (see poolConfig.StatusPort). It can be faked. That is accepted: the
// gate exists to make the lazy path fail loudly, and anyone willing to serve a
// counterfeit DATUM page rather than run a node has opted out of the argument.
//
// Gateways that are DATUM but not currently pooled -- a Prime outage, or one
// configured to mine solo -- pass. They build from the operator's own node,
// which is the entire point; their pool state is gatewaywatch's business.

// errNotDatum means something answered on a status port and it is not a DATUM
// gateway. Only an answer can establish that. A port that does not answer
// proves nothing either way, and is treated as not yet verified.
var errNotDatum = errors.New("does not look like a DATUM gateway status page")

// Matches the page's <title> ("DATUM Gateway Status") and its header ("DATUM
// <span>GATEWAY</span>") once tags are stripped. Either alone is enough; a
// future DATUM that renamed both would stop every fleet running it, loudly,
// which is the right direction for this to fail in.
var datumMarkRE = regexp.MustCompile(`(?i)\bDATUM\s+Gateway\b`)

func isDatumPage(text string) bool { return datumMarkRE.MatchString(text) }

// foreignUpstreamError is the refusal. It names the entry so the operator
// knows exactly what to splice out.
type foreignUpstreamError struct {
	pool poolConfig
}

func (e *foreignUpstreamError) Error() string {
	return fmt.Sprintf("pool %q (%s, status port %d) is not a DATUM gateway. switchyard only "+
		"routes to DATUM gateways building templates from your own node, and refuses to run "+
		"anything while a configured upstream is not one. Remove it from the config to continue",
		e.pool.displayName(), e.pool.hostOrDefault(), e.pool.StatusPort)
}

// datumRecheck is how often an unverified gateway is asked again. Gateways
// typically start alongside switchyard and take a few seconds to serve their
// page; there is no deadline, because giving up would have to mean either
// mining unverified or refusing a gateway that was merely slow. A variable
// only so the tests need not wait it out.
var datumRecheck = 5 * time.Second

// verifyDatum blocks until every configured gateway has positively identified
// itself as DATUM, and returns nil. It returns a *foreignUpstreamError as soon
// as any one of them answers as something else, and ctx's error if cancelled
// first.
//
// Positive identification is required, not merely the absence of a bad
// answer: pointing the status port at nothing would otherwise be the way
// around this. waiting is told, on every pass that leaves something
// unverified, what is still outstanding and why.
func verifyDatum(ctx context.Context, pools []poolConfig, waiting func(string)) error {
	verified := make([]bool, len(pools))
	for {
		var pending error
		for i, p := range pools {
			if verified[i] {
				continue
			}
			text, _, err := fetchGatewayPage(ctx, p.apiURL())
			switch {
			case ctx.Err() != nil:
				return ctx.Err()
			case err != nil:
				if pending == nil {
					pending = fmt.Errorf("%s: %s", p.displayName(), shortReachError(err, p.StatusPort))
				}
			case !isDatumPage(text):
				return &foreignUpstreamError{pool: p}
			default:
				verified[i] = true
			}
		}
		if pending == nil {
			return nil
		}
		waiting(pending.Error())
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(datumRecheck):
		}
	}
}
