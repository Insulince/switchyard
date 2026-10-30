package main

import (
	"context"
	"encoding/json"
	"time"
)

// poolLink is one rig's always-on session to one pool, whatever wire protocol
// that pool speaks. It is the seam that lets co.ups hold a MIXED mesh: an SV1
// pool is served by *upstream, an SV2 pool by *sv2Link, and the coordinator and
// the rig sessions drive both through this one surface without knowing which.
//
// The method set is deliberately nothing more than what the coordinator
// (coordinator.go) and a bound rig session (downstream.go) already ask of a
// gateway session. Extracting it changed no behaviour: *upstream had every one
// of these methods already, and the two that are new -- displayName and
// connInfo -- only move a field read that used to happen OUTSIDE the type back
// inside it, under the type's own lock.
//
// The protocol choice is made once, in newPoolLink, from the pool's config.
// Everything downstream of construction is protocol-blind on purpose: a rig
// binds to "a ready link", rotates by closing its session, and submits through
// whatever link it is bound to -- none of which depends on SV1 vs SV2.
type poolLink interface {
	// run keeps the session alive for the whole generation, reconnecting on its
	// own schedule. One goroutine per link, started by the coordinator.
	run(ctx context.Context)

	// isReady reports whether a rig can bind here right now. upstreamForRig
	// polls this to place a connecting miner, falling back to any ready link
	// when the scheduled one is not.
	isReady() bool

	// displayName is the operator's label for the pool behind this link. It is
	// the pool's configured name, surfaced as a method so callers never have to
	// reach through the link to its config to log or render it.
	displayName() string

	// dropForReauth closes the socket so the run loop reconnects and
	// re-authorises. The only correct response to a miner arriving under a new
	// worker name, since stratum cannot change the authorised user in place.
	dropForReauth()

	// attach binds a rig session to this link and returns the extranonce slice
	// and negotiated configure it should subscribe with. ok is false when the
	// link is not ready or has no slot free.
	attach(sess *rigSession) (en1 string, en2 int, configure json.RawMessage, ok bool)

	// detach unbinds a session, releasing its extranonce slot and dropping any
	// of its shares still in flight.
	detach(sess *rigSession)

	// primeSession sends the bound session the current difficulty and job, so
	// it starts hashing without waiting for the next upstream push.
	primeSession(sess *rigSession)

	// grantedConfigure is the mining.configure result this session actually
	// negotiated upstream, or nil. A rig must never be told it has an extension
	// its link does not hold.
	grantedConfigure() json.RawMessage

	// submit forwards a bound session's share upstream under this link's own
	// identity and routes the gateway's reply back to the rig.
	submit(sess *rigSession, downID json.RawMessage, params json.RawMessage) error

	// attachCanon / detachCanon / submitCanon are the canonical (SV2) downstream
	// surface, mirroring attach/detach/submit for a session that renders the work
	// itself. Both link types implement them: an SV2 pool relays unchanged, an
	// SV1 pool synthesises an sv2Work from its stratum state and translates the
	// share back to a mining.submit. One miner per port, so a canonical bind and
	// an SV1 bind are mutually exclusive.
	attachCanon(d canonDownstream) (sv2Work, bool)
	detachCanon(d canonDownstream)
	submitCanon(jobID uint32, nonce, ntime uint64, extranonce []byte) (<-chan sv2SubmitResult, error)

	// sealDwell closes the current fairness chunk and starts the next. Called on
	// every rotation, for every link, including idle ones (whose chunk is zero).
	sealDwell()

	// statsAt snapshots everything the dashboard reads from this link under a
	// single lock, consistent as of now.
	statsAt(now time.Time) upstreamStats

	// resetStats zeroes the measured counters without disturbing the live
	// session, for a clean baseline after rebalancing hardware.
	resetStats()

	// connInfo reports this link's outbound socket as the OS would see it, for
	// the self-reported outbound list. Read under the link's own lock.
	connInfo() linkConn
}

// linkConn is one link's view of its outbound socket, for outbound(). It is a
// snapshot taken under the link's lock rather than a window onto live fields, so
// a caller can never read a half-updated connection.
type linkConn struct {
	connected bool
	resolved  string
	local     string
	since     time.Time
}

// newPoolLink builds the right kind of link for a pool from its configured
// protocol. This is the one place the SV1/SV2 choice is made; everything after
// it is protocol-blind.
func newPoolLink(co *coordinator, rigIdx, poolIdx int, rig rigConfig, pool poolConfig) poolLink {
	switch pool.proto() {
	case "sv2":
		return newSv2Link(co, rigIdx, poolIdx, rig, pool)
	default:
		return newUpstream(co, rigIdx, poolIdx, rig, pool)
	}
}
