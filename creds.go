package main

import (
	"context"
	"log"
	"sync"
	"time"
)

// credState holds one rig's stratum identity: the username and password the
// MINER offered, which switchyard then presents upstream unchanged.
//
// This is the mechanism behind switchyard's most important property, so it is
// worth stating plainly what changed and why.
//
// Switchyard used to invent an identity. Every upstream session was opened at
// startup and authorised with a name from config.json, long before any miner
// existed, and whatever the rig subsequently asked to be called was answered
// with "true" and discarded. That worked, but it put switchyard in the
// business of deciding who gets credited for the work -- a decision that is
// none of its business and which nobody downstream could audit. From the
// miner's side, a proxy that silently renames you is indistinguishable from a
// proxy that is stealing from you.
//
// Now the miner speaks first. Upstream sessions WAIT for a rig to authorise,
// then present exactly what it sent. Configure a miner the way you would to
// reach the gateway directly, point it at switchyard's port instead, and the
// bytes that reach the gateway are the ones you typed. Switchyard no longer
// has an opinion about your identity, which means it no longer needs to be
// trusted with one.
//
// The cost is small and honest: a rig's gateway sessions do not exist until
// that rig has connected once. There is nothing to lose by waiting -- a rig
// that has never connected has no work to place.
type credState struct {
	mu    sync.Mutex
	user  string
	pass  string
	known bool

	// members is every worker name that has authorised on this port under
	// the current identity: the roster of a virtual rig. After a rotation
	// the miners race back and whoever arrives first is momentarily alone;
	// without the roster a second name on an empty port is indistinguishable
	// from a lone miner renaming itself, and re-authorising the gateways
	// for it drops everyone. Cleared whenever the identity itself moves.
	members map[string]bool

	// changed is closed whenever the credentials move, and then replaced.
	// Waiters take a snapshot of both the values and this channel under the
	// lock, so there is no window in which an update is missed.
	changed chan struct{}
}

func newCredState() *credState {
	return &credState{changed: make(chan struct{})}
}

// get returns the current credentials plus a channel that closes when they
// change. Callers that find !known should wait on the channel.
func (c *credState) get() (user, pass string, known bool, changed <-chan struct{}) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.user, c.pass, c.known, c.changed
}

// set records what a miner offered and, if that is a new identity, starts a
// fresh roster with it as the only member. Reports whether anything actually
// moved, so an ordinary reconnect with the same identity does not churn six
// upstream sessions for nothing.
func (c *credState) set(user, pass string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.known && c.user == user && c.pass == pass {
		return false
	}
	c.user, c.pass, c.known = user, pass, true
	c.members = map[string]bool{user: true}
	close(c.changed)
	c.changed = make(chan struct{})
	return true
}

// join records a worker name as a member of this port's virtual rig without
// changing the identity presented upstream.
func (c *credState) join(user string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.members != nil {
		c.members[user] = true
	}
}

// isMember reports whether a worker name has already been on this port under
// the current identity.
func (c *credState) isMember(user string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.members[user]
}

// waitKnown blocks until this rig has told us who it is, or the context ends.
func (c *credState) waitKnown(ctx context.Context) (user, pass string, ok bool) {
	for {
		u, p, known, changed := c.get()
		if known {
			return u, p, true
		}
		select {
		case <-ctx.Done():
			return "", "", false
		case <-changed:
		}
	}
}

// noteCredentials records what a rig authorised as and, if that is new or
// different, drops every upstream session for that rig so they re-authorise
// under the new identity.
//
// Dropping rather than patching is deliberate: stratum has no way to change
// the authorised user on a live session, so the only correct response to a
// changed identity is a fresh handshake. This happens at most once per miner
// per reconfiguration, and never during ordinary mining.
func (co *coordinator) noteCredentials(rigIdx int, user, pass string) {
	if rigIdx < 0 || rigIdx >= len(co.creds) {
		return
	}
	// Recorded exactly as sent. There is no override path and no
	// normalisation: no trimming, no case folding, no "helpful" repair of an
	// address that looks malformed. Whatever the miner authorised with is
	// what the gateway is told, byte for byte.
	if !co.creds[rigIdx].set(user, pass) {
		return
	}
	log.Printf("[%s] authorising upstream as %q", co.rigLabel(rigIdx), user)
	for j := range co.ups[rigIdx] {
		co.ups[rigIdx][j].dropForReauth()
	}
}

// noteAuthorise is the one place a miner's mining.authorize turns into a
// decision about the port's upstream identity.
//
// A port is one virtual rig with one upstream identity, set by whoever
// arrives first; every name that joins after is recorded as a member. A
// different name can therefore mean two things. A member of the roster is a
// fleet miner coming back -- typically first through the door after a
// rotation, when it is momentarily alone -- and must not touch the identity:
// re-authorising the gateways for it drops everyone on the port for as long
// as the miners' own retry backoff. A name never seen here, arriving on an
// empty port, is a lone miner renaming itself, and is honoured exactly as it
// was before ports could hold more than one miner.
func (co *coordinator) noteAuthorise(rigIdx int, s *rigSession, user, pass string) {
	if rigIdx < 0 || rigIdx >= len(co.creds) {
		return
	}
	creds := co.creds[rigIdx]
	cur, _, known, _ := creds.get()
	switch {
	case !known || cur == user:
		co.noteCredentials(rigIdx, user, pass)
	case creds.isMember(user):
		// Back on the roster; the identity stands.
	case co.otherMiners(rigIdx, s) == 0:
		co.noteCredentials(rigIdx, user, pass)
	default:
		creds.join(user)
		log.Printf("[%s] miner %q joins a port already identified upstream as %q; keeping that",
			co.rigLabel(rigIdx), user, cur)
	}
}

// rigLabel is what to call a rig in logs and on the dashboard.
//
// The worker name the miner supplies is the only answer, because it is the
// name the pool will show and therefore the name the operator already thinks
// in. Before a miner has connected there is no such name at all, and the
// honest thing to display is the port it will connect to.
func (co *coordinator) rigLabel(rigIdx int) string {
	if rigIdx < 0 || rigIdx >= len(co.cfg.Rigs) {
		return "?"
	}
	if user, _, known, _ := co.creds[rigIdx].get(); known && user != "" {
		return user
	}
	// Nothing has connected yet, so there is no name to show -- and inventing
	// one from config would be inventing an identity. The port is the only
	// thing that exists before a miner does, and it is unique by validation.
	return "port " + portOf(co.cfg.Rigs[rigIdx].Listen)
}

// credsKnown reports whether this rig has ever told us who it is.
func (co *coordinator) credsKnown(rigIdx int) bool {
	if rigIdx < 0 || rigIdx >= len(co.creds) {
		return false
	}
	_, _, known, _ := co.creds[rigIdx].get()
	return known
}

const (
	// introExtranonce1 is handed to a miner on an introduction session -- the
	// short-lived connection that exists only to learn its worker name.
	//
	// It is deliberately recognisable rather than random. No work is ever
	// accepted on an introduction session, so this value cannot reach a pool;
	// if it ever turns up in a log or a capture, it means a session that should
	// have been closed was not.
	introExtranonce1     = "00000000"
	introExtranonce2Size = 4

	// introTimeout bounds how long an introduction session may sit open. A
	// miner that subscribes and never authorises is not going to identify
	// itself, and leaving the socket open forever would let one accumulate.
	introTimeout = 30 * time.Second
)

// rigLabels is every rig's current label, for a startup line that is readable
// whether the rigs were named in config or are still waiting to introduce
// themselves.
func (co *coordinator) rigLabels() []string {
	out := make([]string, len(co.cfg.Rigs))
	for i := range out {
		out[i] = co.rigLabel(i)
	}
	return out
}
