package main

import (
	"context"
	"reflect"
	"testing"
	"time"
)

// The central promise: what the miner sends is what goes upstream. Not a name
// from config, not a name switchyard picked -- the bytes the operator typed
// into their miner's own form.
func TestCredentialsArePassedThroughUnchanged(t *testing.T) {
	cfg := portOnlyConfig()
	co := newCoordinator(cfg)

	co.noteCredentials(0, "09864e88", "x")
	user, pass, known, _ := co.creds[0].get()
	if !known || user != "09864e88" || pass != "x" {
		t.Fatalf("got (%q, %q, known=%v), want the miner's own values", user, pass, known)
	}
}

// An upstream must not dial, let alone authorise, before it knows who it is
// authorising as. This is the mechanism that replaced inventing a name.
func TestUpstreamWaitsForTheMinerToIdentifyItself(t *testing.T) {
	cfg := portOnlyConfig()
	co := newCoordinator(cfg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan [2]string, 1)
	go func() {
		u, p, ok := co.creds[0].waitKnown(ctx)
		if ok {
			done <- [2]string{u, p}
		}
	}()

	select {
	case got := <-done:
		t.Fatalf("waitKnown returned %v before any miner authorised", got)
	case <-time.After(50 * time.Millisecond):
	}

	co.noteCredentials(0, "alice", "hunter2")
	select {
	case got := <-done:
		if got[0] != "alice" || got[1] != "hunter2" {
			t.Errorf("waitKnown = %v, want alice/hunter2", got)
		}
	case <-time.After(time.Second):
		t.Fatal("waitKnown did not wake when credentials arrived")
	}
}

// A context that ends while nothing has ever connected must release the
// waiter, or a reload would hang on rigs that never turned up.
func TestWaitKnownReleasesOnCancel(t *testing.T) {
	co := newCoordinator(portOnlyConfig())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, ok := co.creds[0].waitKnown(ctx); ok {
		t.Error("waitKnown reported success on a cancelled context")
	}
}

// An ordinary reconnect sends the same name again. Treating that as a change
// would tear down and rebuild every gateway session for this rig each time a
// miner blinked.
func TestUnchangedCredentialsDoNotChurnSessions(t *testing.T) {
	co := newCoordinator(portOnlyConfig())
	if !co.creds[0].set("rig1", "x") {
		t.Fatal("first set reported no change")
	}
	if co.creds[0].set("rig1", "x") {
		t.Error("re-authorising with identical credentials reported a change")
	}
	if !co.creds[0].set("rig1", "y") {
		t.Error("a changed password was not noticed")
	}
	if !co.creds[0].set("rig2", "y") {
		t.Error("a changed username was not noticed")
	}
}

// There is no override, and that is the point worth pinning: a rig is
// described by a port and nothing else, so there is no field through which
// switchyard could substitute a worker name even if someone wanted it to.
func TestARigIsDescribedByItsPortAlone(t *testing.T) {
	var r rigConfig
	if n := reflect.TypeOf(r).NumField(); n != 1 {
		t.Errorf("rigConfig has %d fields, want exactly 1 (listen)", n)
	}
	if reflect.TypeOf(r).Field(0).Name != "Listen" {
		t.Errorf("rigConfig's only field is %q, want Listen",
			reflect.TypeOf(r).Field(0).Name)
	}
}

// Before a miner connects there is no worker name to show, and inventing one
// would be inventing an identity. The port is the only thing that exists.
func TestRigLabelIsThePortUntilAMinerSpeaks(t *testing.T) {
	co := newCoordinator(portOnlyConfig())
	if got := co.rigLabel(0); got != "port 23401" {
		t.Errorf("unconnected rig labelled %q, want %q", got, "port 23401")
	}

	// Once a miner has spoken, its own name wins: that is the name the pool
	// will display, so it is the one worth reading here.
	co.noteCredentials(0, "from-miner", "x")
	if got := co.rigLabel(0); got != "from-miner" {
		t.Errorf("connected rig labelled %q, want the miner's own name", got)
	}
}

// portOnlyConfig is the shape this design is really about: a rig described by
// nothing but the port its miner connects to.
func portOnlyConfig() config {
	c := config{
		StatusListen: "127.0.0.1:0",
		Pools:        []poolConfig{{Name: "lazarus", Host: "127.0.0.1", Port: 23338, StatusPort: 7156}},
		Rigs:         []rigConfig{{Listen: "0.0.0.0:23401"}},
	}
	c.applyDefaults()
	return c
}

// Every rig waits for its miner now. Nothing in the config can stand in for
// an identity, so there is no path by which gateway sessions come up under a
// name the operator typed rather than one the hardware sent.
func TestEveryRigWaitsForItsMiner(t *testing.T) {
	co := newCoordinator(portOnlyConfig())
	if co.credsKnown(0) {
		t.Error("a rig claims to know its identity before any miner connected")
	}
	co.noteCredentials(0, "real-worker", "x")
	if !co.credsKnown(0) {
		t.Error("credentials from a miner were not recorded")
	}
	user, pass, _, _ := co.creds[0].get()
	if user != "real-worker" || pass != "x" {
		t.Errorf("got (%q, %q), want exactly what the miner sent", user, pass)
	}
}

// The introduction session is the answer to a protocol ordering problem that
// is easy to get wrong, and getting it wrong deadlocks a miner permanently.
//
// Stratum's order is subscribe, then authorize. A rig described by nothing but
// a port has not identified itself at subscribe time, so there is no identity
// to authorise upstream with and no gateway session to bind to. Dropping the
// connection there kills it before the authorize that would have unblocked it,
// and the miner retries into the same wall forever -- which is exactly what
// happened the first time this was built.
//
// So the extranonce handed out during an introduction has to be switchyard's
// own, and it must never be mistaken for a gateway's.
func TestIntroductionExtranonceIsNotAGatewayExtranonce(t *testing.T) {
	if introExtranonce1 == "" {
		t.Fatal("introduction extranonce is empty")
	}
	if introExtranonce2Size <= 0 {
		t.Errorf("introExtranonce2Size = %d, want positive", introExtranonce2Size)
	}
	// Recognisable on purpose. No work is ever accepted on an introduction
	// session, so this value cannot reach a pool; if it appears in a log or a
	// capture, a session that should have been closed was not.
	if introExtranonce1 != "00000000" {
		t.Errorf("introExtranonce1 = %q; it should stay recognisable at a glance", introExtranonce1)
	}
	if introTimeout <= 0 {
		t.Error("an introduction session with no timeout can accumulate forever")
	}
}
