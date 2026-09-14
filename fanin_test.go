package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"
)

// A port is a virtual rig. Whatever is behind it -- one ASIC or a rented
// fleet -- shares one gateway session, and each miner gets a private slice
// of that session's extranonce so none of them can duplicate work. These
// tests pin the partitioning, its reuse, and the one case where it cannot
// apply.

func fanInUpstream(t *testing.T) *upstream {
	t.Helper()
	cfg := testConfig()
	u := newUpstream(newCoordinator(cfg), 0, cfg.Rigs[0], cfg.Pools[0])
	u.ready = true
	u.extranonce1 = "a1b2c3d4"
	u.extranonce2Size = 8
	return u
}

func pipeSession(t *testing.T, co *coordinator, user string) (*rigSession, net.Conn) {
	t.Helper()
	a, b := net.Pipe()
	s := newRigSession(co, testConfig().Rigs[0], 0, a)
	s.claimedUser = user
	t.Cleanup(func() { s.close(); _ = b.Close() })
	return s, b
}

func TestEachMinerGetsItsOwnExtranonceSlice(t *testing.T) {
	u := fanInUpstream(t)
	s1, _ := pipeSession(t, u.co, "one")
	s2, _ := pipeSession(t, u.co, "two")

	en1, en2, _, ok := u.attach(s1)
	if !ok {
		t.Fatal("first attach refused")
	}
	if en1 != "a1b2c3d400" || en2 != 7 {
		t.Errorf("miner 1 got en1=%s en2=%d, want a1b2c3d400 / 7", en1, en2)
	}
	en1, en2, _, ok = u.attach(s2)
	if !ok {
		t.Fatal("second attach refused -- that is the old one-slot behaviour")
	}
	if en1 != "a1b2c3d401" || en2 != 7 {
		t.Errorf("miner 2 got en1=%s en2=%d, want a1b2c3d401 / 7", en1, en2)
	}
	if u.minerCount() != 2 {
		t.Errorf("minerCount = %d, want 2 -- did the second attach evict the first?", u.minerCount())
	}
	select {
	case <-s1.done:
		t.Fatal("attaching a second miner closed the first")
	default:
	}

	// Freed slots are reused, lowest first.
	u.detach(s1)
	s3, _ := pipeSession(t, u.co, "three")
	en1, _, _, _ = u.attach(s3)
	if en1 != "a1b2c3d400" {
		t.Errorf("after miner 1 left, miner 3 got %s, want the freed slot a1b2c3d400", en1)
	}
}

// The submit the gateway sees must carry the 8-byte extranonce2 it handed
// out, which means the miner's 7 bytes with the slice prefix put back. Get
// this wrong and every share from a second miner is "unknown work".
func TestSubmitPutsThePrefixBack(t *testing.T) {
	u := fanInUpstream(t)
	gw, ours := net.Pipe()
	u.w = newConnWriter(ours)
	defer gw.Close()

	s1, _ := pipeSession(t, u.co, "one")
	s2, _ := pipeSession(t, u.co, "two")
	u.attach(s1)
	u.attach(s2)

	got := make(chan string, 1)
	go func() {
		line, _ := bufio.NewReader(gw).ReadString('\n')
		got <- line
	}()
	params := json.RawMessage(`["two.worker","job7","0000000000beef","66e0c0de","deadbeef"]`)
	if err := u.submit(s2, json.RawMessage("9"), params); err != nil {
		t.Fatal(err)
	}
	select {
	case line := <-got:
		if !strings.Contains(line, `"010000000000beef"`) {
			t.Errorf("forwarded submit = %s, want extranonce2 rebuilt as 01+0000000000beef", strings.TrimSpace(line))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("submit never reached the gateway")
	}
}

// A gateway with a single-byte extranonce2 leaves nothing to split. That
// port holds one miner, and it is the one already there: the newcomer is
// refused, because nothing on a port is ever evicted -- not even here.
func TestSingleByteExtranonceRefusesASecondMiner(t *testing.T) {
	u := fanInUpstream(t)
	u.extranonce2Size = 1
	s1, _ := pipeSession(t, u.co, "one")
	s2, _ := pipeSession(t, u.co, "two")

	en1, en2, _, ok := u.attach(s1)
	if !ok || en1 != "a1b2c3d4" || en2 != 1 {
		t.Errorf("legacy attach altered the extranonce: %s/%d ok=%v", en1, en2, ok)
	}
	if _, _, _, ok := u.attach(s2); ok {
		t.Fatal("with no byte to spare a second miner was accepted")
	}
	select {
	case <-s1.done:
		t.Fatal("the miner already on the port was evicted")
	default:
	}
	if u.minerCount() != 1 {
		t.Errorf("minerCount = %d, want 1", u.minerCount())
	}
}

// Nothing on a port is ever displaced, not even a miner with the same name
// as one already there. Behind a published Docker port every miner shares a
// source address, and rented hashrate shares a worker name, so any "this is
// a reconnect" heuristic ends up closing a live miner. Tried; reverted.
func TestSameNameMinersCoexist(t *testing.T) {
	u := fanInUpstream(t)
	first, _ := pipeSession(t, u.co, "rig.a")
	second, _ := pipeSession(t, u.co, "rig.a")
	u.attach(first)
	u.attach(second)
	select {
	case <-first.done:
		t.Fatal("a second miner with the same name displaced the first")
	default:
	}
	if u.minerCount() != 2 {
		t.Errorf("minerCount = %d, want 2", u.minerCount())
	}
}

// The coordinator counts miners per port but reasons about the PORT: it is
// connected while any miner is on it, and only the first one back ends a
// rotation's wait.
func TestPortIsConnectedWhileAnyMinerRemains(t *testing.T) {
	co := newCoordinator(config{
		Rigs:  []rigConfig{{Listen: ":23401"}},
		Pools: []poolConfig{{Name: "A", Host: "h", Port: 1, StatusPort: 2}},
	})
	s1 := &rigSession{claimedUser: "one"}
	s2 := &rigSession{claimedUser: "two"}
	co.setSession(0, s1)
	co.setSession(0, s2)

	d := co.status()
	if !d.Rigs[0].Connected || len(d.Rigs[0].Miners) != 2 {
		t.Fatalf("two miners bound: connected=%v miners=%v", d.Rigs[0].Connected, d.Rigs[0].Miners)
	}
	co.clearSession(0, s1)
	d = co.status()
	if !d.Rigs[0].Connected || len(d.Rigs[0].Miners) != 1 || d.Rigs[0].Miners[0] != "two" {
		t.Fatalf("one miner left: connected=%v miners=%v", d.Rigs[0].Connected, d.Rigs[0].Miners)
	}
	if d.Rigs[0].WaitingSeconds != 0 {
		t.Error("a port with a miner still on it reported as waiting")
	}
	co.clearSession(0, s2)
	if d = co.status(); d.Rigs[0].Connected {
		t.Fatal("no miners left but the port reports connected")
	}
}

// fleetPort is a coordinator with one port whose scheduled gateway is faked
// ready, so real rigSessions can be driven through subscribe/authorize over
// pipes. Sessions are started with fleetMiner; the gateway side of the
// upstream is a pipe nobody reads, which is fine because nothing here submits.
func fleetPort(t *testing.T) *coordinator {
	t.Helper()
	cfg := testConfig()
	co := newCoordinator(cfg)
	u := co.ups[0][0]
	gw, ours := net.Pipe()
	t.Cleanup(func() { _ = gw.Close(); _ = ours.Close() })
	u.mu.Lock()
	u.ready = true
	u.extranonce1 = "a1b2c3d4"
	u.extranonce2Size = 8
	u.w = newConnWriter(ours)
	u.mu.Unlock()
	return co
}

// fleetMiner connects a miner to the port, subscribes and authorises as
// name, and returns the miner's end of the socket. It waits for the
// authorize reply so the caller knows the identity decision has been made.
func fleetMiner(t *testing.T, co *coordinator, name string) net.Conn {
	t.Helper()
	miner, ours := net.Pipe()
	s := newRigSession(co, co.cfg.Rigs[0], 0, ours)
	go s.run()
	t.Cleanup(func() { _ = miner.Close() })
	r := bufio.NewReader(miner)
	send := func(line string) {
		_ = miner.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err := miner.Write([]byte(line + "\n")); err != nil {
			t.Fatalf("%s: write: %v", name, err)
		}
	}
	await := func(id string) {
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				t.Fatalf("%s: waiting for reply %s: %v", name, id, err)
			}
			if strings.Contains(line, `"id":`+id+`,`) {
				return
			}
		}
	}
	send(`{"id":1,"method":"mining.subscribe","params":["test/1"]}`)
	await("1")
	send(`{"id":2,"method":"mining.authorize","params":["` + name + `","x"]}`)
	await("2")
	return miner
}

// awaitEmpty waits for every miner on port 0 to be gone, as after a rotation.
func awaitEmpty(t *testing.T, co *coordinator) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for co.status().Rigs[0].Connected && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if co.status().Rigs[0].Connected {
		t.Fatal("port never emptied")
	}
}

func identityOf(co *coordinator) string {
	u, _, _, _ := co.creds[0].get()
	return u
}

// The failure this pins was seen live: two ASICs on one port, a block
// arrives, switchyard closes both, and whichever reconnects first is alone on
// the port with a name that is not the identity. Treating that as a rename
// re-authorised every gateway session and dropped the port for the miners'
// whole retry backoff -- thirty seconds of nothing, on a coin flip, every
// rotation. A name that has been on the port before is a fleet member coming
// back, and the identity stands.
func TestRosterMemberReturningAloneKeepsTheIdentity(t *testing.T) {
	co := fleetPort(t)
	a := fleetMiner(t, co, "rig.a")
	b := fleetMiner(t, co, "rig.b")
	if got := identityOf(co); got != "rig.a" {
		t.Fatalf("identity = %q, want the first miner rig.a", got)
	}

	// Rotation: everyone is closed, then rig.b wins the race back.
	_ = a.Close()
	_ = b.Close()
	awaitEmpty(t, co)
	fleetMiner(t, co, "rig.b")
	if got := identityOf(co); got != "rig.a" {
		t.Fatalf("rig.b returned first after a rotation and the identity became %q; the gateways were re-authorised and everyone was dropped", got)
	}
	fleetMiner(t, co, "rig.a")
	if got := identityOf(co); got != "rig.a" {
		t.Fatalf("identity = %q after the fleet returned", got)
	}
}

// The common case must be untouched by the roster: one miner, renamed by
// its operator, is honoured on reconnect exactly as before fan-in existed.
func TestLoneMinerRenamingItselfIsStillHonoured(t *testing.T) {
	co := fleetPort(t)
	a := fleetMiner(t, co, "old.name")
	_ = a.Close()
	awaitEmpty(t, co)
	fleetMiner(t, co, "new.name")
	if got := identityOf(co); got != "new.name" {
		t.Fatalf("identity = %q, want new.name -- a lone miner's rename was ignored", got)
	}
}

// A stranger joining a port that already has a miner on it never changes
// the identity, and the miner already hashing is not disturbed.
func TestSecondMinerNeverChangesTheIdentity(t *testing.T) {
	co := fleetPort(t)
	a := fleetMiner(t, co, "rig.a")
	fleetMiner(t, co, "rig.b")
	if got := identityOf(co); got != "rig.a" {
		t.Fatalf("identity = %q after a second miner joined, want rig.a", got)
	}
	_ = a.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	if _, err := a.Read(make([]byte, 1)); err == nil || !strings.Contains(err.Error(), "timeout") {
		t.Fatalf("first miner's socket did not stay quietly open: %v", err)
	}
}

// The test that matters most. A block is a share whose hash happened to
// clear the network target; it takes exactly the path every share takes.
// So the question "can slicing the extranonce destroy a block" is the
// question "does the gateway hash the same coinbase the miner hashed". Build
// it both ways -- from what the miner was told, and from what the gateway
// receives after submit -- and require the same double-SHA256.
func TestSlicedShareHashesToTheSameCoinbaseTheMinerHashed(t *testing.T) {
	u := fanInUpstream(t) // gateway said extranonce1=a1b2c3d4, extranonce2 size 8
	gw, ours := net.Pipe()
	u.w = newConnWriter(ours)
	defer gw.Close()

	s1, _ := pipeSession(t, u.co, "one")
	s2, _ := pipeSession(t, u.co, "two")
	u.attach(s1)
	minerEn1, minerEn2Size, _, _ := u.attach(s2)

	coinb1 := []byte("coinb1-prefix-bytes")
	coinb2 := []byte("coinb2-suffix-bytes")
	unhex := func(h string) []byte {
		b, err := hex.DecodeString(h)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	dsha := func(parts ...[]byte) [32]byte {
		first := sha256.Sum256(bytes.Join(parts, nil))
		return sha256.Sum256(first[:])
	}

	// What the miner hashed: its extranonce1 and the 7 bytes it rolled.
	rolled := strings.Repeat("ab", minerEn2Size)
	minerHash := dsha(coinb1, unhex(minerEn1), unhex(rolled), coinb2)

	// What the gateway receives.
	got := make(chan string, 1)
	go func() {
		line, _ := bufio.NewReader(gw).ReadString('\n')
		got <- line
	}()
	params := json.RawMessage(`["two","job1","` + rolled + `","66e0c0de","deadbeef"]`)
	if err := u.submit(s2, json.RawMessage("1"), params); err != nil {
		t.Fatal(err)
	}
	var fwd struct {
		Params []string `json:"params"`
	}
	select {
	case line := <-got:
		if err := json.Unmarshal([]byte(line), &fwd); err != nil {
			t.Fatalf("forwarded submit not decodable: %v: %s", err, line)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("submit never reached the gateway")
	}
	gwEn2 := fwd.Params[2]
	if len(gwEn2) != 2*u.extranonce2Size {
		t.Fatalf("gateway received extranonce2 of %d bytes, it announced %d", len(gwEn2)/2, u.extranonce2Size)
	}
	gatewayHash := dsha(coinb1, unhex(u.extranonce1), unhex(gwEn2), coinb2)

	if minerHash != gatewayHash {
		t.Fatalf("the gateway would hash a different coinbase than the miner did:\n miner   en1=%s en2=%s\n gateway en1=%s en2=%s",
			minerEn1, rolled, u.extranonce1, gwEn2)
	}
}
