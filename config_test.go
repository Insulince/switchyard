package main

import (
	"encoding/json"
	"math"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
)

// a freshly-generated, correctly-formatted SV2 authority public key string, for
// the config tests below. The matching secret is irrelevant to them -- validation
// only cares that the key is well-formed.
func testAuthorityKey(t *testing.T) string {
	t.Helper()
	priv, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return authorityKeyEncode(priv.PubKey())
}

// a valid 32-byte hex secp256k1 scalar for an sv2 rig's authoritySecret.
const testAuthoritySecret = "5300a042c44499ec5d09d222043ec4af04bfc6bb5403c8aa9f6195c89523aa5d"

// A fresh install has no config file, and that must not be fatal. The whole
// first-run flow depends on switchyard being able to start with nothing, serve
// its page, and be told what to do -- if a missing file killed the process,
// the first thing a new operator would meet is a program that refuses to boot
// and a file nobody has told them how to write.
func TestMissingConfigStartsUnconfigured(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nothing-here.json")

	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("missing config: err = %v, want nil", err)
	}
	if cfg.configured() {
		t.Error("missing config reports configured; want a setup prompt, not a dashboard")
	}
	// Defaults still have to be there, or the setup form opens with blanks
	// where it should be showing what it is about to use.
	if cfg.MinDwellSeconds == 0 || cfg.MaxDwellSeconds == 0 || cfg.DashboardPollSeconds == 0 {
		t.Errorf("defaults not applied to an empty config: %+v", cfg)
	}
}

// A file that exists but cannot be parsed is a BROKEN install, not a fresh
// one. Starting empty there would silently discard a working setup and hand
// the operator a setup wizard over the top of it.
func TestCorruptConfigIsFatal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(path); err == nil {
		t.Fatal("corrupt config parsed without error")
	}
}

// THE DIVERGENCE GUARANTEE. The dashboard never applies the struct it
// received; it writes the file and the supervisor rebuilds from that file. So
// what matters is that a config survives the round trip through disk
// unchanged -- if it did not, "saved in the UI" and "booted from disk" would
// be two different running systems, which is exactly what this design exists
// to make impossible.
func TestSavedConfigReloadsIdentically(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")

	want := config{
		DashboardPort: 7160,
		Pools: []poolConfig{
			{Name: "alpha", Host: "127.0.0.1", Port: 23336, StatusPort: 7154, Protocol: "sv1"},
			{Name: "beta", Host: "127.0.0.1", Port: 23337, StatusPort: 7155, Protocol: "sv1"},
		},
		Rigs: []rigConfig{
			{Port: 23401, Protocol: "sv1"},
		},
		MinDwellSeconds:      90,
		MaxDwellSeconds:      1200,
		DashboardPollSeconds: 3,
	}
	want.applyDefaults()
	if err := want.validate(); err != nil {
		t.Fatalf("fixture is not valid: %v", err)
	}
	if err := saveConfig(path, want); err != nil {
		t.Fatalf("saveConfig: %v", err)
	}

	got, err := loadConfig(path)
	if err != nil {
		t.Fatalf("reloading what we just wrote: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("config changed across a disk round trip\n saved: %+v\nloaded: %+v", want, got)
	}
}

// The temp-and-rename in saveConfig exists so a crash mid-write cannot leave a
// truncated file. The observable half of that promise is that the destination
// is never a partial write and no debris is left behind.
func TestSaveConfigLeavesNoTempFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	cfg := config{Pools: []poolConfig{{Name: "a", Host: "127.0.0.1", Port: 23336, StatusPort: 7154}}}
	cfg.applyDefaults()

	if err := saveConfig(path, cfg); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() != "config.json" {
			t.Errorf("left behind %q", e.Name())
		}
	}
}

// Rigs with nowhere to send work is not an empty config, it is a broken one --
// every placement calculation divides by the pool count. Pools without rigs,
// by contrast, is an ordinary halfway point during setup.
func TestRigsWithoutPoolsIsRejected(t *testing.T) {
	for _, c := range []struct {
		name    string
		cfg     config
		wantErr bool
	}{
		{"empty", config{}, false},
		{"pools only", config{Pools: []poolConfig{{Name: "a", Host: "127.0.0.1", Port: 23336, StatusPort: 7154, Protocol: "sv1"}}}, false},
		{"rigs only", config{Rigs: []rigConfig{{Port: 1, Protocol: "sv1"}}}, true},
		{"both", config{
			Pools: []poolConfig{{Name: "a", Host: "127.0.0.1", Port: 23336, StatusPort: 7154, Protocol: "sv1"}},
			Rigs:  []rigConfig{{Port: 1, Protocol: "sv1"}},
		}, false},
	} {
		cfg := c.cfg
		cfg.applyDefaults()
		err := cfg.validate()
		if (err != nil) != c.wantErr {
			t.Errorf("%s: err = %v, wantErr %v", c.name, err, c.wantErr)
		}
	}
}

// A suggestion must never collide with a port this config already claims, or
// the form would helpfully propose a value that fails validation the moment it
// is submitted.
func TestSuggestPortSkipsTakenPorts(t *testing.T) {
	taken := map[int]bool{defaultRigPortBase: true, defaultRigPortBase + 1: true}
	got := suggestPort(defaultRigPortBase, taken)
	if got == 0 {
		t.Fatal("no port suggested")
	}
	if taken[got] {
		t.Errorf("suggested %d, which was already taken", got)
	}
	if got < defaultRigPortBase {
		t.Errorf("suggested %d, below the base %d", got, defaultRigPortBase)
	}
}

// probeListen has to actually bind, not just parse. A port held by something
// else must come back as an error while the operator is still looking at the
// form -- not at the next boot, with a miner already pointed at it.
func TestProbeListenDetectsATakenPort(t *testing.T) {
	if err := probeListen("127.0.0.1:0"); err != nil {
		t.Fatalf("probing an ephemeral port failed: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("could not open a port to contend with: %v", err)
	}
	defer ln.Close()
	if err := probeListen(ln.Addr().String()); err == nil {
		t.Error("probing a port that is already bound reported success")
	}
}

// Renaming onto a path is refused in more ordinary situations than it first
// appears -- a config file bind-mounted by inode, a symlink into a store the
// process may write through but not unlink, a directory owned by someone else
// with a writable file inside it. In every one of those the FILE is writable
// and only the directory operation fails, so saving has to fall back to
// rewriting in place rather than reporting a failure the operator cannot act on.
func TestSaveConfigFallbackWritesInPlace(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")

	cfg := config{Pools: []poolConfig{{Name: "a", Host: "127.0.0.1", Port: 23336, StatusPort: 7154, Protocol: "sv1"}}}
	cfg.applyDefaults()
	if err := saveConfig(path, cfg); err != nil {
		t.Fatal(err)
	}

	cfg.Pools = append(cfg.Pools, poolConfig{Name: "b", Host: "127.0.0.1", Port: 23337, StatusPort: 7155, Protocol: "sv1"})
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := writeInPlace(path, append(data, '\n')); err != nil {
		t.Fatalf("writeInPlace: %v", err)
	}

	got, err := loadConfig(path)
	if err != nil {
		t.Fatalf("reloading an in-place write: %v", err)
	}
	if len(got.Pools) != 2 || got.Pools[1].Name != "b" {
		t.Errorf("in-place write did not land: %+v", got.Pools)
	}
}

// Truncation is the part that is easy to get wrong: writing a SHORTER config
// over a longer one without O_TRUNC leaves the tail of the old file behind,
// producing trailing garbage that fails to parse on the next boot.
func TestWriteInPlaceTruncates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := writeInPlace(path, []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaa")); err != nil {
		t.Fatal(err)
	}
	if err := writeInPlace(path, []byte("bb")); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "bb" {
		t.Errorf("file = %q, want %q -- old content was not truncated", b, "bb")
	}
}

// A loopback default is unreachable from outside a container, a VM or a
// package manager's sandbox -- which is where most operators run this. The
// default dashboard bind is every interface (dashboardAddr() -> ":7160"), so
// the first-run URL actually resolves from another device.
func TestDefaultDashboardPortBindsAllInterfaces(t *testing.T) {
	var c config
	c.applyDefaults()
	if c.DashboardPort != 7160 {
		t.Fatalf("default dashboardPort = %d, want 7160", c.DashboardPort)
	}
	if c.dashboardAddr() != ":7160" {
		t.Fatalf("default dashboardAddr = %q, want %q (every interface)", c.dashboardAddr(), ":7160")
	}
}

func TestBrowseURLIsAlwaysOpenable(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{":7160", "http://localhost:7160/"},
		{"0.0.0.0:7160", "http://localhost:7160/"},
		{"127.0.0.1:7160", "http://127.0.0.1:7160/"},
		{"192.168.1.9:7160", "http://192.168.1.9:7160/"},
	} {
		if got := browseURL(tc.in); got != tc.want {
			t.Errorf("browseURL(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// A key nobody recognises is a key the operator believes in. The README once
// documented a per-pool "payoutAddress" that no longer exists; loading a
// config that still carries it must fail loudly rather than pay the wrong
// address in silence.
func TestUnknownConfigKeysAreRejected(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	body := `{"pools":[{"name":"A","host":"h","port":1,"statusPort":2,` +
		`"payoutAddress":"bc1qexample"}],"rigs":[{"listen":":23401"}]}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := loadConfig(path)
	if err == nil {
		t.Fatal("a config carrying an obsolete payoutAddress loaded without complaint")
	}
	if !strings.Contains(err.Error(), "payoutAddress") {
		t.Fatalf("the error should name the offending key, got: %v", err)
	}
}

// The flag alone marks the solo entry. It has no pool, so it has no name, and
// a file that gives it one is wrong rather than quietly reinterpreted.
func TestSoloEntryHasNoName(t *testing.T) {
	c := config{Pools: []poolConfig{
		{Solo: true, Name: "RIPTIDE-old", Host: "gw-solo", Port: 23339, StatusPort: 7157, Protocol: "sv1"},
	}}
	c.applyDefaults()
	err := c.validate()
	if err == nil || !strings.Contains(err.Error(), "has no pool to name") {
		t.Fatalf("err = %v, want the no-name error", err)
	}

	c.Pools[0].Name = ""
	if err := c.validate(); err != nil {
		t.Fatalf("unnamed solo entry rejected: %v", err)
	}
	if got, want := c.Pools[0].displayName(), "solo"; got != want {
		t.Errorf("displayName = %q, want %q", got, want)
	}
}

// One solo slot is the supported path. A second marked entry is a config
// mistake, caught on load and on save alike.
func TestOnlyOneEntryMayBeSolo(t *testing.T) {
	c := config{Pools: []poolConfig{
		{Solo: true, Host: "gw-s1", Port: 23339, StatusPort: 7157, Protocol: "sv1"},
		{Solo: true, Host: "gw-s2", Port: 23340, StatusPort: 7158, Protocol: "sv1"},
	}}
	c.applyDefaults()
	err := c.validate()
	if err == nil || !strings.Contains(err.Error(), "only one pool can be solo") {
		t.Fatalf("err = %v, want the one-solo rule", err)
	}
}

// "solo" is switchyard's own label, in any case and with or without a solo
// gateway configured. Only that literal word is reserved.
func TestSoloNameIsReserved(t *testing.T) {
	second := map[string]poolConfig{
		"beside a solo gateway":  {Solo: true, Host: "gw-solo", Port: 23339, StatusPort: 7157, Protocol: "sv1"},
		"without a solo gateway": {Name: "other", Host: "gw-b", Port: 23337, StatusPort: 7155, Protocol: "sv1"},
	}
	for desc, other := range second {
		for name, wantOK := range map[string]bool{
			"solo": false, "Solo": false, "SOLO": false, "sOlO": false, " solo ": false,
			"Solo2": true, "s0l0": true, "solo pool": true,
		} {
			c := config{Pools: []poolConfig{{Name: name, Host: "gw-a", Port: 23336, StatusPort: 7154, Protocol: "sv1"}, other}}
			c.applyDefaults()
			err := c.validate()
			if wantOK && err != nil {
				t.Errorf("%s: name %q rejected: %v", desc, name, err)
			}
			if !wantOK && (err == nil || !strings.Contains(err.Error(), "reserved")) {
				t.Errorf("%s: name %q: err = %v, want the reserved-name error", desc, name, err)
			}
		}
	}
}

// Labels are what logs, health and /status key on, so they must be unique --
// including for unnamed entries, which the old name check skipped.
func TestLabelsMustBeUnique(t *testing.T) {
	c := config{Pools: []poolConfig{
		{Name: "gw-b:23337", Host: "gw-a", Port: 23336, StatusPort: 7154, Protocol: "sv1"},
		{Host: "gw-b", Port: 23337, StatusPort: 7155, Protocol: "sv1"},
	}}
	c.applyDefaults()
	err := c.validate()
	if err == nil || !strings.Contains(err.Error(), "duplicate pool name") {
		t.Fatalf("err = %v, want a duplicate-label error", err)
	}
}

func TestSoloSurvivesSaveAndLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	c := config{Pools: []poolConfig{{Solo: true, Host: "gw-solo", Port: 23339, StatusPort: 7157, Protocol: "sv1"}}}
	c.applyDefaults()
	if err := saveConfig(path, c); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	if strings.Contains(string(raw), `"name"`) {
		t.Errorf("a name was written for the solo entry:\n%s", raw)
	}
	got, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Pools[0].Solo || got.Pools[0].Name != "" {
		t.Errorf("after round trip: %+v, want solo with no name", got.Pools[0])
	}
}

// Two entries on one gateway address is a mistake about the ADDRESS, and the
// error must say so -- not report a "duplicate pool name" for entries the
// operator never named.
func TestSharedAddressIsReportedAsSuch(t *testing.T) {
	c := config{Pools: []poolConfig{
		{Host: "127.0.0.1", Port: 23336, StatusPort: 7154, Protocol: "sv1"},
		{Host: "127.0.0.1", Port: 23336, StatusPort: 7155, Protocol: "sv1"},
	}}
	c.applyDefaults()
	err := c.validate()
	if err == nil || !strings.Contains(err.Error(), "share the gateway address") {
		t.Fatalf("err = %v, want the shared-address error", err)
	}
}

// Omission is not a default. A config that names no protocol on a pool or a rig
// is rejected, not silently treated as sv1 -- a setting that decides where
// hashrate goes must be stated.
func TestAbsentProtocolIsRejected(t *testing.T) {
	// Pool with no protocol (rig is explicit so only the pool is at fault).
	cp := config{
		Pools: []poolConfig{{Name: "a", Host: "127.0.0.1", Port: 23336, StatusPort: 7154}},
		Rigs:  []rigConfig{{Port: 23401, Protocol: "sv1"}},
	}
	cp.applyDefaults()
	if err := cp.validate(); err == nil {
		t.Fatal("a pool with no protocol was accepted; want it rejected")
	}
	// Rig with no protocol (pool is explicit so only the rig is at fault).
	cr := config{
		Pools: []poolConfig{{Name: "a", Host: "127.0.0.1", Port: 23336, StatusPort: 7154, Protocol: "sv1"}},
		Rigs:  []rigConfig{{Port: 23401}},
	}
	cr.applyDefaults()
	if err := cr.validate(); err == nil {
		t.Fatal("a rig with no protocol was accepted; want it rejected")
	}
}

// An SV2 pool needs its authority key to verify the gateway; without it,
// switchyard would happily hand its hashrate to a hijacker. An SV1 pool carrying
// one is a belief that does nothing, which this codebase refuses on principle.
func TestPoolAuthorityKeyRules(t *testing.T) {
	key := testAuthorityKey(t)
	base := func(p poolConfig) config {
		c := config{Pools: []poolConfig{p}, Rigs: []rigConfig{{Port: 23401, Protocol: "sv1"}}}
		c.applyDefaults()
		return c
	}
	for _, tc := range []struct {
		name    string
		pool    poolConfig
		wantSub string // "" => must validate cleanly
	}{
		{"sv2 with key", poolConfig{Name: "a", Host: "h", Port: 23336, StatusPort: 7154, Protocol: "sv2", AuthorityKey: key}, ""},
		{"sv2 without key", poolConfig{Name: "a", Host: "h", Port: 23336, StatusPort: 7154, Protocol: "sv2"}, "no authorityKey"},
		{"sv2 bad key", poolConfig{Name: "a", Host: "h", Port: 23336, StatusPort: 7154, Protocol: "sv2", AuthorityKey: "not-a-key"}, "authority key"},
		{"sv1 with key", poolConfig{Name: "a", Host: "h", Port: 23336, StatusPort: 7154, Protocol: "sv1", AuthorityKey: key}, "only applies to an sv2"},
		{"no protocol", poolConfig{Name: "a", Host: "h", Port: 23336, StatusPort: 7154}, "protocol is required"},
		{"unknown protocol", poolConfig{Name: "a", Host: "h", Port: 23336, StatusPort: 7154, Protocol: "sv3"}, "unknown protocol"},
	} {
		c := base(tc.pool)
		err := c.validate()
		if tc.wantSub == "" {
			if err != nil {
				t.Errorf("%s: unexpected error %v", tc.name, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), tc.wantSub) {
			t.Errorf("%s: err = %v, want it to mention %q", tc.name, err, tc.wantSub)
		}
	}
}

// Mirror of the pool rules for a rig's own SV2 identity.
func TestRigAuthoritySecretRules(t *testing.T) {
	base := func(r rigConfig) config {
		c := config{Pools: []poolConfig{{Name: "a", Host: "h", Port: 23336, StatusPort: 7154, Protocol: "sv1"}}, Rigs: []rigConfig{r}}
		c.applyDefaults()
		return c
	}
	for _, tc := range []struct {
		name    string
		rig     rigConfig
		wantSub string
	}{
		{"sv2 with secret", rigConfig{Port: 23401, Protocol: "sv2", AuthoritySecret: testAuthoritySecret}, ""},
		{"sv2 without secret", rigConfig{Port: 23401, Protocol: "sv2"}, "no authoritySecret"},
		{"sv2 bad secret", rigConfig{Port: 23401, Protocol: "sv2", AuthoritySecret: "beef"}, "authority secret"},
		{"sv1 with secret", rigConfig{Port: 23401, Protocol: "sv1", AuthoritySecret: testAuthoritySecret}, "only applies to an sv2"},
		{"no protocol", rigConfig{Port: 23401}, "protocol is required"},
		{"unknown protocol", rigConfig{Port: 23401, Protocol: "sv2x"}, "unknown protocol"},
	} {
		c := base(tc.rig)
		err := c.validate()
		if tc.wantSub == "" {
			if err != nil {
				t.Errorf("%s: unexpected error %v", tc.name, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), tc.wantSub) {
			t.Errorf("%s: err = %v, want it to mention %q", tc.name, err, tc.wantSub)
		}
	}
}

// The divergence guarantee (see TestSavedConfigReloadsIdentically) must hold for
// SV2 configs too: an sv2 pool and rig, keys and all, survive the disk round
// trip byte-for-byte, or "saved in the UI" and "booted from disk" diverge.
func TestSV2ConfigReloadsIdentically(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")

	want := config{
		Pools: []poolConfig{
			{Name: "sv1pool", Host: "127.0.0.1", Port: 23336, StatusPort: 7154, Protocol: "sv1"},
			{Name: "sv2pool", Host: "127.0.0.1", Port: 23338, StatusPort: 7156, Protocol: "sv2", AuthorityKey: testAuthorityKey(t)},
		},
		Rigs: []rigConfig{
			{Port: 23401, Protocol: "sv1"},
			{Port: 23402, Protocol: "sv2", AuthoritySecret: testAuthoritySecret},
		},
	}
	want.applyDefaults()
	if err := want.validate(); err != nil {
		t.Fatalf("fixture is not valid: %v", err)
	}
	if err := saveConfig(path, want); err != nil {
		t.Fatalf("saveConfig: %v", err)
	}
	got, err := loadConfig(path)
	if err != nil {
		t.Fatalf("reloading what we just wrote: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("sv2 config changed across a disk round trip\n saved: %+v\nloaded: %+v", want, got)
	}
}

// The dashboard never sends switchyard's own SV2 secret; it sends a sentinel.
// resolveRigIdentities is what turns those sentinels into real credentials on
// the save path, and getting it wrong either leaks a secret into the browser
// (by not redacting) or silently wipes one (by not keeping it).
func TestResolveRigIdentitiesResolvesSentinels(t *testing.T) {
	existing, err := newAuthoritySecret()
	if err != nil {
		t.Fatal(err)
	}
	running := config{Rigs: []rigConfig{
		{Port: 23404, Protocol: "sv2", AuthoritySecret: existing},
	}}
	in := &config{Rigs: []rigConfig{
		{Port: 23404, Protocol: "sv2", AuthoritySecret: authSecretKeep},     // keep -> existing
		{Port: 23405, Protocol: "sv2", AuthoritySecret: authSecretGenerate}, // generate -> fresh
		{Port: 23401, Protocol: "sv1", AuthoritySecret: authSecretKeep},     // sv1 -> cleared
		{Port: 23406, Protocol: "sv2", AuthoritySecret: existing},           // manual -> untouched
	}}
	if err := resolveRigIdentities(in, running); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if in.Rigs[0].AuthoritySecret != existing {
		t.Errorf("keep did not copy the on-file secret: %q", in.Rigs[0].AuthoritySecret)
	}
	if s := in.Rigs[1].AuthoritySecret; s == authSecretGenerate || len(s) != 64 {
		t.Errorf("generate did not mint a 32-byte hex secret: %q", s)
	}
	if _, err := in.Rigs[1].authorityPriv(); err != nil {
		t.Errorf("generated secret is not a usable authority secret: %v", err)
	}
	if in.Rigs[2].AuthoritySecret != "" {
		t.Errorf("an sv1 rig kept a sentinel secret: %q", in.Rigs[2].AuthoritySecret)
	}
	if in.Rigs[3].AuthoritySecret != existing {
		t.Errorf("a hand-supplied secret was altered: %q", in.Rigs[3].AuthoritySecret)
	}
}

// A rig's port is editable, so a kept identity has to follow the rig rather
// than stay with the number. Two rigs swapping ports must each keep their own
// secret, and a rig moved to a brand-new port must take its secret with it.
// Resolving by the CURRENT port would hand each rig the other's identity on a
// swap, and lose it entirely on a move.
func TestKeepFollowsARemappedPort(t *testing.T) {
	a, err := newAuthoritySecret()
	if err != nil {
		t.Fatal(err)
	}
	b, err := newAuthoritySecret()
	if err != nil {
		t.Fatal(err)
	}
	running := config{Rigs: []rigConfig{
		{Port: 23401, Protocol: "sv2", AuthoritySecret: a},
		{Port: 23402, Protocol: "sv2", AuthoritySecret: b},
	}}
	in := &config{Rigs: []rigConfig{
		{Port: 23402, Protocol: "sv2", AuthoritySecret: keepSentinel(23401)}, // swapped
		{Port: 23401, Protocol: "sv2", AuthoritySecret: keepSentinel(23402)}, // swapped
		{Port: 23409, Protocol: "sv1", AuthoritySecret: keepSentinel(23401)}, // flipped to sv1
	}}
	if err := resolveRigIdentities(in, running); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if in.Rigs[0].AuthoritySecret != a || in.Rigs[1].AuthoritySecret != b {
		t.Error("swapping two rigs' ports swapped their identities too; each must keep its own")
	}
	if in.Rigs[2].AuthoritySecret != "" {
		t.Errorf("an sv1 rig kept a sentinel secret: %q", in.Rigs[2].AuthoritySecret)
	}

	moved := &config{Rigs: []rigConfig{{Port: 23460, Protocol: "sv2", AuthoritySecret: keepSentinel(23402)}}}
	if err := resolveRigIdentities(moved, running); err != nil {
		t.Fatalf("resolve after a move: %v", err)
	}
	if moved.Rigs[0].AuthoritySecret != b {
		t.Error("a rig moved to a new port lost its identity")
	}

	for _, sec := range []string{keepSentinel(23499), keepPrefix + "x"} {
		bad := &config{Rigs: []rigConfig{{Port: 23401, Protocol: "sv2", AuthoritySecret: sec}}}
		if err := resolveRigIdentities(bad, running); err == nil {
			t.Errorf("keep %q resolved with nothing on file; want an error, not an empty secret", sec)
		}
	}
}

func TestResolveRigIdentitiesKeepWithoutPriorFails(t *testing.T) {
	in := &config{Rigs: []rigConfig{
		{Port: 23404, Protocol: "sv2", AuthoritySecret: authSecretKeep},
	}}
	if err := resolveRigIdentities(in, config{}); err == nil {
		t.Fatal("keeping an identity that is not on file should fail, not silently produce an empty secret")
	}
}

// A staged secret is handed out once, to the save that resolves it, and then is
// gone -- otherwise generated-but-unsaved secrets would pile up in memory.
func TestStagedSecretsAreConsumedOnce(t *testing.T) {
	s := newServer("")
	secret, err := newAuthoritySecret()
	if err != nil {
		t.Fatal(err)
	}
	h := s.stageSecret(secret)
	if got, ok := s.consumeStaged(h); !ok || got != secret {
		t.Fatalf("staged secret not returned intact: got %q ok=%v", got, ok)
	}
	if _, ok := s.consumeStaged(h); ok {
		t.Fatal("a staged secret must be consumable only once")
	}
}

// sharep makes a *float64 for a share literal in a fixture. Shares are pointers
// so an explicit 0 is distinguishable from "unset"; the tests need both.
func sharep(v float64) *float64 { return &v }

// No shares at all is the default, and it means an even split -- exactly what
// every pre-existing config already has and relies on. targets must reflect
// that without any share field being present.
func TestSharesAbsentIsEvenSplit(t *testing.T) {
	c := config{Pools: []poolConfig{
		{Name: "a", Host: "127.0.0.1", Port: 23336, StatusPort: 7154, Protocol: "sv1"},
		{Name: "b", Host: "127.0.0.1", Port: 23337, StatusPort: 7155, Protocol: "sv1"},
		{Name: "c", Host: "127.0.0.1", Port: 23338, StatusPort: 7156, Protocol: "sv1"},
	}}
	c.applyDefaults()
	if err := c.validate(); err != nil {
		t.Fatalf("a config with no shares was rejected: %v", err)
	}
	got := c.targets()
	for i, want := range []float64{1.0 / 3, 1.0 / 3, 1.0 / 3} {
		if got[i] != want {
			t.Errorf("targets()[%d] = %v, want %v (even split)", i, got[i], want)
		}
	}
}

// Shares are all-or-nothing: a split where only some of the whole is named is
// not a split anyone can act on, so a config that sets a share on some pools
// and not others is refused rather than guessed at.
func TestSharesMustBeAllOrNone(t *testing.T) {
	c := config{Pools: []poolConfig{
		{Name: "a", Host: "127.0.0.1", Port: 23336, StatusPort: 7154, Share: sharep(60), Protocol: "sv1"},
		{Name: "b", Host: "127.0.0.1", Port: 23337, StatusPort: 7155, Protocol: "sv1"},
	}}
	c.applyDefaults()
	err := c.validate()
	if err == nil || !strings.Contains(err.Error(), "every pool sets one or none") {
		t.Fatalf("err = %v, want the all-or-nothing error", err)
	}
}

// Shares that do not total 100 are not a division of the whole -- and there is
// no honest value to invent for the remainder, so this refuses with a named
// error rather than normalising behind the operator's back.
func TestSharesMustSumTo100(t *testing.T) {
	c := config{Pools: []poolConfig{
		{Name: "a", Host: "127.0.0.1", Port: 23336, StatusPort: 7154, Share: sharep(60), Protocol: "sv1"},
		{Name: "b", Host: "127.0.0.1", Port: 23337, StatusPort: 7155, Share: sharep(30), Protocol: "sv1"},
	}}
	c.applyDefaults()
	err := c.validate()
	if err == nil || !strings.Contains(err.Error(), "not 100%") {
		t.Fatalf("err = %v, want the sum-to-100 error", err)
	}
}

// A share is a percentage; a value outside 0..100 is a typo, named as such.
// The total in the error is what the operator would add up by hand, not the
// binary noise of summing floats: these three sum to 60.599999999999994.
func TestShareTotalInErrorIsRounded(t *testing.T) {
	cfg := config{Pools: []poolConfig{
		{Name: "a", Host: "h", Port: 1, StatusPort: 2, Share: sharep(10.1), Protocol: "sv1"},
		{Name: "b", Host: "h", Port: 3, StatusPort: 4, Share: sharep(20.2), Protocol: "sv1"},
		{Name: "c", Host: "h", Port: 5, StatusPort: 6, Share: sharep(30.3), Protocol: "sv1"},
	}}
	cfg.applyDefaults()
	err := cfg.validate()
	if err == nil {
		t.Fatal("shares totalling 60.6 were accepted")
	}
	if !strings.Contains(err.Error(), "total 60.6%") {
		t.Errorf("error = %q, want it to report a total of 60.6%%", err)
	}
}

func TestShareOutOfRangeIsRejected(t *testing.T) {
	c := config{Pools: []poolConfig{
		{Name: "a", Host: "127.0.0.1", Port: 23336, StatusPort: 7154, Share: sharep(140), Protocol: "sv1"},
		{Name: "b", Host: "127.0.0.1", Port: 23337, StatusPort: 7155, Share: sharep(-40), Protocol: "sv1"},
	}}
	c.applyDefaults()
	err := c.validate()
	if err == nil || !strings.Contains(err.Error(), "0 to 100") {
		t.Fatalf("err = %v, want the range error", err)
	}
}

// A valid split: every pool sets a share, they total 100, the solo entry is in
// the division like any other pool, and targets reflects the fractions.
func TestValidSharesIncludingSolo(t *testing.T) {
	c := config{Pools: []poolConfig{
		{Name: "a", Host: "127.0.0.1", Port: 23336, StatusPort: 7154, Share: sharep(50), Protocol: "sv1"},
		{Name: "b", Host: "127.0.0.1", Port: 23337, StatusPort: 7155, Share: sharep(30), Protocol: "sv1"},
		{Solo: true, Host: "gw-solo", Port: 23339, StatusPort: 7157, Share: sharep(20), Protocol: "sv1"},
	}}
	c.applyDefaults()
	if err := c.validate(); err != nil {
		t.Fatalf("a valid 50/30/20 split with a solo slot was rejected: %v", err)
	}
	got := c.targets()
	for i, want := range []float64{0.50, 0.30, 0.20} {
		if got[i] != want {
			t.Errorf("targets()[%d] = %v, want %v", i, got[i], want)
		}
	}
}

// An explicit 0 means "this pool, deliberately, gets nothing" and must survive
// the disk round trip as a 0 -- not vanish under omitempty and read back as
// "unset". This is the whole reason Share is a pointer, so the regression is
// worth pinning.
func TestExplicitZeroShareSurvivesRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	c := config{Pools: []poolConfig{
		{Name: "a", Host: "127.0.0.1", Port: 23336, StatusPort: 7154, Share: sharep(100), Protocol: "sv1"},
		{Name: "b", Host: "127.0.0.1", Port: 23337, StatusPort: 7155, Share: sharep(0), Protocol: "sv1"},
	}}
	c.applyDefaults()
	if err := c.validate(); err != nil {
		t.Fatalf("100/0 split rejected: %v", err)
	}
	if err := saveConfig(path, c); err != nil {
		t.Fatal(err)
	}
	got, err := loadConfig(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if got.Pools[1].Share == nil {
		t.Fatal("the explicit 0 share was dropped on save; it read back as unset")
	}
	if *got.Pools[1].Share != 0 {
		t.Errorf("share = %v after round trip, want 0", *got.Pools[1].Share)
	}
}

// Two-decimal shares that total 100 are valid -- the proportional editor lands
// on them routinely (adjust one pool of four and the rest take a third of the
// remainder each), and binary rounding of the sum must not reject an honest 100.
func TestSharesTwoDecimalsSumTo100(t *testing.T) {
	c := config{Pools: []poolConfig{
		{Name: "a", Host: "127.0.0.1", Port: 23336, StatusPort: 7154, Share: sharep(33.33), Protocol: "sv1"},
		{Name: "b", Host: "127.0.0.1", Port: 23337, StatusPort: 7155, Share: sharep(33.33), Protocol: "sv1"},
		{Name: "c", Host: "127.0.0.1", Port: 23338, StatusPort: 7156, Share: sharep(33.34), Protocol: "sv1"},
	}}
	c.applyDefaults()
	if err := c.validate(); err != nil {
		t.Fatalf("a 33.33/33.33/33.34 split was rejected: %v", err)
	}
	got := c.targets()
	for i, want := range []float64{0.3333, 0.3333, 0.3334} {
		if math.Abs(got[i]-want) > 1e-9 {
			t.Errorf("targets()[%d] = %v, want %v", i, got[i], want)
		}
	}
}
