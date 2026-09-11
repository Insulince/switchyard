package main

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

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
	if cfg.MinDwellSeconds == 0 || cfg.MaxDwellSeconds == 0 || cfg.PollSeconds == 0 {
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
		StatusListen: "0.0.0.0:7160",
		Pools: []poolConfig{
			{Name: "alpha", Host: "127.0.0.1", Port: 23336, StatusPort: 7154},
			{Name: "beta", Host: "127.0.0.1", Port: 23337, StatusPort: 7155},
		},
		Rigs: []rigConfig{
			{Listen: "0.0.0.0:23401"},
		},
		MinDwellSeconds: 90,
		MaxDwellSeconds: 1200,
		PollSeconds:     3,
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
		{"pools only", config{Pools: []poolConfig{{Name: "a", Host: "127.0.0.1", Port: 23336, StatusPort: 7154}}}, false},
		{"rigs only", config{Rigs: []rigConfig{{Listen: ":1"}}}, true},
		{"both", config{
			Pools: []poolConfig{{Name: "a", Host: "127.0.0.1", Port: 23336, StatusPort: 7154}},
			Rigs:  []rigConfig{{Listen: ":1"}},
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

// "23401" is what an operator types. Refusing it in favour of "0.0.0.0:23401"
// would be pedantry, and silently storing the bare string would produce a
// listener on a port nobody expects.
func TestNormaliseListen(t *testing.T) {
	for in, want := range map[string]string{
		"23401":             "0.0.0.0:23401",
		":23401":            "0.0.0.0:23401",
		"  23401  ":         "0.0.0.0:23401",
		"0.0.0.0:23401":     "0.0.0.0:23401",
		"127.0.0.1:23401":   "127.0.0.1:23401",
		"192.168.1.5:23401": "192.168.1.5:23401",
		"":                  "",
	} {
		if got := normaliseListen(in); got != want {
			t.Errorf("normaliseListen(%q) = %q, want %q", in, got, want)
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

	cfg := config{Pools: []poolConfig{{Name: "a", Host: "127.0.0.1", Port: 23336, StatusPort: 7154}}}
	cfg.applyDefaults()
	if err := saveConfig(path, cfg); err != nil {
		t.Fatal(err)
	}

	cfg.Pools = append(cfg.Pools, poolConfig{Name: "b", Host: "127.0.0.1", Port: 23337, StatusPort: 7155})
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
// first-run message telling them to open a URL that refuses the connection was
// the failure this guards.
func TestDefaultStatusListenIsNotLoopbackOnly(t *testing.T) {
	var c config
	c.applyDefaults()
	if c.StatusListen != ":7160" {
		t.Fatalf("default statusListen = %q, want %q", c.StatusListen, ":7160")
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
