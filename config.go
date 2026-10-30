package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
)

// poolConfig is one upstream DATUM gateway. Note that this is the LOCAL
// gateway's stratum port, not the pool itself -- switchyard never speaks to
// a pool directly. Each gateway holds its own permanently-established,
// authenticated session with its Prime; we only ever move rigs between
// gateways on this machine.
type poolConfig struct {
	// Host is where the DATUM gateway is reachable, and both ports below are
	// on it. One field rather than two addresses, because typing the same host
	// twice is two chances to get it wrong and one of them fails silently.
	Host string `json:"host"`

	// Port is the gateway's stratum port -- where hashrate actually goes.
	Port int `json:"port"`

	// StatusPort is the gateway's status page, and it is REQUIRED.
	//
	// It looks like a reporting nicety and is not. It is the only place one
	// specific failure is visible: a gateway can accept every share switchyard
	// sends while the pool rejects every one of them, and nothing switchyard
	// measures itself would look wrong. Measured on a live gateway, that
	// failure loses 100% of earnings while every dashboard in the path reports
	// success. Requiring the page is the price of it never happening silently.
	StatusPort int `json:"statusPort"`

	// Name is what to call this pool, and the only source of its name at
	// runtime. The setup form pre-fills it from the gateway's pool tag, but
	// what is saved here is what is shown -- the tag is not re-read for it,
	// because a gateway in non-pooled mode prints its own local tag in that
	// field, and a pool once spent hours renamed to its operator.
	Name string `json:"name,omitempty"`

	// Solo marks the one entry whose gateway is deliberately configured with
	// no pool: the time rotation gives it is spent mining solo, from the
	// operator's own node. See the README's "Solo slot".
	//
	// The flag ALONE says so. A solo entry has no pool and therefore no
	// Name, and nothing invents one for it: overloading Name with a marker
	// would take that string away from any real pool that happened to use
	// it. Code that needs a label calls displayName.
	//
	// At most one entry may carry it. That is the supported way to mine solo
	// alongside pools, not an enforcement mechanism: an operator who adds
	// further unmarked solo gateways is not stopped, those just get the
	// ordinary "this gateway has no pool" warning.
	Solo bool `json:"solo,omitempty"`

	// Protocol is how switchyard speaks to this gateway: "sv1" or "sv2", and it
	// is REQUIRED -- there is no default. Omission is a mistake, not a choice, so
	// validate refuses an empty or unrecognised value rather than guessing; a
	// setting that decides where hashrate goes must be stated, not inferred. SV2
	// is the XBT (BLAKE2b) wire: an encrypted, authenticated Noise session.
	Protocol string `json:"protocol"`

	// AuthorityKey is the gateway's SV2 authority PUBLIC key, in the SRI
	// base58check string the gateway prints ("configure this on miners"). It is
	// REQUIRED when Protocol is "sv2" and forbidden otherwise: it is the only
	// thing that lets switchyard verify it is talking to the real gateway rather
	// than a hijacker, which is the whole point of SV2 authentication. The
	// format is decoded and pinned in sv2key.go.
	AuthorityKey string `json:"authorityKey,omitempty"`
}

// stratumAddr is the endpoint switchyard actually opens a socket to.
func (p poolConfig) stratumAddr() string {
	return net.JoinHostPort(p.hostOrDefault(), strconv.Itoa(p.Port))
}

// proto reports how switchyard speaks to this gateway. It returns the field
// verbatim ("sv1" or "sv2"); validate guarantees it is one of those before any
// behavioural code reads it, so there is no defaulting to hide an empty value.
func (p poolConfig) proto() string { return p.Protocol }

// authorityPub decodes the gateway's SV2 authority public key. Only meaningful
// for an sv2 pool; validate guarantees it is present and decodable first.
func (p poolConfig) authorityPub() (*btcec.PublicKey, error) {
	return authorityKeyDecode(p.AuthorityKey)
}

// apiURL is the gateway's status page.
func (p poolConfig) apiURL() string {
	return "http://" + net.JoinHostPort(p.hostOrDefault(), strconv.Itoa(p.StatusPort))
}

// hostOrDefault treats a blank host as "this machine", which is where a
// gateway lives in the overwhelming majority of setups.
func (p poolConfig) hostOrDefault() string {
	if p.Host == "" {
		return "127.0.0.1"
	}
	return p.Host
}

// gatewayName is the label for the DATUM gateway in front of this pool.
//
// The host is the gateway by definition -- it is the endpoint switchyard opens
// a socket to -- so it needs no separate field and cannot drift out of date.
func (p poolConfig) gatewayName() string {
	return p.hostOrDefault()
}

// rigConfig is one physical miner. Each rig gets its own listener port so we
// can address rigs independently -- that is the whole reason this works with
// fewer rigs than pools.
type rigConfig struct {
	// Port is the ONLY thing switchyard needs to know about a rig, and all it
	// accepts: the TCP port its listener binds, always on 0.0.0.0 (a rig port
	// that answered only on loopback would be a rig no miner on the LAN could
	// reach). There is no host field -- it is invariably the whole machine -- so
	// the config carries the one number that varies and nothing that does not.
	//
	// Everything else about a miner -- its worker name, its password -- comes
	// off the connection, because the miner already carries all of it. There
	// is deliberately no override here. Switchyard forwards connections; it
	// does not improve the hardware behind them, and a field that let it
	// substitute a worker name would be a field that let it substitute a
	// worker name, whatever the stated reason.
	//
	// If a miner cannot send the name a pool needs, that is a limitation of
	// the miner, and papering over it is somebody else's job.
	Port int `json:"port"`

	// Protocol is how the miner on this port speaks to switchyard: "sv1" or
	// "sv2", and it is REQUIRED -- there is no default, and validate refuses an
	// empty or unrecognised value. An SV2 rig is a downstream translator (or
	// SV2-native miner) that pins switchyard's authority key over Noise.
	Protocol string `json:"protocol"`

	// AuthoritySecret is switchyard's OWN authority secret for this SV2 listener
	// -- a 32-byte hex secp256k1 scalar whose public half the downstream
	// translator pins. REQUIRED when Protocol is "sv2", forbidden otherwise.
	//
	// It is a credential and lives beside the rig's stratum password, which is
	// why saveConfig already writes the file 0600. It is per-rig rather than
	// global on purpose: switchyard presents one identity per downstream port,
	// exactly as a gateway presents one authority key per SV2 listener.
	AuthoritySecret string `json:"authoritySecret,omitempty"`
}

// proto reports how this rig's miner speaks to switchyard. It returns the field
// verbatim ("sv1" or "sv2"); validate guarantees it is one of those before any
// behavioural code reads it, so there is no defaulting to hide an empty value.
func (r rigConfig) proto() string { return r.Protocol }

// listenAddr is the address switchyard binds this rig's listener on: the port,
// on every interface. A rig is reached by miners on the LAN, so it is always
// 0.0.0.0 -- the config stores only the port, and this is where that becomes an
// address.
func (r rigConfig) listenAddr() string {
	return fmt.Sprintf("0.0.0.0:%d", r.Port)
}

// authorityPriv decodes switchyard's own downstream authority secret for this
// rig. Only meaningful for an sv2 rig; validate guarantees it is present and
// decodable before anything calls this.
func (r rigConfig) authorityPriv() (*btcec.PrivateKey, error) {
	return authoritySecretDecode(r.AuthoritySecret)
}

// SV2 identity sentinels the dashboard puts in a rig's authoritySecret in place
// of a real secret, so the secret itself never has to reach the browser.
//
// They are VALUES in the existing authoritySecret field, not new keys: the
// config decoder forbids unknown keys, and a UI-only field would be one. Neither
// is valid 32-byte hex, so a real secret can never be mistaken for one, and a
// hand-edited config that literally contained one would simply fail to decode
// its "secret" and be refused -- which is correct, it is not a secret.
const (
	authSecretKeep     = "__keep__"     // reuse the secret already on file for this listener
	authSecretGenerate = "__generate__" // mint a fresh one on save (legacy fallback)
	// stagedPrefix marks an authoritySecret as a handle into the server's staged
	// store: a secret the editor generated in-screen and parked server-side, to
	// be swapped for the real secret on save (see server.consumeStaged). It is a
	// VALUE prefix in the authoritySecret field, like the sentinels above.
	stagedPrefix = "__staged__:"
)

// resolveRigIdentities turns the dashboard's SV2 identity sentinels into real
// authority secrets before the incoming config is validated or written:
// __generate__ mints a fresh secret, __keep__ copies the one already on file for
// that listener, and a hand-supplied hex secret is left untouched. It runs on
// the save path only (see saveAndReload), so by the time validate runs, every
// secret is real -- the sentinels never reach disk or the validator.
//
// running is the config switchyard is serving right now, the source of the
// "keep" secrets. Listeners are matched by port, which is a rig's whole stable
// identity across an edit.
func resolveRigIdentities(incoming *config, running config) error {
	prior := map[int]string{}
	for _, r := range running.Rigs {
		if r.AuthoritySecret != "" {
			prior[r.Port] = r.AuthoritySecret
		}
	}
	for i := range incoming.Rigs {
		r := &incoming.Rigs[i]
		if r.proto() != "sv2" {
			// A sentinel left behind by an sv2 -> sv1 flip is not a credential;
			// drop it so validate does not reject the sv1 rig for carrying one.
			if r.AuthoritySecret == authSecretKeep || r.AuthoritySecret == authSecretGenerate {
				r.AuthoritySecret = ""
			}
			continue
		}
		switch r.AuthoritySecret {
		case authSecretGenerate:
			secret, err := newAuthoritySecret()
			if err != nil {
				return fmt.Errorf("rig %d: minting SV2 authority identity: %w", r.Port, err)
			}
			r.AuthoritySecret = secret
		case authSecretKeep:
			prev := prior[r.Port]
			if prev == "" {
				return fmt.Errorf("rig %d: asked to keep its SV2 identity, but none is on file "+
					"for this port -- generate one or provide your own", r.Port)
			}
			r.AuthoritySecret = prev
		}
		// Anything else is a hand-supplied secret; validate checks its format.
	}
	return nil
}

type config struct {
	// DashboardPort is the TCP port the dashboard (and its /status JSON) serves on.
	DashboardPort int `json:"dashboardPort"`

	// DashboardHost is the bind host for the dashboard. Empty (the default) binds
	// every interface, so the page stays reachable from another device on the LAN.
	// Set it to "127.0.0.1" to bind loopback only -- the way to keep the admin
	// surface off the LAN (the state-changing endpoints are unauthenticated),
	// reaching it over an SSH tunnel or an authenticated reverse proxy instead.
	DashboardHost string `json:"dashboardHost,omitempty"`

	Pools []poolConfig `json:"pools"`
	Rigs  []rigConfig  `json:"rigs"`

	// MinDwellSeconds is the floor on how long a rig stays on a pool before
	// a block is allowed to rotate it again.
	//
	// This is NOT here to smooth block-interval variance -- that averages out
	// and is not worth engineering around. It exists because two blocks can
	// land seconds apart, and each rotation costs a rig reconnect. Without a
	// floor, a burst of fast blocks would spend more time reconnecting than
	// hashing.
	MinDwellSeconds int `json:"minDwellSeconds"`

	// MaxDwellSeconds forces a rotation when the network has not produced a
	// block for this long.
	//
	// Block intervals are exponentially distributed, so a long gap is not an
	// anomaly, it is guaranteed to happen regularly -- and every minute of one
	// is a minute a pool receives nothing from us. TIDES windows are measured
	// in blocks of accepted work, so a pool that sees no shares for half an
	// hour is a pool whose window we are falling out of, for no reason other
	// than the chain being quiet.
	//
	// The floor and the ceiling guard opposite failures: the floor stops a
	// burst of fast blocks spending more time reconnecting than hashing, the
	// ceiling stops a quiet chain stranding a pool. Neither is about block
	// time variance in the payout sense, which averages out and is not worth
	// engineering around.
	MaxDwellSeconds int `json:"maxDwellSeconds"`

	// DashboardPollSeconds is how often the dashboard refetches /status.
	//
	// The default of 2s is chosen against what actually changes. Rotations are
	// the fast event and they are driven by blocks, so the thing a viewer is
	// waiting to see happen arrives at most once every few minutes -- but when
	// it does, it should not sit unrendered for long enough that the flash and
	// the spark have nothing to do with what the page is showing.
	//
	// Cost is negligible either way: /status is a few kilobytes off localhost
	// and the handler takes one lock, so this could sit at 1s without anyone
	// noticing. It is exposed because "how live is live" is a taste question,
	// not because the default is a compromise. Below about 0.5s the animations
	// start to overlap themselves and it reads as jitter.
	//
	// Named for the dashboard specifically so it is never confused with
	// gatewayPollSeconds, which is a different thing on a different cadence:
	// this is the browser re-rendering, that is switchyard reading each
	// gateway's status page.
	DashboardPollSeconds float64 `json:"dashboardPollSeconds"`

	// GatewayPollSeconds is how often each gateway's status page is read for
	// the pool-side share counters.
	//
	// Top level rather than per pool: it is a statement about how eagerly
	// switchyard should watch for a misconfiguration, which is a property of
	// the operator's patience, not of any individual gateway. Every gateway is
	// asked the same question and the answers move at the same speed.
	GatewayPollSeconds int `json:"gatewayPollSeconds"`

	// DialTimeoutSeconds bounds gateway connect and handshake.
	DialTimeoutSeconds int `json:"dialTimeoutSeconds"`
}

func (c *config) minDwell() time.Duration {
	return time.Duration(c.MinDwellSeconds) * time.Second
}

func (c *config) maxDwell() time.Duration {
	return time.Duration(c.MaxDwellSeconds) * time.Second
}

func (c *config) dialTimeout() time.Duration {
	return time.Duration(c.DialTimeoutSeconds) * time.Second
}

// loadConfig reads the config file, or reports an EMPTY one if there is no
// file yet.
//
// A missing file is deliberately not an error. Switchyard must be able to
// start with nothing at all, serve its page, and be told what to do from
// there -- otherwise the first thing a new user meets is a process that
// refuses to boot and a file they have not been told how to write. An
// unconfigured switchyard mines nothing, which is the correct behaviour for a
// program that has not been told about a single rig or pool.
//
// A file that EXISTS but cannot be read or parsed is still fatal. That is not
// a fresh install, it is a broken one, and quietly starting empty would
// discard a working setup.
func loadConfig(path string) (config, error) {
	var c config
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		c.applyDefaults()
		return c, nil
	}
	if err != nil {
		return c, fmt.Errorf("reading config: %w", err)
	}
	c, err = decodeConfig(bytes.NewReader(b))
	if err != nil {
		return c, fmt.Errorf("parsing config: %w", err)
	}
	c.applyDefaults()
	return c, c.validate()
}

// decodeConfig is the one place that decides what a valid config document is.
//
// UNKNOWN KEYS ARE FATAL, and deliberately so. encoding/json's default is to
// discard anything it does not recognise without a word, which turns a typo
// ("pollSecons") and an obsolete field carried over from an older README into
// the same thing: a setting the operator believes is in effect and which does
// nothing. For a program whose config decides where work goes, a silently
// ignored key is the worst available outcome -- everything looks fine and the
// wrong thing happens.
//
// The cost is that a config written for a newer switchyard will not load on an
// older one. That is the correct trade: refusing to start is recoverable in
// ten seconds, and a silently misread config is not.
//
// Both ways in share it -- the file at boot and the dashboard's save -- so
// the two cannot disagree about what they will accept. They did briefly, and
// the direction of the disagreement was the bad one: the save path silently
// dropped what the load path would have refused, writing a file that was not
// the document the operator sent.
func decodeConfig(r io.Reader) (config, error) {
	var c config
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return c, err
	}
	return c, nil
}

func (c *config) applyDefaults() {
	if c.MinDwellSeconds <= 0 {
		c.MinDwellSeconds = 60
	}
	if c.MaxDwellSeconds <= 0 {
		c.MaxDwellSeconds = 900
	}
	if c.DashboardPollSeconds <= 0 {
		c.DashboardPollSeconds = 2
	}
	if c.DashboardPollSeconds < 0.5 {
		c.DashboardPollSeconds = 0.5
	}
	if c.DialTimeoutSeconds <= 0 {
		c.DialTimeoutSeconds = 10
	}
	if c.GatewayPollSeconds <= 0 {
		c.GatewayPollSeconds = 30
	}
	// A floor, because this is HTTP to a neighbouring service rather than a
	// local socket, and these counters move over minutes. Polling one every
	// second would be pure rudeness for no additional information.
	if c.GatewayPollSeconds < 5 {
		c.GatewayPollSeconds = 5
	}
	// EVERY interface, not loopback.
	//
	// A loopback default is only reachable from inside whatever the process is
	// running in, and the people this is written for mostly do not run it
	// directly on the machine they browse from: a container, a StartOS or
	// Umbrel package, a VM, a headless box down the hall. In every one of
	// those, 127.0.0.1 means "unreachable" and the first-run message tells the
	// operator to open a URL that refuses the connection -- with the process
	// itself logging that it is listening.
	//
	// The narrower default was safer and unusable, which is not safer. The port
	// is all that is configurable now; the bind is always every interface.
	if c.DashboardPort <= 0 {
		c.DashboardPort = 7160
	}
	// Deliberately does NOT derive User from Name. An empty User means "use
	// whatever the miner authorises with", which is the default and the point;
	// filling it in from the config would reinstate the substitution this
	// design removed.
}

// configured reports whether there is enough here to actually mine. It is
// deliberately separate from validate: an empty config is VALID, it just has
// nothing to do, and the dashboard uses that distinction to decide whether to
// show a dashboard or a setup form.
func (c *config) configured() bool {
	return len(c.Pools) > 0 && len(c.Rigs) > 0
}

func (c *config) validate() error {
	// Rigs with nowhere to send their work is not an empty config, it is a
	// broken one -- every placement calculation divides by the pool count.
	if len(c.Rigs) > 0 && len(c.Pools) == 0 {
		return fmt.Errorf("%d rig(s) configured but no pools", len(c.Rigs))
	}
	// A ceiling below the floor would make every rotation immediately
	// eligible for a forced one, which is a reconnect storm rather than a
	// schedule. Equal is the same failure: the instant a rotation satisfies
	// the floor it has also reached the ceiling. Catch it here instead of at
	// three in the morning.
	if c.MaxDwellSeconds <= c.MinDwellSeconds {
		return fmt.Errorf("dwell ceiling (%ds) must be strictly greater than the floor (%ds)",
			c.MaxDwellSeconds, c.MinDwellSeconds)
	}
	// More rigs than pools is legal but means some pool is always covered
	// twice; fewer rigs than pools is the interesting case and the reason
	// this program exists. Neither is an error -- but zero-length names and
	// duplicate listen addresses are, and they fail confusingly at runtime.
	seenPool := map[string]bool{}
	seenStratum := map[string]bool{}
	solos := 0
	for i, p := range c.Pools {
		if p.Port <= 0 || p.Port > 65535 {
			return fmt.Errorf("pool %d: a gateway stratum port is required", i)
		}
		// Required, not optional. See StatusPort's own comment: without it,
		// a total loss of earnings is invisible from every vantage point
		// switchyard has.
		if p.StatusPort <= 0 || p.StatusPort > 65535 {
			return fmt.Errorf("pool %d (%s): a gateway status port is required, so switchyard can "+
				"see whether the pool is accepting this gateway's work", i, p.displayName())
		}
		if p.Port == p.StatusPort {
			return fmt.Errorf("pool %d (%s): stratum and status ports are both %d; they are "+
				"different services on the gateway", i, p.displayName(), p.Port)
		}
		// An authority key is the gateway's SV2 identity and means nothing to an
		// SV1 gateway. Required for sv2 (switchyard cannot verify the gateway
		// without it, and an unverified gateway is the hijack this prevents);
		// refused for sv1, because a key sitting on an SV1 pool is a belief the
		// operator holds that does nothing -- the same failure the unknown-key
		// rule guards against, one level down.
		switch p.proto() {
		case "":
			return fmt.Errorf("pool %d (%s): protocol is required (\"sv1\" or \"sv2\"); "+
				"switchyard does not assume one", i, p.displayName())
		case "sv1":
			if p.AuthorityKey != "" {
				return fmt.Errorf("pool %d (%s): authorityKey is set but protocol is sv1; "+
					"an authority key only applies to an sv2 gateway", i, p.displayName())
			}
		case "sv2":
			if p.AuthorityKey == "" {
				return fmt.Errorf("pool %d (%s): protocol is sv2 but no authorityKey; "+
					"switchyard cannot verify the gateway's identity without it", i, p.displayName())
			}
			if _, err := p.authorityPub(); err != nil {
				return fmt.Errorf("pool %d (%s): %w", i, p.displayName(), err)
			}
		default:
			return fmt.Errorf("pool %d (%s): unknown protocol %q (want \"sv1\" or \"sv2\")",
				i, p.displayName(), p.Protocol)
		}
		if p.Solo {
			solos++
			if p.Name != "" {
				return fmt.Errorf("pool %d is the solo gateway, which has no pool to name; "+
					"remove its name (%q)", i, p.Name)
			}
		}
		// The address first: two entries on one gateway is a mistake about
		// the address, and an unnamed entry's label IS its address, so
		// checking labels first reported it as a "duplicate pool name" the
		// operator never typed.
		if seenStratum[p.stratumAddr()] {
			return fmt.Errorf("two pools share the gateway address %q", p.stratumAddr())
		}
		// On the label, not the raw name: the label is what everything keys
		// on, and unnamed entries have one too.
		label := p.displayName()
		if seenPool[label] {
			return fmt.Errorf("duplicate pool name %q", label)
		}
		seenPool[label] = true
		seenStratum[p.stratumAddr()] = true
	}
	if solos > 1 {
		return fmt.Errorf("only one pool can be solo (%d are marked solo)", solos)
	}
	seenPort := map[int]bool{}
	for i, r := range c.Rigs {
		if r.Port <= 0 || r.Port > 65535 {
			return fmt.Errorf("rig %d: a listen port is required", i)
		}
		// The authority secret is switchyard's own SV2 identity for this port.
		// Required for sv2 (there is no downstream Noise session to present
		// without it); refused for sv1, where it would be a credential doing
		// nothing.
		switch r.proto() {
		case "":
			return fmt.Errorf("rig %d (port %d): protocol is required (\"sv1\" or \"sv2\"); "+
				"switchyard does not assume one", i, r.Port)
		case "sv1":
			if r.AuthoritySecret != "" {
				return fmt.Errorf("rig %d (port %d): authoritySecret is set but protocol is sv1; "+
					"it only applies to an sv2 listener", i, r.Port)
			}
		case "sv2":
			if r.AuthoritySecret == "" {
				return fmt.Errorf("rig %d (port %d): protocol is sv2 but no authoritySecret; "+
					"switchyard needs its own authority identity to present downstream", i, r.Port)
			}
			if _, err := r.authorityPriv(); err != nil {
				return fmt.Errorf("rig %d (port %d): %w", i, r.Port, err)
			}
		default:
			return fmt.Errorf("rig %d (port %d): unknown protocol %q (want \"sv1\" or \"sv2\")",
				i, r.Port, r.Protocol)
		}
		// Two rigs on one port is the one arrangement that cannot work: the
		// second listener never binds, and the miner pointed at it is
		// silently connected to the wrong rig's slot.
		if seenPort[r.Port] {
			return fmt.Errorf("two rigs share listen port %d", r.Port)
		}
		seenPort[r.Port] = true
	}
	return nil
}

// saveConfig writes the config and nothing else. It does not apply it.
//
// Two strategies, in order, because there is no single one that is both safe
// and universally possible:
//
//  1. Write a temporary file beside the target and rename it into place. This
//     is atomic: a crash or a full disk leaves the previous config intact
//     rather than a truncated file that fails to parse on next boot -- which
//     for switchyard means miners pointed at ports nothing is listening on.
//
//  2. If the rename is refused, rewrite the file in place and fsync it.
//
// The fallback is not hypothetical and is not a Docker quirk, though that is
// where it shows up first. Renaming ONTO a path only works when the path is an
// ordinary directory entry the process may replace. Plenty of perfectly normal
// deployments break that assumption: a config file bind-mounted by inode, a
// path that is a symlink into a store the process may write through but not
// unlink, a directory owned by another user with a writable file inside it.
// In every one of those cases the file itself is writable and only the
// DIRECTORY operation is refused, so an installer that insisted on rename
// would fail for a reason the operator cannot see and cannot fix from the
// dashboard.
//
// The in-place path gives up atomicity, which is a genuine loss and worth
// stating plainly: a crash mid-write leaves a partial file. It is still far
// better than refusing to save at all, and the window is a single small write.
//
// The caller is expected to have validated first. Writing an invalid config
// would leave a file the next boot refuses, turning a rejected form
// submission into a broken install.
func saveConfig(path string, c config) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')

	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}

	// 0600: rig entries carry a stratum password. It is almost always
	// worthless -- "x" is the convention -- but it is still a credential field
	// and there is no reason for anyone else to read it.
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err == nil {
		if err := os.Rename(tmp, path); err == nil {
			return nil
		}
		// Clean up before falling back, or the next boot's directory listing
		// is littered with abandoned .tmp files.
		_ = os.Remove(tmp)
	}

	return writeInPlace(path, data)
}

// writeInPlace truncates and rewrites an existing file, then flushes it to
// disk. Used only when a rename cannot be performed -- see saveConfig.
//
// The explicit Sync matters more here than it would after a rename: with no
// atomic swap to rely on, an unflushed write is a file that exists, parses
// today from the page cache, and is empty after a power cut.
func writeInPlace(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// probeListen reports whether switchyard could actually bind an address, by
// binding it and letting go again.
//
// Asked while the operator is looking at the form, this turns "the port was
// taken" from a failure at next boot -- with a miner already pointed at it --
// into a red line under a field. There is an unavoidable race between the
// probe and the real listen, but the alternative is not probing at all, which
// fails the same way plus a reboot later.
func probeListen(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return ln.Close()
}

// suggestPort finds the first port at or above base that nothing is using.
//
// This SUGGESTS; it never decides. A rig is configured once to point at a
// specific port and left alone for months, so the port has to be a stable
// recorded fact, not something rediscovered at each boot -- a switchyard that
// picked its own ports would silently strand every miner the first time one
// was taken. Scanning is only here so that a first-time operator is not asked
// to invent a number.
func suggestPort(base int, taken map[int]bool) int {
	for port := base; port < base+200; port++ {
		if taken[port] {
			continue
		}
		if probeListen(fmt.Sprintf("0.0.0.0:%d", port)) == nil {
			return port
		}
	}
	return 0
}

// validateRaw rejects values that applyDefaults would otherwise silently
// replace.
//
// This exists because the two functions have opposite jobs and run in that
// order. applyDefaults treats "0 or less" as "not set" and substitutes a
// sensible value -- correct for a config file with a field omitted, and
// exactly wrong for a form where somebody typed -5. Left to applyDefaults, a
// negative dwell floor becomes 60 and the operator is never told their input
// was discarded.
//
// So the submit path checks the raw numbers first and says no, and only then
// fills in the genuine blanks.
func (c *config) validateRaw() error {
	if c.MinDwellSeconds < 0 {
		return fmt.Errorf("dwell floor cannot be negative (got %ds)", c.MinDwellSeconds)
	}
	if c.MaxDwellSeconds < 0 {
		return fmt.Errorf("dwell ceiling cannot be negative (got %ds)", c.MaxDwellSeconds)
	}
	if c.DashboardPollSeconds < 0 {
		return fmt.Errorf("dashboard refresh cannot be negative (got %gs)", c.DashboardPollSeconds)
	}
	if c.DialTimeoutSeconds < 0 {
		return fmt.Errorf("dial timeout cannot be negative (got %ds)", c.DialTimeoutSeconds)
	}
	if c.GatewayPollSeconds < 0 {
		return fmt.Errorf("gateway poll interval cannot be negative (got %ds)", c.GatewayPollSeconds)
	}
	// Both present and out of order is a mistake worth naming before defaults
	// get a chance to rewrite either of them.
	if c.MinDwellSeconds > 0 && c.MaxDwellSeconds > 0 && c.MaxDwellSeconds <= c.MinDwellSeconds {
		return fmt.Errorf("dwell ceiling (%ds) must be strictly greater than the floor (%ds)",
			c.MaxDwellSeconds, c.MinDwellSeconds)
	}
	return nil
}

// displayName is how an entry is told apart -- in logs, in the gateway health
// map, and in the pool names /status joins rigs to pools by. Derived, never
// stored: the operator's label, the solo entry's role and address, or the
// address alone, so an entry is never nameless and never needs a sentinel.
//
// Every such site calls this rather than reading Name. Reading Name directly
// is how unnamed entries once logged blanks and shared one health record.
func (p poolConfig) displayName() string {
	if p.Solo {
		return "solo (" + p.stratumAddr() + ")"
	}
	if p.Name != "" {
		return p.Name
	}
	return p.stratumAddr()
}

// gatewayPoll is how often to read each gateway's status page.
func (c *config) gatewayPoll() time.Duration {
	return time.Duration(c.GatewayPollSeconds) * time.Second
}

// dashboardAddr is the address the dashboard binds: DashboardHost (empty = every
// interface) and the configured port.
func (c *config) dashboardAddr() string {
	return net.JoinHostPort(c.DashboardHost, strconv.Itoa(c.DashboardPort))
}
