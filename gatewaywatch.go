package main

import (
	"context"
	"errors"
	"log"
	"regexp"
	"strconv"
	"sync"
	"time"
)

// gatewayHealth is what a DATUM gateway says about its own relationship with
// the pool behind it.
//
// This is here because of a specific failure that is otherwise invisible from
// every vantage point switchyard has, and it is worth recording exactly what
// was measured.
//
// With a gateway set to pool_pass_full_users = true and a worker name that is
// not a payout address, the gateway accepts every share LOCALLY and the pool
// rejects every one of them. Observed directly: 9 local accepted, 0 pool
// accepted, 9 pool rejected -- a 100% loss -- while switchyard reported 9
// accepted, 0 rejected, and the miner's own dashboard showed a healthy rig.
// Nothing anywhere in switchyard's own view of the world was wrong.
//
// The gateway's status page is the only place that failure appears, and it
// needs no authentication to read. So switchyard reads it, and puts the
// pool-side numbers next to its own. That turns a silent, total loss of
// earnings into a red line on a dashboard.
type gatewayHealth struct {
	PoolHost     string    `json:"poolHost,omitempty"`
	Status       string    `json:"status,omitempty"`
	Tag          string    `json:"tag,omitempty"`
	PoolAccepted uint64    `json:"poolAccepted"`
	PoolRejected uint64    `json:"poolRejected"`
	Checked      time.Time `json:"checked,omitempty"`
	Err          string    `json:"error,omitempty"`
	// Unpooled is the gateway saying it has no pool. DATUM does not idle
	// miners when its Prime connection fails; it falls back to solo mining
	// under the local coinbase tag and keeps accepting shares as if nothing
	// happened. Observed for nine hours on a live gateway whose Prime had
	// been upgraded past it ("Bad configuration version from server"): every
	// rotation onto that pool was a rotation onto solo, the pool-side
	// accepted counter froze, and the card stayed green.
	Unpooled bool `json:"unpooled,omitempty"`
	// NetworkDifficulty is the dimensionless network difficulty, derived from
	// the "Block Difficulty" field on the gateway page. DATUM does NOT print the
	// difficulty there: it prints the expected WORK per block -- difficulty x
	// 2^32, the mean number of hashes to find one -- human-formatted with an SI
	// suffix, e.g. "27.2E" (2.72e19 hashes) on a chain whose difficulty is
	// ~6.33e9. parseNetworkDifficulty scales the suffix back in and divides by
	// 2^32 to recover the difficulty stored here. The solo card turns it into
	// odds of finding a block.
	NetworkDifficulty float64 `json:"networkDifficulty,omitempty"`
	// SoloMismatch is an entry marked solo whose gateway names a pool. Its
	// work is going to that pool, so the dashboard's "solo" would be wrong.
	// Warn-only: nothing is refused for it.
	SoloMismatch bool `json:"soloMismatch,omitempty"`
}

// The one status DATUM prints when it is actually talking to its Prime.
// Anything else -- "Non-Pooled Mode", "Connecting", a blank -- means the
// shares this gateway takes are not reaching the pool switchyard thinks it
// is feeding. A blank is treated as unknown rather than unpooled, so a page
// whose layout switchyard could not parse does not read as an outage.
const gatewayPooledStatus = "Connected and Ready"

func (h gatewayHealth) unpooled() bool {
	return h.Status != "" && h.Status != gatewayPooledStatus
}

// What DATUM prints for the pool host of a gateway configured with no pool
// (datum_api.c). A pooled gateway that has lost its Prime still prints its
// host, so this is "solo by configuration", never "pool down".
const gatewayNoPoolHost = "N/A"

// applyRole reads the page in the light of what the config says the entry
// is. The solo entry having no pool is the point, so it is not unpooled; it
// is a mismatch only if its gateway turns out to name a pool after all.
func (h *gatewayHealth) applyRole(solo bool) {
	if solo {
		h.Unpooled = false
		h.SoloMismatch = h.PoolHost != "" && h.PoolHost != gatewayNoPoolHost
		return
	}
	h.Unpooled = h.unpooled()
	h.SoloMismatch = false
}

// rejecting reports the case worth shouting about: the pool is refusing work
// the gateway accepted.
//
// Requires a handful of samples before saying anything. A gateway restarted
// mid-round can legitimately show one or two pool rejects -- shares in flight
// when the session moved -- and crying misconfiguration at that would train
// the operator to ignore this.
func (h gatewayHealth) rejecting() bool {
	const floor = 5
	total := h.PoolAccepted + h.PoolRejected
	return total >= floor && h.PoolRejected > h.PoolAccepted
}

type gatewayWatcher struct {
	mu     sync.RWMutex
	health map[string]gatewayHealth
}

func newGatewayWatcher() *gatewayWatcher {
	return &gatewayWatcher{health: map[string]gatewayHealth{}}
}

func (g *gatewayWatcher) get(pool string) (gatewayHealth, bool) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	h, ok := g.health[pool]
	return h, ok
}

func (g *gatewayWatcher) set(pool string, h gatewayHealth) {
	g.mu.Lock()
	g.health[pool] = h
	g.mu.Unlock()
}

// watchGateways polls the status page of every pool that has one configured.
//
// Interval comes from gatewayPollSeconds, and it is a top-level setting rather
// than a per-pool one: it expresses how eagerly the operator wants a
// misconfiguration caught, which is a property of them, not of any individual
// gateway. Every gateway is asked the same question and the answers move at
// the same speed.
//
// Slow by default. These counters move over minutes, and a gateway's status
// page is the only thing switchyard ever fetches over HTTP -- hammering a
// neighbouring service for a number that changes twice a minute would be rude.
func (co *coordinator) watchGateways(ctx context.Context) {
	every := time.Duration(co.cfg.GatewayPollSeconds) * time.Second

	poll := func() {
		for _, pool := range co.cfg.Pools {
			info, err := inspectGatewayFull(ctx, pool.apiURL())
			// Verified as DATUM before anything started, and now answering
			// as something else: the gate's verdict applies mid-run too.
			// A page that has merely stopped answering is a gateway
			// restarting, not a verdict, and falls through to the error
			// below like it always has.
			if errors.Is(err, errNotDatum) && co.refuse != nil {
				co.refuse(&foreignUpstreamError{pool: pool})
				return
			}
			if err != nil {
				prev, _ := co.gw.get(pool.displayName())
				prev.Err = err.Error()
				prev.Checked = time.Now()
				co.gw.set(pool.displayName(), prev)
				continue
			}
			info.applyRole(pool.Solo)
			was, _ := co.gw.get(pool.displayName())
			co.gw.set(pool.displayName(), *info)
			// Log the transition, not the state: an operator who has this
			// dashboard closed should still find it in the journal.
			if info.Unpooled && !was.Unpooled {
				log.Printf("WARNING: gateway %s reports %q -- it has no pool and is solo mining "+
					"under its own tag. Rotations onto it are not reaching %s.",
					pool.stratumAddr(), info.Status, pool.displayName())
			}
			if info.SoloMismatch && !was.SoloMismatch {
				log.Printf("WARNING: %s is marked solo, but its gateway mines to %s -- "+
					"its work is going to that pool, not solo.",
					pool.displayName(), info.PoolHost)
			}
			if info.rejecting() && !was.rejecting() {
				log.Printf("WARNING: pool %s (behind gateway %s) is rejecting the work this gateway accepts "+
					"(%d rejected vs %d accepted upstream). Check pool_pass_full_users on that gateway.",
					pool.displayName(), pool.stratumAddr(), info.PoolRejected, info.PoolAccepted)
			}
		}
	}

	poll()
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			poll()
		}
	}
}

var (
	poolAccRE = regexp.MustCompile(`Pool Shares Accepted:\s*(\d+)`)
	poolRejRE = regexp.MustCompile(`Pool Shares Rejected:\s*(\d+)`)
	// The number AND its optional SI magnitude suffix: DATUM prints this field
	// human-formatted, e.g. "27.2E". Capturing only the digits silently dropped
	// the suffix and read 27.2E (2.72e19) as 27.2 -- a block every fraction of a
	// second and a "1 in 1 chance per day" on the solo card. See
	// parseNetworkDifficulty. The \b is what makes a suffix a suffix: tags are
	// stripped before this runs, so a value with no suffix is followed by the next
	// field's label, and a "T" that starts a word must not read as tera.
	netDiffRE = regexp.MustCompile(`Block Difficulty:\s*([0-9]+(?:\.[0-9]+)?)(?:\s*([kKMGTPEZY])\b)?`)
)

// siScale maps DATUM's human-readable magnitude suffix to its multiplier. DATUM
// formats large numbers on its status page this way; k is the SI 1e3 whether
// written k or K.
var siScale = map[string]float64{
	"":  1,
	"k": 1e3, "K": 1e3,
	"M": 1e6,
	"G": 1e9,
	"T": 1e12,
	"P": 1e15,
	"E": 1e18,
	"Z": 1e21,
	"Y": 1e24,
}

// twoPow32 is difficulty 1 expressed in hashes: a difficulty-1 block takes 2^32
// expected hashes. It is the bridge between the WORK DATUM prints and the
// difficulty the rest of switchyard reasons in.
const twoPow32 = 4294967296.0

// parseNetworkDifficulty reads DATUM's "Block Difficulty" field and returns the
// dimensionless network difficulty, or 0 if the field is absent or unparseable.
//
// DATUM prints the expected WORK per block there, not the difficulty: the mean
// number of hashes to find a block, which is difficulty x 2^32, SI-formatted
// like "27.2E". So the suffix is scaled back in and the result -- hashes -- is
// divided by 2^32 to recover the difficulty. The solo card multiplies by 2^32
// again to get a hash count; the units meet in the middle, honestly, with the
// gateway's work on one side and switchyard's difficulty on the other.
func parseNetworkDifficulty(text string) float64 {
	m := netDiffRE.FindStringSubmatch(text)
	if len(m) < 3 {
		return 0
	}
	work, err := strconv.ParseFloat(m[1], 64)
	if err != nil {
		return 0
	}
	return work * siScale[m[2]] / twoPow32
}

// inspectGatewayFull is inspectGateway plus the share counters. Split so the
// editor's one-shot "Inspect" button and this poller cannot drift apart.
func inspectGatewayFull(ctx context.Context, rawURL string) (*gatewayHealth, error) {
	info, text, err := fetchGatewayStatus(ctx, rawURL)
	if err != nil {
		return nil, err
	}
	h := &gatewayHealth{
		PoolHost:          info.PoolHost,
		Status:            info.Status,
		Tag:               info.Tag,
		PoolAccepted:      firstUint(poolAccRE, text),
		PoolRejected:      firstUint(poolRejRE, text),
		NetworkDifficulty: parseNetworkDifficulty(text),
		Checked:           time.Now(),
	}
	h.Unpooled = h.unpooled()
	return h, nil
}

func firstUint(re *regexp.Regexp, text string) uint64 {
	if m := re.FindStringSubmatch(text); len(m) > 1 {
		if n, err := strconv.ParseUint(m[1], 10, 64); err == nil {
			return n
		}
	}
	return 0
}
