package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log"
	"regexp"
	"strconv"
	"strings"
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
	// NetworkDifficulty is the current block's difficulty, from the job
	// section of the page. DATUM prints it pooled or not; the solo card turns
	// it into odds of finding a block.
	NetworkDifficulty float64 `json:"networkDifficulty,omitempty"`
	// SoloMismatch is an entry marked solo whose gateway names a pool. Its
	// work is going to that pool, so the dashboard's "solo" would be wrong.
	// Warn-only: nothing is refused for it.
	SoloMismatch bool `json:"soloMismatch,omitempty"`
	// BlockHeight is the height of the block the gateway's current job is
	// BUILDING -- the template height, one above the chain tip -- and
	// PrevBlock is that job's previous block hash in the familiar display
	// order. Together they are where the dashboard's chain-tip height comes
	// from; see noteGatewayTip for why they are read as a pair.
	BlockHeight uint64 `json:"blockHeight,omitempty"`
	PrevBlock   string `json:"prevBlock,omitempty"`
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
			if info.BlockHeight > 0 {
				co.noteGatewayTip(hiddenPrevhash(info.PrevBlock), info.BlockHeight-1)
			}
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

	// A new block also asks for a read, so the tip's height appears within a
	// second of the tip itself rather than up to a whole poll interval later.
	// The gateway's page can trail the job it just pushed by a moment, so a
	// read that still finds no height for the new tip is retried once,
	// shortly after; anything slower than that is left to the regular tick.
	var retry <-chan time.Time
	poll()
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			poll()
		case <-co.gwKick:
			poll()
			retry = nil
			if !co.tipHeightKnown() {
				retry = time.After(3 * time.Second)
			}
		case <-retry:
			retry = nil
			poll()
		}
	}
}

var (
	poolAccRE = regexp.MustCompile(`Pool Shares Accepted:\s*(\d+)`)
	poolRejRE = regexp.MustCompile(`Pool Shares Rejected:\s*(\d+)`)
	netDiffRE = regexp.MustCompile(`Block Difficulty:\s*([0-9]+(?:\.[0-9]+)?)`)
	heightRE  = regexp.MustCompile(`Block Height:\s*(\d+)`)
	// DATUM wraps the hash's leading zeros in their own element to dim them,
	// so once tags are stripped the hash arrives split by whitespace
	// ("0000000000000000 5ed8e0..."). Sixty-four hex digits with any
	// whitespace between them, rejoined below.
	prevBlockRE = regexp.MustCompile(`Previous Block:\s*((?:[0-9a-fA-F]\s*){64})`)
	spacesRE    = regexp.MustCompile(`\s+`)
)

// hiddenPrevhash turns a display-order block hash into the prevhash string
// DATUM puts in every BLAKE2b job (datum_blake2b_prevblock_hidden in
// datum_pow.c): the tagged SHA-256 of the hash's display-order bytes under
// "Bitcoin prevblock header, hashed", with its first six bytes zeroed.
//
// That is the value switchyard's rotation clock -- and the dashboard's chain
// tip -- is keyed on, and it is deliberately not the block hash a node or an
// explorer shows. This is how a height read from a gateway's page, which
// prints the ordinary hash, is matched to it. "" for anything malformed.
func hiddenPrevhash(display string) string {
	raw, err := hex.DecodeString(display)
	if err != nil || len(raw) != 32 {
		return ""
	}
	tag := sha256.Sum256([]byte("Bitcoin prevblock header, hashed"))
	h := sha256.New()
	h.Write(tag[:])
	h.Write(tag[:])
	h.Write(raw)
	out := h.Sum(nil)
	clear(out[:6])
	return hex.EncodeToString(out)
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
		NetworkDifficulty: firstFloat(netDiffRE, text),
		BlockHeight:       firstUint(heightRE, text),
		Checked:           time.Now(),
	}
	if prev := spacesRE.ReplaceAllString(firstGroup(prevBlockRE, text), ""); len(prev) == 64 {
		h.PrevBlock = strings.ToLower(prev)
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

func firstFloat(re *regexp.Regexp, text string) float64 {
	if m := re.FindStringSubmatch(text); len(m) > 1 {
		if f, err := strconv.ParseFloat(m[1], 64); err == nil {
			return f
		}
	}
	return 0
}
