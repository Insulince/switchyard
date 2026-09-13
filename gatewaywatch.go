package main

import (
	"context"
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
			if err != nil {
				prev, _ := co.gw.get(pool.Name)
				prev.Err = err.Error()
				prev.Checked = time.Now()
				co.gw.set(pool.Name, prev)
				continue
			}
			was, _ := co.gw.get(pool.Name)
			co.gw.set(pool.Name, *info)
			// Log the transition, not the state: an operator who has this
			// dashboard closed should still find it in the journal.
			if info.Unpooled && !was.Unpooled {
				log.Printf("WARNING: gateway %s reports %q -- it has no pool and is solo mining "+
					"under its own tag. Rotations onto it are not reaching %s.",
					pool.Name, info.Status, pool.displayName())
			}
			if info.rejecting() && !was.rejecting() {
				log.Printf("WARNING: pool behind %s is rejecting the work this gateway accepts "+
					"(%d rejected vs %d accepted upstream). Check pool_pass_full_users on that gateway.",
					pool.Name, info.PoolRejected, info.PoolAccepted)
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
)

// inspectGatewayFull is inspectGateway plus the share counters. Split so the
// editor's one-shot "Inspect" button and this poller cannot drift apart.
func inspectGatewayFull(ctx context.Context, rawURL string) (*gatewayHealth, error) {
	info, text, err := fetchGatewayStatus(ctx, rawURL)
	if err != nil {
		return nil, err
	}
	h := &gatewayHealth{
		PoolHost:     info.PoolHost,
		Status:       info.Status,
		Tag:          info.Tag,
		PoolAccepted: firstUint(poolAccRE, text),
		PoolRejected: firstUint(poolRejRE, text),
		Checked:      time.Now(),
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
