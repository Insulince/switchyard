package main

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

// shareFeed carries share events to the dashboard as they happen, for its
// experimental "shares" flow mode: one dot per real share.
//
// Pushed rather than polled because polling cannot do this job. The dashboard
// polls /status every two seconds, and a counter read on a timer says how many
// shares arrived since the last reading, never when -- every dot would be
// guessed into its slot. A pushed event leaves at the moment the share was
// accepted.
//
// It belongs to the server, not the coordinator, because the server is what
// outlives a reload (see server). A dashboard's stream should carry on across
// a config save rather than go quiet until the page is reloaded.
//
// Everything here is free when nobody is watching: publish is one atomic load
// on the share path, and the fast gateway loop idles on the same check.
type shareFeed struct {
	mu   sync.Mutex
	subs map[chan shareEvent]struct{}
	n    atomic.Int32
}

// shareEvent is one share, or one batch of pool-side shares.
//
// Indices rather than names: the dashboard already holds the names in the
// same order from /status, and resolving them here would mean taking the
// coordinator's locks on the share path for the sake of an animation.
type shareEvent struct {
	// Kind is "gw" for a share a gateway accepted from a rig, or "pool" for
	// shares the pool accepted from a gateway.
	Kind string `json:"k"`
	Rig  int    `json:"rig"`
	Pool int    `json:"pool"`
	// N is how many. Always 1 for "gw"; for "pool", how far the gateway's
	// counter moved between two reads, which is nearly always 1 at the rate
	// those reads run.
	N uint64 `json:"n"`
}

// shareSubBuffer is how many events a subscriber may fall behind by before
// its events are dropped. Dropped, never waited on: publish runs on the path
// every accepted share takes back to the miner, and a stalled browser tab must
// cost that path nothing. A missing dot is the whole price.
const shareSubBuffer = 64

func newShareFeed() *shareFeed {
	return &shareFeed{subs: map[chan shareEvent]struct{}{}}
}

// watched reports whether anyone is subscribed. Safe on a nil feed, which is
// what a coordinator built outside a server (every test) has.
func (f *shareFeed) watched() bool {
	return f != nil && f.n.Load() > 0
}

func (f *shareFeed) subscribe() (<-chan shareEvent, func()) {
	ch := make(chan shareEvent, shareSubBuffer)
	f.mu.Lock()
	f.subs[ch] = struct{}{}
	f.n.Store(int32(len(f.subs)))
	f.mu.Unlock()
	var once sync.Once
	return ch, func() {
		once.Do(func() {
			f.mu.Lock()
			delete(f.subs, ch)
			f.n.Store(int32(len(f.subs)))
			f.mu.Unlock()
		})
	}
}

func (f *shareFeed) publish(ev shareEvent) {
	if !f.watched() {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for ch := range f.subs {
		select {
		case ch <- ev:
		default:
		}
	}
}

// shareWatchEvery is how often each gateway's status page is read while a
// dashboard is subscribed.
//
// The pool's acceptances are visible nowhere else: DATUM pushes nothing, so
// this is a poll, and its interval IS the timing resolution of the pool leg.
// A read is one small page (~5 KB, ~10 ms on a LAN), so four a second per
// gateway is negligible -- and it only runs while someone is watching, which
// is why it is not the configured gatewayPollSeconds. That setting is for
// catching a misconfigured gateway, where minutes are fine, and it keeps its
// slow default for everyone who never opens this mode.
const shareWatchEvery = 250 * time.Millisecond

// watchPoolShares starts one fast reader per gateway that has a status page.
// One each rather than one loop over all, so a gateway that is slow to answer
// delays only its own dots.
func (co *coordinator) watchPoolShares(ctx context.Context) {
	for j, pool := range co.cfg.Pools {
		if pool.StatusPort == 0 {
			continue
		}
		go co.watchPoolSharesOf(ctx, j, pool.apiURL())
	}
}

func (co *coordinator) watchPoolSharesOf(ctx context.Context, poolIdx int, url string) {
	t := time.NewTicker(shareWatchEvery)
	defer t.Stop()
	var last uint64
	// have is whether last is a reading taken while someone was watching.
	// Cleared whenever nobody is, so that a subscriber arriving later gets
	// shares from then on -- not, in its first event, every share accepted
	// while the page was closed.
	have := false
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if !co.feed.watched() {
			have = false
			continue
		}
		h, err := inspectGatewayFull(ctx, url)
		if err != nil {
			continue
		}
		// Only an increase is shares. A decrease is the gateway restarting
		// and its counters with it: take the new value as the baseline.
		if have && h.PoolAccepted > last {
			co.feed.publish(shareEvent{Kind: "pool", Pool: poolIdx, N: h.PoolAccepted - last})
		}
		last, have = h.PoolAccepted, true
	}
}
