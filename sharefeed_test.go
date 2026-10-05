package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// publish runs on the path every accepted share takes back to the miner. A
// subscriber that has stopped reading must cost that path nothing: its events
// are dropped, never waited on.
func TestShareFeedDropsRatherThanBlocks(t *testing.T) {
	f := newShareFeed()
	if f.watched() {
		t.Fatal("watched with no subscribers")
	}
	events, unsubscribe := f.subscribe()
	if !f.watched() {
		t.Fatal("not watched with a subscriber")
	}

	done := make(chan struct{})
	go func() {
		for i := 0; i < shareSubBuffer*3; i++ {
			f.publish(shareEvent{Kind: "gw", N: 1})
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("publish blocked on a subscriber that is not reading")
	}
	if len(events) != shareSubBuffer {
		t.Errorf("buffered %d events, want the buffer full at %d", len(events), shareSubBuffer)
	}

	unsubscribe()
	unsubscribe() // idempotent: the stream handler defers it
	if f.watched() {
		t.Error("still watched after unsubscribe -- the fast gateway loop would never idle")
	}
}

// A nil feed is what every coordinator built outside a server has. Nothing
// that touches it may panic.
func TestNilShareFeedIsInert(t *testing.T) {
	var f *shareFeed
	if f.watched() {
		t.Error("nil feed reports watched")
	}
	f.publish(shareEvent{Kind: "gw"})
}

// One event per share the gateway accepted, from the response that accepted
// it, naming the rig and pool by index -- and nothing for a rejection.
func TestAcceptedSharesArePublished(t *testing.T) {
	cfg := testConfig()
	co := newCoordinator(cfg)
	co.feed = newShareFeed()
	events, unsubscribe := co.feed.subscribe()
	defer unsubscribe()

	u := newUpstream(co, 0, 1, cfg.Rigs[0], cfg.Pools[0])
	s, peer := pipeSession(t, co, "w")
	go func() { _, _ = io.Copy(io.Discard, peer) }() // net.Pipe blocks until read

	respond := func(id uint64, result string) {
		u.mu.Lock()
		u.pending[id] = pendingSubmit{sess: s, downID: json.RawMessage(strconv.FormatUint(id, 10))}
		u.mu.Unlock()
		u.routeResponse(&message{ID: json.RawMessage(strconv.FormatUint(id, 10)), Result: json.RawMessage(result)})
	}

	respond(1, "true")
	select {
	case ev := <-events:
		if ev != (shareEvent{Kind: "gw", Rig: 0, Pool: 1, N: 1}) {
			t.Errorf("event = %+v, want gw rig 0 pool 1 n 1", ev)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no event for an accepted share")
	}

	respond(2, "false")
	respond(3, "null")
	select {
	case ev := <-events:
		t.Errorf("rejection published as a share: %+v", ev)
	case <-time.After(100 * time.Millisecond):
	}
}

// The fast loop reports increases in the pool-side counter, and only those
// seen while someone is watching: a dashboard opening must not receive every
// share accepted while it was closed as one enormous first event.
func TestPoolSharesReportedOnlyWhileWatched(t *testing.T) {
	var accepted atomic.Uint64
	accepted.Store(13000)
	gw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, `<table>
		  <tr><td>Status:</td><td>Connected and Ready</td></tr>
		  <tr><td>Pool Host:</td><td>pool.example:23334</td></tr>
		  <tr><td>Pool Shares Accepted:</td><td>%d  (1 diff)</td></tr>
		</table>`, accepted.Load())
	}))
	defer gw.Close()

	co := newCoordinator(config{})
	co.feed = newShareFeed()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go co.watchPoolSharesOf(ctx, 2, gw.URL)

	// Shares accepted while nobody watches are never reported.
	accepted.Add(500)
	time.Sleep(3 * shareWatchEvery)

	events, unsubscribe := co.feed.subscribe()
	defer unsubscribe()
	// Let the first watched read take its baseline.
	time.Sleep(3 * shareWatchEvery)
	select {
	case ev := <-events:
		t.Fatalf("backlog published on subscribe: %+v", ev)
	default:
	}

	accepted.Add(2)
	select {
	case ev := <-events:
		if ev != (shareEvent{Kind: "pool", Pool: 2, N: 2}) {
			t.Errorf("event = %+v, want pool 2 n 2", ev)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no event for pool-side shares")
	}

	// A gateway restart resets its counters: that is a new baseline, not
	// a negative number of shares.
	accepted.Store(3)
	time.Sleep(3 * shareWatchEvery)
	accepted.Add(1)
	select {
	case ev := <-events:
		if ev.N != 1 {
			t.Errorf("after a counter reset, event = %+v, want n 1", ev)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no event after a counter reset")
	}
}

// The status server sets a ReadTimeout, and a share stream lives far longer
// than any request it was sized for. Checked rather than assumed: whether a
// connection deadline reaches a running handler is net/http's business, and
// a dashboard that went quiet fifteen seconds in would look like no shares.
func TestShareStreamOutlivesReadTimeout(t *testing.T) {
	s := newServer("")
	ts := httptest.NewUnstartedServer(s.routes())
	ts.Config.ReadTimeout = 150 * time.Millisecond
	ts.Start()
	defer ts.Close()

	conn, err := net.Dial("tcp", ts.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, _ = io.WriteString(conn, "GET /shares/stream HTTP/1.1\r\nHost: x\r\n\r\n")
	rd := bufio.NewReader(conn)
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	waitFor := func(want string) {
		t.Helper()
		for {
			line, err := rd.ReadString('\n')
			if err != nil {
				t.Fatalf("stream ended before %q: %v", want, err)
			}
			if strings.Contains(line, want) {
				return
			}
		}
	}
	waitFor(": open")

	// Well past the read timeout, then an event.
	time.Sleep(4 * ts.Config.ReadTimeout)
	s.feed.publish(shareEvent{Kind: "pool", Pool: 1, N: 3})
	waitFor(`data: {"k":"pool","rig":0,"pool":1,"n":3}`)
}
