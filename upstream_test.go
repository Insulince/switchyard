package main

import (
	"bufio"
	"encoding/json"
	"strings"
	"testing"
	"testing/iotest"
)

// The bug this guards against cost three hours of a rig hashing at difficulty
// 1 while the gateway wanted 4096, and it was invisible from every side: the
// pools were paid correctly, switchyard's own status reported the right
// number, and only the gateway's reject counter showed anything wrong.
//
// bufio.Scanner reuses one buffer, so Bytes() is only valid until the next
// Scan. handleNotification retains what it is handed for the life of the
// session, so an uncopied slice quietly mutates into whatever line arrived
// afterwards -- and a rig primed with half a job, or with a share-rejection
// response, does not complain. It just keeps working at its default of 1.
func TestRetainedLinesSurviveFurtherReads(t *testing.T) {
	const (
		diffLine   = `{"id":null,"method":"mining.set_difficulty","params":[4096]}`
		notifyLine = `{"id":null,"method":"mining.notify","params":["job1","abcd","cb1","",[],"20000000","190fffff","66000000",true]}`
		// The line that did the clobbering in the real incident: long enough
		// to overwrite both retained slices in place.
		noise = `{"error":[23,"high-hash",null],"id":179681,"result":null}                                             `
	)

	u := newUpstream(newCoordinator(testConfig()), 0, testConfig().Rigs[0], testConfig().Pools[0])

	// OneByteReader is what makes this a real reproduction. Handed the whole
	// input at once, Scanner reads all three lines into distinct regions of
	// one buffer and nothing is ever overwritten -- the bug does not appear.
	// A socket delivers a line at a time, so Scanner must refill and compacts
	// by copying the remainder over the front of the buffer, which is exactly
	// where the previously returned token lives.
	src := iotest.OneByteReader(strings.NewReader(diffLine + "\n" + notifyLine + "\n" + noise + "\n"))
	sc := bufio.NewScanner(src)
	sc.Buffer(make([]byte, 0, 256), maxLine)

	for sc.Scan() {
		// Deliberately NOT copied, so this reproduces the original failure
		// exactly and pins the defence where it belongs: handleNotification
		// must own what it retains, whatever its caller hands it.
		line := sc.Bytes()
		var m message
		if err := json.Unmarshal(line, &m); err != nil {
			continue
		}
		if m.isNotification() {
			u.handleNotification(&m, line)
		}
	}

	if got := string(u.lastDiff); !strings.Contains(got, `"params":[4096]`) {
		t.Errorf("lastDiff = %q, want a set_difficulty carrying 4096", got)
	}
	if u.diff != 4096 {
		t.Errorf("diff = %d, want 4096", u.diff)
	}
	if got := string(u.lastNotify); !strings.Contains(got, `"mining.notify"`) {
		t.Errorf("lastNotify = %q, want the job line", got)
	}
}

// A difficulty we cannot parse must not become the difficulty we hand a rig.
// Storing it would be worse than dropping it: the rig silently falls back to 1
// and floods, where dropping leaves the last known-good value in place.
func TestUnparseableDifficultyIsRejected(t *testing.T) {
	u := newUpstream(newCoordinator(testConfig()), 0, testConfig().Rigs[0], testConfig().Pools[0])

	good := []byte(`{"id":null,"method":"mining.set_difficulty","params":[1024]}`)
	var m message
	_ = json.Unmarshal(good, &m)
	u.handleNotification(&m, good)

	for _, bad := range []string{
		`{"id":null,"method":"mining.set_difficulty","params":[]}`,
		`{"id":null,"method":"mining.set_difficulty","params":["nonsense"]}`,
		`{"id":null,"method":"mining.set_difficulty","params":[0]}`,
	} {
		var bm message
		if err := json.Unmarshal([]byte(bad), &bm); err != nil {
			t.Fatalf("test input is not valid JSON: %v", err)
		}
		u.handleNotification(&bm, []byte(bad))
		if u.diff != 1024 {
			t.Fatalf("%s replaced a good difficulty: diff = %d", bad, u.diff)
		}
		if !strings.Contains(string(u.lastDiff), "1024") {
			t.Fatalf("%s replaced a good lastDiff: %q", bad, u.lastDiff)
		}
	}
}

func testConfig() config {
	c := config{
		StatusListen: "127.0.0.1:0",
		Pools:        []poolConfig{{Name: "lazarus", Host: "127.0.0.1", Port: 23338, StatusPort: 7156}},
		Rigs:         []rigConfig{{Listen: "0.0.0.0:23401"}},
	}
	c.applyDefaults()
	return c
}
