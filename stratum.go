package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sync"
)

// Stratum V1 is newline-delimited JSON-RPC. Every line is one of three
// things: a request (has "method" and a non-null "id"), a server-initiated
// notification (has "method", "id" is null), or a response (echoes an "id"
// and carries "result"/"error").
//
// Every field we do not need is kept as json.RawMessage on purpose. Miner
// firmware is wildly inconsistent -- ids arrive as numbers from some units
// and strings from others, and mining.submit carries a trailing version-bits
// param only when version rolling was negotiated. Decoding into concrete
// types would reject perfectly valid lines from firmware we do not control.
// We read the two or three fields we actually care about and forward the
// rest of every line verbatim.
type message struct {
	ID     json.RawMessage `json:"id"`
	Method string          `json:"method,omitempty"`
	Params json.RawMessage `json:"params,omitempty"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  json.RawMessage `json:"error,omitempty"`
}

// isNotification reports whether a line is server->client push traffic
// (mining.notify, mining.set_difficulty, ...) rather than a reply we asked
// for. Some servers send a literal null id, others omit the field entirely,
// so both have to count.
func (m *message) isNotification() bool {
	return m.Method != "" && (len(m.ID) == 0 || string(m.ID) == "null")
}

// connWriter serialises writes to one socket. Stratum has no framing beyond
// the newline, so two goroutines writing concurrently would interleave
// halves of two JSON documents and desynchronise the peer permanently. Every
// write to every socket in this program goes through one of these.
type connWriter struct {
	mu   sync.Mutex
	w    io.Writer
	dead bool
}

func newConnWriter(c net.Conn) *connWriter { return &connWriter{w: c} }

func (cw *connWriter) writeLine(b []byte) error {
	cw.mu.Lock()
	defer cw.mu.Unlock()
	if cw.dead {
		return fmt.Errorf("writer closed")
	}
	if _, err := cw.w.Write(append(b, '\n')); err != nil {
		cw.dead = true
		return err
	}
	return nil
}

func (cw *connWriter) close() {
	cw.mu.Lock()
	cw.dead = true
	cw.mu.Unlock()
}

// rawID renders an id for interpolation into a hand-built response. Stratum
// ids may legitimately be numbers or strings; both are already valid JSON in
// their raw form, so they pass straight through. A missing id becomes null,
// which is what a notification looks like.
func rawID(id json.RawMessage) string {
	if len(id) == 0 {
		return "null"
	}
	return string(id)
}

// paramsAt pulls the nth element of a params array without decoding the
// whole thing into concrete types.
func paramsAt(params json.RawMessage, n int) (json.RawMessage, bool) {
	var arr []json.RawMessage
	if err := json.Unmarshal(params, &arr); err != nil {
		return nil, false
	}
	if n >= len(arr) {
		return nil, false
	}
	return arr[n], true
}

// paramStringAt pulls the nth element and unquotes it as a JSON string.
// paramStringAt pulls the nth element as a string: the prevhash and
// extranonce1 a gateway sends, and the username a miner offers in
// mining.authorize.
func paramStringAt(params json.RawMessage, n int) (string, bool) {
	raw, ok := paramsAt(params, n)
	if !ok {
		return "", false
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", false
	}
	return s, true
}

// paramNumberAt pulls the nth element as a JSON number. This is how
// mining.set_difficulty is read, and it MUST accept fractions: stratum
// difficulty is a number, not an integer, and a gateway that converts its
// power-of-two pool difficulty to true Bitcoin difficulty sends 1024 as
// 1023.984375. An integer-only parse dropped every one of those, the rig
// fell back to difficulty 1, and the gateway rejected 96% of what it sent
// as high-hash. Nothing downstream could tell -- the miner was happy and the
// pool-side counters looked fine.
func paramNumberAt(params json.RawMessage, n int) (float64, bool) {
	raw, ok := paramsAt(params, n)
	if !ok {
		return 0, false
	}
	var v float64
	if err := json.Unmarshal(raw, &v); err != nil {
		return 0, false
	}
	return v, true
}

// replaceParam0 rewrites the first element of a params array, which for
// mining.submit is the worker name.
//
// This matters because our upstream sessions are authorised with the worker
// name from OUR config, established long before any rig connected. Whatever
// the rig sends downstream is its own business; if we forwarded it verbatim
// the gateway would see a submit from a worker it never authorised on that
// connection. Rewriting keeps pool-side crediting anchored to one stable
// identity per rig, no matter how the miner is configured.
func replaceParam0(params json.RawMessage, v string) (json.RawMessage, error) {
	var arr []json.RawMessage
	if err := json.Unmarshal(params, &arr); err != nil {
		return nil, err
	}
	if len(arr) == 0 {
		return params, nil
	}
	q, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	arr[0] = q
	return json.Marshal(arr)
}
