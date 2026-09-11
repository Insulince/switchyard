package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"
)

// probeStratum answers the question the status page cannot: is the port you
// typed actually a stratum server, and is it the same gateway?
//
// WHY THIS EXISTS. A pool entry is two ports on one host, and until now only
// one of them was checked. Reaching the status page proved the host was right
// and said nothing whatever about the stratum port, so a wrong number there
// produced a green "connected to DATUM gateway" line and a pool that could
// never carry a share. That is the worst shape a check can have: confident,
// prominent, and answering a different question than the one being asked.
//
// A bare TCP dial is not enough either, and is in fact the trap itself. Type
// the status port into the stratum field and the dial succeeds -- it is an
// open port on a live service. So this speaks stratum: it sends a real
// mining.subscribe and requires a well-formed response with the same id.
// An HTTP server answers that with an HTTP error page, which does not parse,
// which is the point.
//
// The connection is opened, one line is exchanged, and it is closed. The
// gateway sees a client that subscribed and left, which is a thing miners do
// constantly and it is built to handle.
func probeStratum(ctx context.Context, addr string) error {
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()

	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		// Classified rather than assumed. A refused connection and a hostname
		// that does not resolve are different mistakes in different fields,
		// and reporting the second as "nothing is listening on port 23335"
		// points the reader at the one thing they got right.
		n, _ := strconv.Atoi(portOf(addr))
		return errors.New(shortReachError(err, n))
	}
	defer func() { _ = conn.Close() }()

	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}

	const probeID = 9001
	req := fmt.Sprintf(
		`{"id":%d,"method":"mining.subscribe","params":["switchyard-probe"]}`+"\n", probeID)
	if _, err := conn.Write([]byte(req)); err != nil {
		return fmt.Errorf("port %s accepted the connection then dropped it", portOf(addr))
	}

	sc := bufio.NewScanner(conn)
	// Stratum lines are small. A cap keeps a wrong port that happens to be a
	// firehose from being read into memory a line at a time.
	sc.Buffer(make([]byte, 0, 8*1024), 64*1024)

	for sc.Scan() {
		var m struct {
			ID     json.RawMessage `json:"id"`
			Result json.RawMessage `json:"result"`
			Error  json.RawMessage `json:"error"`
			Method string          `json:"method"`
		}
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			// Not JSON at all. An HTTP server lands here, which is exactly the
			// mistake this check was written for.
			return fmt.Errorf("port %s answered, but not as a stratum server "+
				"— check you have not used the status port here", portOf(addr))
		}
		// A gateway may push set_difficulty or notify before answering the
		// subscribe. Those are proof enough on their own, but keep reading for
		// the response so a rejection is reported as one.
		if m.Method != "" {
			continue
		}
		if string(m.ID) != strconv.Itoa(probeID) {
			continue
		}
		if len(m.Error) > 0 && string(m.Error) != "null" {
			return fmt.Errorf("stratum server refused the check: %s", m.Error)
		}
		if len(m.Result) == 0 || string(m.Result) == "null" {
			return fmt.Errorf("port %s answered a subscribe with nothing", portOf(addr))
		}
		return nil
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("port %s did not answer a stratum subscribe in time", portOf(addr))
	}
	// Reached by a port that is open, is not stratum, and hangs up rather than
	// replying -- which is what DATUM's own status server does, and therefore
	// the single most likely thing on the other end of a wrong number here.
	return fmt.Errorf("port %s is open but did not answer a stratum subscribe "+
		"— is that really the miner port?", portOf(addr))
}

// portOf is for messages only: the operator typed a port, so a failure should
// name the port rather than a host:port they did not type.
// portOf is the port from a host:port, a bare ":port", or a bare port --
// every form an operator can end up with. SplitHostPort rather than a colon
// scan, so a bracketed IPv6 host does not lose its address to the split.
func portOf(addr string) string {
	if _, p, err := net.SplitHostPort(addr); err == nil {
		return p
	}
	return addr
}
