package main

import (
	"sort"
	"time"
)

// outboundConn is one connection switchyard has opened to somewhere else.
//
// This list exists to be checked against the operating system's own view. It
// is self-reported, so a hostile build could simply lie -- and that is worth
// saying out loud rather than glossing over. What it buys is asymmetry: an
// honest switchyard's list matches `netstat`/`ss` exactly, and a mismatch is
// immediate, decisive evidence of something wrong. Anyone can spend five
// seconds confirming it; nobody has to take the number on faith.
//
// The complete set of destinations switchyard should ever have open is the
// gateways in config.json, one connection per rig per gateway. There is no
// telemetry, no update check, no analytics endpoint, and nothing that resolves
// a hostname the operator did not write down.
type outboundConn struct {
	// Addr is the remote endpoint as passed to the dialler, and Resolved is
	// what the socket actually connected to. They differ when a name resolves
	// somewhere unexpected -- which is exactly the case worth being able to
	// see.
	Addr     string `json:"addr"`
	Resolved string `json:"resolved,omitempty"`
	Local    string `json:"local,omitempty"`

	Pool      string    `json:"pool"`
	Rig       string    `json:"rig"`
	Purpose   string    `json:"purpose"`
	Connected bool      `json:"connected"`
	Since     time.Time `json:"since,omitempty"`
}

// outbound enumerates every socket switchyard currently holds open to another
// machine, along with the reason it exists.
func (co *coordinator) outbound() []outboundConn {
	out := make([]outboundConn, 0, len(co.cfg.Rigs)*len(co.cfg.Pools))
	for i, rig := range co.cfg.Rigs {
		_ = rig
		for j, pool := range co.cfg.Pools {
			u := co.ups[i][j]
			c := outboundConn{
				Addr:    pool.stratumAddr(),
				Pool:    pool.Name,
				Rig:     co.rigLabel(i),
				Purpose: "stratum session to this gateway",
			}
			u.mu.Lock()
			if u.conn != nil {
				c.Connected = true
				if ra := u.conn.RemoteAddr(); ra != nil {
					c.Resolved = ra.String()
				}
				if la := u.conn.LocalAddr(); la != nil {
					c.Local = la.String()
				}
				c.Since = u.connectedAt
			}
			u.mu.Unlock()
			out = append(out, c)
		}
	}
	// Grouped by destination, because that is how the same question is asked
	// of the operating system.
	sort.SliceStable(out, func(a, b int) bool {
		if out[a].Addr != out[b].Addr {
			return out[a].Addr < out[b].Addr
		}
		return out[a].Rig < out[b].Rig
	})
	return out
}
