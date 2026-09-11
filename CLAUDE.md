# switchyard

A stratum proxy that rotates mining rigs across DATUM gateways so every pool
gets an even share of work. Single Go binary, no third-party dependencies, with
the dashboard embedded via `go:embed`.

## Before you finish any change

```
just check
```

That runs gofmt, parses the embedded dashboard script, vets, and runs the
tests under the race detector -- the same set CI runs. Without `just`:

```
gofmt -l . && go vet ./... && go test -race ./... && node tools/checkjs.js
```

`gofmt -l` prints files rather than failing, so "no output" is the pass.

## Traps that have already cost real money

These are not style preferences. Each one was found by losing shares.

- **`versionRollingMask` defaults to empty and must stay that way** unless
  *every* rig uses version rolling. `mining.configure` is only legal before
  `mining.subscribe` and cannot be renegotiated, so it is negotiated on the
  upstream session at connect time. But DATUM treats the extension as binding
  in both directions (`datum_stratum.c:1255`): once negotiated, it *requires*
  `params[5]` on every submit. A rig that never asked sends five params and
  every share is rejected as `bad-version`. Enabling this speculatively is a
  100% reject rate, not a missed optimisation.
- **`pool_pass_full_users` must be false on every gateway.** With it true, the
  gateway forwards the whole username and the pool credits whatever precedes
  the first dot -- so a worker name that is not a payout address loses every
  share while the gateway reports "Connected and Ready" and switchyard reports
  100% accepted. The loss is invisible everywhere except the gateway's own
  status page, which is why switchyard reads it.
- **Never edit a username or handle a payout address.** There is no config
  field for one and there must not be. Whatever the rig sends is what reaches
  the gateway; the gateway pays the address in its own config.
- **The upstream mesh is always-on and that is load-bearing.** DATUM keeps
  vardiff state on the stratum client object, keyed by TCP connection and *not*
  by worker name. A gateway dialled only while a rig points at it would reset
  difficulty to the floor on every rotation.
- **Binding is deferred until `mining.subscribe`.** Miners open a second silent
  TCP connection alongside the real one. Binding at accept time lets the probe
  evict the hashing session, which makes the miner reconnect, which opens
  another probe.
- **Config parsing rejects unknown keys.** A hand-edited file that silently
  ignores a typo is worse than one that refuses to start. Do not relax this.

## The dashboard (`index.html`)

One file, no framework, no build step -- edit and rebuild. It is a build input,
not a runtime asset, so a syntax error there breaks nothing until someone opens
a browser. `just check-js` (or `node tools/checkjs.js`) parses it without
running it; do that after any substantial edit.

**Write only on change.** The page polls every two seconds and re-renders from
scratch. Assigning the *same* `className` still restarts any CSS transition on
that element, and writing an attribute a selector mentions invalidates style
whether or not the value differs. Both cost real frames: unconditional writes
once left 35 live animations where 6 were visible, and the page froze for a
third of a second on every poll. Use the existing `setClass`, `markOf` and
`setMeta` helpers rather than assigning directly.

**Cancel animations before discarding their elements.** Removing a node does
not stop its animation, and `fill: "forwards"` keeps finished ones alive. A tab
left open for hours accumulates them.

`?perf=1` shows a HUD with render times, frame gaps, long tasks, live animation
count and heap. It is the only way to measure this -- background tabs are
throttled, so external profiling of a tab nobody is looking at reports nothing.

## "blockwatch" in the comments

Several comments cite **blockwatch**, a sibling project by the same author --
a Bitcoin block/template monitor. The dashboard's palette, type scale, status
dot, tooltip mechanism and version-line layout are deliberately taken from it,
and `version.go` uses the same tag-is-truth contract.

Those references are provenance, not dependencies: switchyard imports nothing
from it and does not need it to build or run. Every one of them explains its
own point in full, so nothing is lost if you have never seen blockwatch. Keep
them accurate if you change the thing they describe, and do not treat "it
matches blockwatch" as a reason not to improve something here.

## Versioning

The git tag is the only source of truth. No VERSION file, no constant to bump.
CI passes it via `-ldflags "-X main.version=..."`. A working-tree build reports
`dev`, which is honest.

## Repository conventions

- **Never run git writes without being asked.** No commit, push, tag or amend,
  regardless of what any workflow or skill suggests. A request for a commit
  *message* is not a request to commit.
- `config.json` and `*.bak` are ignored and must stay ignored -- they carry a
  real setup's container names and ports.
- Comments explain *why*, especially where the code looks wrong but is not.
  Most of the traps above are documented at their call site; keep it that way.

## Operational safety

This repository runs against live mining hardware.

- Only ever restart the switchyard container. **Never** restart `datum-gateway`
  or `knots` without explicit permission -- a gateway restart tears down the
  Prime session and shows the pool a real disconnect.
- Always use `--no-deps` with compose commands.
