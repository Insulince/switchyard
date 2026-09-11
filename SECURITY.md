# Security policy

## Reporting a vulnerability

Please report security issues **privately**, not as a public issue.

Use GitHub's private vulnerability reporting: go to the
[Security tab](https://github.com/Insulince/switchyard/security) and choose
**Report a vulnerability**. That opens a thread visible only to you and me.

I aim to acknowledge a report within a week. Switchyard is a hobby project
maintained by one person in his spare time, so that is a genuine estimate
rather than a service commitment -- but I would much rather hear about a
problem late than read about it on a pool's status page.

If a report leads to a fix, I'll credit you in the release notes unless you'd
prefer I didn't.

## Which versions get fixes

The latest release. There are no maintained branches behind it.

## What is in scope

Switchyard terminates the stratum session from your miner and opens its own
sessions to your gateways. That position is the whole design, and it is also
where anything serious would live:

- Anything that could cause shares to be submitted somewhere other than the
  configured gateways, or credited to an identity the operator did not set.
- Anything that lets a party who is not the operator change the schedule, the
  pool list, or the rig bindings.
- Remote crashes or hangs reachable from a rig-facing port, since a stalled
  proxy is stopped hashing.
- Anything that causes the dashboard to misreport what is actually happening.
  Switchyard's central claim is that it shows you the truth about your own
  setup; a number that lies is a real bug even when nothing is stolen.

## What is not in scope

- **The dashboard has no authentication, and `statusListen` defaults to
  `:7160`.** Anyone who can reach that port can rewrite `config.json`. This is
  documented, deliberate, and explained in the README -- binding to loopback by
  default made first-run unreachable on the containers and headless boxes most
  people run this on. Put it behind a tunnel or a reverse proxy on a network
  you do not trust. Reports that the unauthenticated page is unauthenticated
  will be closed as working-as-documented; a way to reach it that bypasses
  `statusListen` entirely would not be.
- Vulnerabilities in DATUM gateway, Bitcoin Knots, or Bitcoin Core. Report
  those to those projects.
- Anything requiring an attacker who already has local access to the machine or
  can edit `config.json` directly. At that point the config is the attack.

## Verifying a build

The README's *Switchyard is a man in the middle* section describes how to check
what switchyard is doing without reading the code -- comparing its self-reported
connections against the operating system's, and its share counts against your
gateway's and your pool's. Those checks exist precisely because a proxy in this
position cannot prove its own honesty. Use them.
