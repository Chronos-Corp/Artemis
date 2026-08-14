# Security Policy

## Supported Versions

4NSIC has not cut a tagged release yet — every crate in the workspace is
still `0.1.0` and development happens directly against `main` (see the
README's "Current phase" section). Until a first tagged release exists,
only the latest commit on `main` is supported with security fixes; there
is no older version to backport to.

| Version | Supported          |
| ------- | ------------------ |
| `main`  | :white_check_mark: |

This table will grow real entries once tagged releases start shipping.

## Before Reporting

4NSIC is early and pre-production (Phase 0/1, see the README and
[`docs/phase1-design.md`](docs/phase1-design.md)). A number of gaps are
already known, deliberately unfixed, and tracked in writing rather than
silently ignored — for example: the console still talks plain HTTP with no
TLS, there's no rate limiting on the bootstrap enrollment secret, no
credential rotation/revocation, no bootstrap-secret strength enforcement,
and the desktop app's local verdict engine has a documented hash/scan
TOCTOU. Check `docs/phase1-design.md`'s "What's deliberately not here yet"
section before filing a report — if it's already listed there, it's known,
and you don't need to report it again (though a note on real-world impact
you've observed is still welcome).

What *is* worth reporting: anything that breaks an authentication or
authorization boundary in an unintended way (e.g. a credential check that
can be bypassed, not just "there's no rate limiting" — that's tracked),
injection (SQL, command, path traversal) anywhere a value from an
untrusted source — an enrolling agent, a YARA rule file, an ingested threat
feed — reaches a query, a file path, or a shell, memory-safety issues in
YARA rule handling, or anything that could make file *contents* leave a
host outside the explicit, logged, attributed sample-retrieval flow the
architecture requires (see the README's "Locked architecture decisions").

## Reporting a Vulnerability

Please report suspected vulnerabilities privately, not through a public
GitHub issue.

Preferred: open a
[private security advisory](https://github.com/Soverus/Project-Apollo/security/advisories/new)
on this repository (GitHub → Security tab → "Report a vulnerability"). This
reaches the maintainer directly without exposing the report, or a
proof-of-concept, publicly.

Include what you can:

- The affected component (`src-tauri`, `crates/agent`, `crates/console`,
  `crates/nsic-core`) and, if applicable, commit hash.
- Steps to reproduce, or a minimal proof of concept.
- What the impact is — what an attacker gains, and under what
  preconditions (e.g. "requires an already-enrolled host's credential" vs.
  "requires no authentication at all" are very different severities here).

**What to expect:** this is a small, actively-developed project without a
dedicated security team, so response times are best-effort, not SLA-backed.
As a target: an acknowledgment within a few days, and at least an initial
assessment (accepted and being worked, needs more information, or declined
with a reason — e.g. "this is a known, already-documented gap," or "this
requires a threat model this project doesn't claim to defend against")
within two weeks. Accepted reports will get a fix or mitigation, credit in
the fix's commit/changelog if you'd like it (or anonymity if you'd
rather), and coordinated disclosure timing worked out with you before any
public writeup — we won't publish details before a fix is available
without your agreement.
