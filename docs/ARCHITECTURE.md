# Architecture

## Why an orchestrator, not a reimplementation

TBHM itself names Subfinder, Amass, httpx, and puredns as best-in-class
tools, and its own reference "recon frameworks" (reNgine, reconftw) are
both orchestrators that call out to specialized binaries rather than
reimplementing subdomain enumeration, port scanning, etc. from scratch.
recon-engine follows the same pattern:

- **`utils/subprocess_runner.py`** is the one place external binaries get
  shelled out to, with consistent timeout/error handling.
- **`utils/http.py`** is the one place API-based sources get called, with
  a consistent User-Agent and timeout policy.
- **Every `modules/*.py` file is a thin, single-responsibility wrapper**
  around either an external tool or an external API, matching exactly one
  named TBHM technique (see `docs/MODULE-MAP.md` for the full mapping).

Things that are genuinely just DNS/HTTP protocol work with no advantage
to shelling out (PTR lookups, DMARC TXT record parsing, CSP header
parsing, cert SAN extraction) are implemented natively in Python instead
of wrapping a CLI tool for them.

## Data flow

```
target domain
     │
     ▼
subdomain_passive.py ──┐
github_recon.py ───────┼──► dedupe.py ──► state.py (AssetStore, SQLite)
subdomain_bruteforce.py┤         │
permutation.py ─────────┘        │ (new assets this run vs. all-time)
                                  ▼
                         live_validation.py (httpx)
                                  │
                    ┌─────────────┼─────────────┐
                    ▼             ▼              ▼
          favicon_fingerprint  screenshotting   (tech already
                .py               .py            detected by httpx)
                    │             │
                    └──────┬──────┘
                           ▼
                scoring/prioritize.py (risk_score, risk_reasons)
                           │
                           ▼
                reporting/export.py (JSON + Markdown)
```

Everything upstream of `live_validation.py` produces a flat set of
candidate hostnames; `live_validation.py` is the single point where
"is this real" gets checked, mirroring the "feed results forward into
httpx" pattern that recurs throughout the source material for nearly
every technique.

## Why `state.py` exists (not just flat files)

Two capabilities explicitly called for in the project's own capability
inventory depend on persistent, queryable state rather than a one-shot
script:

1. **Change detection** (`pipeline.py: change_report`) — TBHM's "recon is
   a cycle" framing only has teeth if you can ask "what's new since last
   time," which requires remembering what you saw before.
2. **Source-reliability scorecard** (`pipeline.py: source_reliability`) —
   tracking which technique found which asset, across every scan, not
   just the current run.

SQLite was chosen over a flat JSON/CSV asset list specifically so these
two queries (`new_since`, grouped source counts) are cheap and don't
require re-reading/re-parsing the entire history on every run.

## What's deliberately NOT auto-recursive

TBHM frames recon as cyclical — a newly-found apex domain (via
acquisitions, GitHub, or AI) should trigger re-running earlier stages
against it. `pipeline.py`'s module docstring explains the deliberate
choice not to implement this as automatic unbounded recursion within a
single run: scope creep in bug bounty has real consequences (testing an
asset you weren't authorized to touch), so expanding to a newly-found
apex domain is left as an explicit `recon-engine scan <new-domain>` call
a human decides to make, not something the tool does on its own.
