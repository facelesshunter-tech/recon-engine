# recon-engine

A bug bounty reconnaissance orchestrator built to cover **every technique**
in Jason Haddix's "The Bug Hunter's Methodology — Day One" training deck:
ASN/IP discovery, subdomain enumeration (passive, brute-force, and
pattern-based permutation), GitHub secret/subdomain hunting, WHOIS/DNS/
IP/DMARC pivoting, VHost discovery, live-host triage, favicon
fingerprinting, and CVE-aware asset prioritization — wired together into
one pipeline with persistent state for change detection over time.

See [`docs/MODULE-MAP.md`](docs/MODULE-MAP.md) for the complete,
section-by-section accounting of which source-material concept maps to
which module, including honest notes on the handful of things that
genuinely can't be automated (GUI-only business-intelligence tools, mass
search-engine dorking, a community practice game).

## Why this exists

Most recon tooling either reimplements subdomain enumeration badly, or
is scoped to one technique at a time. This follows the same architecture
as the source material's own reference frameworks (reNgine, reconftw):
**orchestrate best-in-class existing tools** (Subfinder, Amass, httpx,
puredns, dnsgen, naabu, VHostScan, github-subdomains, TruffleHog, ...)
and implement direct API/protocol logic natively for the techniques that
have no off-the-shelf tool (reverse WHOIS/DNS/IP pivoting, DMARC-sharing
discovery, favicon fingerprinting, GitHub dork generation, CVE-aware
scoring). See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Quickstart

```bash
pip install -e .
cp config/config.example.yaml config/config.yaml   # fill in whatever API keys you have
recon-engine config-check                            # see what's active
recon-engine scan example.com
```

Full setup, including every external tool's install command and every
API key's signup link: [`docs/SETUP.md`](docs/SETUP.md).

## What a scan produces

```
recon-output/
├── assets.db              # persistent SQLite asset inventory (all history)
├── example.com.json       # this run's new assets + ranked live hosts
├── example.com.md         # same, human-readable
└── screenshots/example.com/   # if --screenshots was passed
```

```bash
recon-engine changes example.com --since-hours 168    # what's new this week
recon-engine sources --target example.com              # which technique found what
```

## Project layout

```
recon_engine/
  cli.py          # entrypoint: scan / changes / sources / config-check
  pipeline.py      # orchestrates every module into one feed-forward pipeline
  config.py        # API key + tool-path resolution (config.yaml + env vars)
  state.py          # SQLite asset inventory, new-asset / source-reliability queries
  models.py         # shared Asset / LiveHost data model
  modules/          # one file per TBHM technique -- see docs/MODULE-MAP.md
  scoring/           # CVE-watchlist + "stuff to watch for" asset ranking
  reporting/          # JSON + Markdown export
docs/
  MODULE-MAP.md      # every concept -> module, with honest implementation status
  ARCHITECTURE.md
  SETUP.md
  PROGRAM_SELECTION.md
templates/
  VULNERABILITY_REPORT_TEMPLATE.md
config/
  config.example.yaml   # every named API source, scaffolded
```

## Scope and responsible use

This tool is for authorized security testing only — bug bounty programs
you're enrolled in, or infrastructure you own or have explicit written
permission to test. Several stages (bruteforce, permutation, port
scanning) actively generate traffic against discovered hosts; confirm
scope before pointing them at a target. See
[`docs/PROGRAM_SELECTION.md`](docs/PROGRAM_SELECTION.md).

## Provenance

Built from `TBHM-DAY-ONE-KNOWLEDGE-BASE.md`, a structured ingestion of
the 224-page "TBHM Day One" slide deck (Jason Haddix / Arcanum
Information Security), produced in a companion session before this
repository existed. See that file for the full page-by-page source
material this project implements.
