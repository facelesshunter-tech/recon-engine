# recon-engine

A bug bounty reconnaissance orchestrator built to cover **every technique**
in Jason Haddix's "The Bug Hunter's Methodology — Day One" training deck,
plus the additional senior-recon tooling a real engagement needs beyond
it: ASN/IP discovery, subdomain enumeration (passive, brute-force, and
pattern-based permutation) with automatic cross-tool deduplication,
GitHub secret/subdomain hunting (including GitDorker), WHOIS/DNS/IP/DMARC
pivoting, DNS validation and wildcard filtering (dnsx), VHost discovery,
live-host triage with TLS/cert probing (tlsx) and WAF fingerprinting
(wafw00f), content discovery (ffuf), JS-aware crawling and historical URL
mining (Katana/gau), JS endpoint/secret/source-map extraction, hidden
parameter discovery (Arjun + x8), API route brute-forcing (Kiterunner),
favicon fingerprinting, scoped CVE-watchlist verification (nuclei,
enriched with live EPSS/CISA-KEV data), and CVE-aware asset
prioritization — wired together into one staged, senior-methodology
pipeline ("the right tool at the right time," passive before active,
cheap before expensive) with persistent state for change detection over
time.

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

Three separate, purpose-built output files per target -- deliberately
not merged into one blob, so "what should I look at first" (ranked
worklist) stays distinct from "what does this infrastructure actually
look like" (architecture map) and "what did every opt-in deep-dive tool
find" (raw auxiliary findings):

```
recon-output/
├── assets.db                      # persistent SQLite asset inventory (all history)
├── example.com.json                # this run's new assets + ranked live hosts
├── example.com.md                  # same, human-readable ranked worklist
├── example.com-architecture.md     # per-host tech stack, TLS/cert, WAF, DNS -- the infra map
├── example.com-findings.json       # raw results from any opt-in deep-dive stage that ran
│                                    # (GitDorker, cloud_enum, ffuf, Katana/gau, JS analysis,
│                                    #  Arjun/x8, Kiterunner, scoped nuclei verification)
└── screenshots/example.com/        # if --screenshots was passed
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
  modules/          # one file per technique -- see docs/MODULE-MAP.md
  scoring/           # CVE-watchlist + "stuff to watch for" asset ranking, EPSS/CISA-KEV enrichment
  reporting/          # export.py (ranked worklist, JSON+Markdown), architecture.py (infra/tech-detection map)
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
