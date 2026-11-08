# Setup

## 1. Python environment

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

## 2. External tool binaries

recon-engine orchestrates these rather than reimplementing them (see
`docs/ARCHITECTURE.md` for why). Install whichever ones you want — every
module degrades gracefully with a clear warning if its tool is missing,
so you don't need all of them to get started.

| Tool | Install | Used by |
|---|---|---|
| [subfinder](https://github.com/projectdiscovery/subfinder) | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` | `subdomain_passive.py` |
| [amass](https://github.com/owasp-amass/amass) | `go install github.com/owasp-amass/amass/v4/...@master` | `subdomain_passive.py` |
| [bbot](https://github.com/blacklanternsecurity/bbot) | `pipx install bbot` | `subdomain_passive.py` (optional) |
| [puredns](https://github.com/d3mondev/puredns) | `go install github.com/d3mondev/puredns/v2@latest` (needs [massdns](https://github.com/blechschmidt/massdns) too) | `subdomain_bruteforce.py`, `permutation.py` |
| [dnsgen](https://github.com/ProjectAnte/dnsgen) | `pip install dnsgen` | `permutation.py` |
| [alterx](https://github.com/projectdiscovery/alterx) | `go install github.com/projectdiscovery/alterx/cmd/alterx@latest` | `permutation.py` (alternative engine) |
| [naabu](https://github.com/projectdiscovery/naabu) | `go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest` | `port_scan.py` |
| [rustscan](https://github.com/RustScan/RustScan) | see repo | `port_scan.py` (optional) |
| [smap](https://github.com/s0md3v/Smap) | `go install github.com/s0md3v/smap/cmd/smap@latest` | `port_scan.py` (needs Shodan key) |
| [httpx](https://github.com/projectdiscovery/httpx) | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` — **not** the Python `httpx` pip package | `live_validation.py` |
| [go-stare](https://github.com/dwisiswant0/go-stare) | see repo | `screenshotting.py` |
| [gowitness](https://github.com/sensepost/gowitness) | via Docker, see `screenshotting.py: gowitness_docker` | `screenshotting.py` (optional) |
| [EyeWitness](https://github.com/RedSiege/EyeWitness) | see repo | `screenshotting.py` (optional, for default-cred-checker) |
| [VHostScan](https://github.com/codingo/VHostScan) | `pip install VHostScan` | `vhost_scan.py` |
| [github-subdomains](https://github.com/gwendal-lv/github-subdomains) | `go install github.com/gwendal-lv/github-subdomains@latest` | `github_recon.py` |
| [trufflehog](https://github.com/trufflesecurity/trufflehog) | see repo | `github_recon.py` (optional) |
| [FavFreak](https://github.com/devanshbatham/FavFreak) | `git clone` it; point `tools.favfreak` at `favfreak.py` | `favicon_fingerprint.py` (optional — native hashing works without it) |
| [waymore](https://github.com/xnl-h4ck3r/waymore) | `pip install waymore` | `csp_misc.py` (optional) |

Run `recon-engine config-check` any time to see exactly which of these
are currently detected on `PATH`.

## 3. API keys

Copy `config/config.example.yaml` to `config/config.yaml` and fill in
whatever you have. Priority order (matches TBHM's own KB §12.4
recommendation):

1. **Chaos** — free, instant signup: https://chaos.projectdiscovery.io
2. **GitHub tokens** — free, instant: https://github.com/settings/tokens
   (classic tokens, no special scopes needed for code search). Get
   **several** — recon-engine round-robins across all configured tokens.
3. **Shodan** — freemium: https://account.shodan.io/register
4. **Free/cheap**: FacebookCT (requires creating a Facebook Developer
   app — see the deck's own walkthrough, reproduced in
   `config/config.example.yaml`'s comments), c99/RiskIQ, dnsdumpster
5. **Paid/limited**: whoxy, whoisxmlapi, host.io, SecurityTrails,
   Crunchbase (enterprise sales contact, not self-serve), sec-api.io
   (free tier available), greyhatwarfare

## 4. Not wired up — and why (read this before filing an issue)

- **Tracxn, Pitchbook, OCCRP Aleph**: browse-only / enterprise-gated web
  tools with no public API suited to this use case.
  `acquisitions.py: manual_research_checklist()` gives you direct search
  URLs instead.
- **Google Alerts**: no public API for programmatically creating an
  alert. Set one up by hand for `"<company> acquisition"` as the deck
  itself demonstrates.
- **Mass Google/Bing dorking**: search engines actively block scripted
  querying at volume. `subdomain_passive.py: google_exclusion_dork()`
  generates the query string for you to paste into a browser, same as
  the deck's own manual workflow.
- **DuckDuckGo Tracker Radar / Cloudflare Radar**: named in the deck's
  final appendix with no elaboration beyond the title. Both have real
  public APIs/datasets; not wired up because there's no concrete
  technique described to implement against — see
  `TBHM-DAY-ONE-KNOWLEDGE-BASE.md` §22.4 for exactly what the source
  said (very little).
- **check_mdi.py**: the deck itself marks this deprecated/broken
  (Microsoft changed `GetFederationInformation`'s behavior). Not
  reimplemented on purpose — see `msft_tenant.py` for the working
  replacement approach.

## 5. First run

```bash
recon-engine config-check
recon-engine scan example.com
recon-engine scan example.com --github --screenshots --favicon --favicon-db ./favfreak-hashes.json
recon-engine scan example.com --bruteforce --permutation --wordlist words.txt --resolvers resolvers.txt
recon-engine changes example.com --since-hours 168
recon-engine sources --target example.com
```

Only scan targets you are authorized to test.
