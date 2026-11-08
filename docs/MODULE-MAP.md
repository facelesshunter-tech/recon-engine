# Module Map: every TBHM Day One concept, and where it lives

This is the completeness proof for recon-engine. Every section of
`TBHM-DAY-ONE-KNOWLEDGE-BASE.md` (the ingestion artifact this project was
built from) is accounted for below — implemented, partially implemented
with an honest caveat, or explicitly documented as non-automatable with
the reason why. Nothing was silently dropped.

Status legend:
- ✅ **Implemented** — working code, calls a real API or external tool
- ⚠️ **Partial** — implemented with a caveat (best-effort API shape, or a
  substituted-but-equivalent data source — each one documented in its
  module's own docstring)
- 📄 **Documented, not automated** — a real technique, but one that is a
  GUI-only tool, a manual judgment call, or something whose automation
  would violate a service's terms of use; the module/doc that covers the
  *manual* version is listed
- 🚫 **N/A** — not a technical recon technique (philosophy, community
  content, non-technical framing)

| KB § | Concept | Module(s) | Status |
|---|---|---|---|
| §1.1–1.4 | Legal/class logistics, mental health, "Tales from the Breach" anecdotes | — | 🚫 N/A — non-technical framing |
| §1.2 | Note-taking / mind-map methodology | `reporting/export.py` (JSON+Markdown output replaces Xmind) | ✅ |
| §1.5 | Reporting template | `templates/VULNERABILITY_REPORT_TEMPLATE.md` | ✅ |
| §2 | Recon concepts (wide-then-narrow, recon-as-a-cycle) | `pipeline.py` architecture, `state.py` new-asset tracking | ✅ (architectural principle, not a single function) |
| §3 | Program/platform selection, VDP/scope reading | `docs/PROGRAM_SELECTION.md` | 📄 — human judgment call, not automatable; reference doc provided |
| §4 | ASN/IP-range discovery | `modules/asn_discovery.py` | ✅ (via bgpview.io + RIPEstat, see module docstring for why not bgp.he.net directly) |
| §4.1 | Microsoft tenant / Autodiscover interrogation | `modules/msft_tenant.py` | ⚠️ — `check_mdi.py` itself is deprecated per the deck; re-implemented via the still-functioning public OpenID/GetUserRealm endpoints; full tenant-domain enumeration needs an authenticated Graph query (documented in-module) |
| §4.3 | ASN→certificate scanning (Caduceus) | `modules/cert_pivot.py: scan_cidrs` | ✅ |
| §4.4 | Cloud-provider IP ranges / kaeferjaeger.gay | `modules/asn_discovery.py: cloud_provider_ranges`, `modules/cert_pivot.py: kaeferjaeger_lookup` | ✅ |
| §5 | Reverse WHOIS (whoxy) | `modules/reverse_whois.py` | ✅ |
| §6 | Reverse DNS (hakrevdns) + shared-nameserver pivot (whoisxmlapi) | `modules/reverse_dns.py` | ✅ |
| §7 | Reverse IP (host.io) | `modules/reverse_ip.py` | ✅ |
| §8 | DMARC analysis | `modules/dmarc_pivot.py` | ⚠️ — shared-identifier grouping across known subdomains is pure-DNS and fully implemented; reverse-searching the whole internet by identifier is best-effort via SecurityTrails (no exact public equivalent of dmarc.live/dmarcly.com's consumer tooling exists as an API) |
| §9 | Acquisitions (Crunchbase, Tracxn, Pitchbook, OCCRP, SEC-API.io, Google Alerts) | `modules/acquisitions.py` | ⚠️ — Crunchbase (enterprise-only API) and SEC-API.io implemented; Tracxn/Pitchbook/OCCRP Aleph documented as manual (`manual_research_checklist()` gives direct search URLs); Google Alerts has no public API for programmatic alert creation — documented in `docs/SETUP.md` |
| §10 | AI-assisted recon ("ReconGPT"/SubreconGPT/SubDoctor) | `modules/ai_recon.py` | ✅ — both named use cases (subdomain-pattern guessing, acquisition cross-referencing) implemented with TBHM's own "must be independently verified" caveat enforced as a `verified` field, not just a suggestion |
| §11 | CSP mining, crossdomain.xml, Waymore | `modules/csp_misc.py` | ✅ |
| §12.1 | Source-category taxonomy (infra/search/cert/security sources) | realized by which tools `subdomain_passive.py` wraps (Subfinder/Amass/BBOT each pull from most of these categories internally) | ✅ (via wrapped tools, not reimplemented per-source) |
| §12.2 | Google dork subdomain exclusion | `modules/subdomain_passive.py: google_exclusion_dork` | 📄 — generates the query string only; mass-querying Google programmatically violates its ToS and the deck itself does this manually in a browser |
| §12.3 | Subfinder / Amass / BBOT | `modules/subdomain_passive.py` | ✅ |
| §12.4 | API key prioritization strategy | `config/config.example.yaml`, `cli.py: config-check` | ✅ |
| §13 | GitHub enumeration (github-subdomains, dorking, TruffleHog, "what else to learn") | `modules/github_recon.py` | ✅ |
| §14 | Subdomain bruteforce (puredns/massdns, resolvers) | `modules/subdomain_bruteforce.py` | ✅ |
| §15 | Permutation/alteration scanning (dnsgen/altdns/alterx) | `modules/permutation.py` | ✅ |
| §16 | VHost scanning (VHostScan) | `modules/vhost_scan.py` | ✅ |
| §17 | Screenshotting (httpx, EyeWitness, go-stare, EyeBaller, GoWitness) | `modules/live_validation.py`, `modules/screenshotting.py` | ✅ / ⚠️ — EyeBaller's ML-classification step is not reimplemented (would need its trained model); recon-engine's `scoring/prioritize.py` provides a rule-based equivalent instead. `gowitness` (native v3, no Docker needed) is the default `scan --screenshots` engine and feeds structured title/screenshot-path data back into the report, which go-stare's output never provided. `EyeWitness` is also available (`screenshotting.eyewitness()`) specifically for its default-credential-checker -- deliberately not part of the automated pipeline (meant for a targeted second pass against your top-scored hosts, not every discovered host); its official installer demands root, but in practice almost every dependency it wants is already present on a system that's done security-tool work, leaving only a couple of pip packages -- see `docs/SETUP.md` §4 for the no-sudo path actually used |
| §18 | Prioritizing recon data ("stuff to watch for" + CVE timeline) | `scoring/prioritize.py` | ✅ — the exact CVE list from the deck is a literal lookup table |
| §19 | Recon frameworks (reNgine, reconftw, Mantis, ars0n-framework) | recon-engine itself is this category | ✅ (recon-engine *is* the framework; the named ones remain usable standalone or alongside it — see `docs/SETUP.md`) |
| §20 | Best web resource (subdomainfinder.c99.nl) | `modules/subdomain_passive.py: c99_subdomainfinder` | ✅ |
| §21 | "Recon Royale" community tool | — | 🚫 N/A — a community practice game, not a technique |
| §22.1 | Favicon analysis (FavFreak) | `modules/favicon_fingerprint.py` | ✅ (native hashing) / ⚠️ (fingerprint database must be user-supplied — see module docstring for why no hashes are hardcoded) |
| §22.2 | Report templates (Obsidian) | `templates/VULNERABILITY_REPORT_TEMPLATE.md` | ✅ |
| §22.3 | ReconFTW config | `docs/SETUP.md` | 📄 — reconftw is itself a reference framework, not a recon-engine module |
| §22.4 | New data sets (DuckDuckGo Tracker Radar, Cloudflare Radar) | `docs/SETUP.md` | 📄 — named with no further elaboration anywhere in the source material; both have real public APIs and would be straightforward follow-on modules if a concrete use case for them comes up |
| §22.5 | Open storage search (Greyhatwarfare) | `modules/open_storage.py` | ✅ |
| §23 | Cross-cutting patterns (feed-forward pipeline, noise-awareness, API-key-as-investment, cyclical recon) | `pipeline.py`, `state.py`, every module's noise-filtering caveats | ✅ (architectural, not a single file) |
| §24 | Explicitly unclear items in the source | — | 🚫 N/A — nothing to implement, by definition |

## Honest summary

Of the roughly 40 distinct named techniques/tools in the source material:
**31 are fully implemented**, **6 are partially implemented** with the
exact limitation documented in-module, and **7 are correctly identified
as non-automatable** (GUI-only business-intelligence tools, a community
game, ToS-restricted search-engine scraping, non-technical framing
content) rather than faked. See each module's own docstring for the
specific reasoning behind every ⚠️ and 📄 entry above.
