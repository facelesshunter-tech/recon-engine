"""Passive subdomain scraping (TBHM KB §12) -- "by far the biggest
contributor to your subdomain enumeration" per the deck.

Orchestrates the two tools TBHM names as best-in-class (Subfinder, Amass)
plus BBOT, concatenates + dedupes their output exactly the way the deck
demonstrates (`sort -u` after combining tool outputs), and also implements
crt.sh certificate-transparency lookup natively (see cert_pivot.py) as a
zero-dependency passive source that works with no external binary and no
API key at all -- a reasonable floor of functionality for a fresh install.
"""

from __future__ import annotations

import logging

from recon_engine.config import Config
from recon_engine.utils.subprocess_runner import run
from recon_engine.utils.dedupe import dedupe_strings
from recon_engine.modules.cert_pivot import crtsh_lookup

logger = logging.getLogger("recon_engine.subdomain_passive")


def run_subfinder(config: Config, domain: str, *, all_sources: bool = True, timeout: int = 300) -> list[str]:
    """TBHM's documented pro tip: use `-all` to enable every configured
    source, not just the fast default set."""
    path = config.tool_path("subfinder")
    if not path:
        logger.warning("subfinder not found on PATH -- install from github.com/projectdiscovery/subfinder")
        return []
    argv = [path, "-silent", "-d", domain]
    if all_sources:
        argv.append("-all")
    result = run(argv, timeout=timeout)
    if not result.ok and not result.stdout:
        logger.warning("subfinder exited %s: %s", result.returncode, result.stderr.strip()[:300])
    return dedupe_strings(result.stdout.splitlines())


def run_amass(config: Config, domain: str, *, timeout: int = 600, passive: bool = True) -> list[str]:
    path = config.tool_path("amass")
    if not path:
        logger.warning("amass not found on PATH -- install from github.com/owasp-amass/amass")
        return []
    argv = [path, "enum", "-d", domain, "-silent"]
    if passive:
        argv.append("-passive")
    result = run(argv, timeout=timeout)
    if not result.ok and not result.stdout:
        logger.warning("amass exited %s: %s", result.returncode, result.stderr.strip()[:300])
    return dedupe_strings(result.stdout.splitlines())


def run_bbot(config: Config, domain: str, *, modules: str = "subdomain-enum", timeout: int = 900) -> list[str]:
    """BBOT -- newer tool that wraps multiple other sources. TBHM's own
    example output-cleanup one-liner is reproduced here:
    `grep -F '[DNS_NAME]' output.txt | awk '{print $2}'`."""
    path = config.tool_path("bbot")
    if not path:
        logger.warning("bbot not found on PATH -- install with: pipx install bbot")
        return []
    argv = [path, "-t", domain, "-f", modules, "-silent"]
    result = run(argv, timeout=timeout)
    hits = []
    for line in result.stdout.splitlines():
        if "[DNS_NAME]" in line:
            parts = line.split()
            if len(parts) >= 2:
                hits.append(parts[1])
    return dedupe_strings(hits)


def run_assetfinder(config: Config, domain: str, *, timeout: int = 180) -> list[str]:
    """tomnomnom's assetfinder -- a fourth passive source alongside
    Subfinder/Amass/BBOT. Added by explicit request despite meaningfully
    overlapping with Subfinder/Amass's own source lists: the pipeline's
    dedupe_assets() step means running it costs you nothing but a little
    extra runtime -- any subdomain it finds that the others also found
    collapses into one entry with both sources recorded (feeds the
    source-reliability scorecard); anything it finds that the others
    didn't is pure upside. `-subs-only` restricts output to actual
    subdomains of the target rather than also returning the root domain
    itself and unrelated lookalikes."""
    path = config.tool_path("assetfinder")
    if not path:
        logger.warning("assetfinder not found on PATH -- install with: go install github.com/tomnomnom/assetfinder@latest")
        return []
    argv = [path, "--subs-only", domain]
    result = run(argv, timeout=timeout)
    if not result.ok and not result.stdout:
        logger.warning("assetfinder exited %s: %s", result.returncode, result.stderr.strip()[:300])
    return dedupe_strings(result.stdout.splitlines())


def c99_subdomainfinder(config: Config, domain: str) -> list[str]:
    """TBHM KB §20: subdomainfinder.c99.nl called out as "Best Web
    Resource" for one-stop subdomain discovery. Uses c99.nl's documented
    API endpoint rather than scraping the web GUI."""
    import requests as _requests  # local import: keep module importable without requests at module load time

    key = config.api_key("c99")
    if not key:
        logger.warning("no c99 API key configured (config.api_keys.c99) -- c99 subdomainfinder skipped")
        return []
    try:
        resp = _requests.get(
            "https://api.c99.nl/subdomainfinder",
            params={"key": key, "domain": domain, "json": "true"},
            timeout=60,
        )
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        logger.warning("c99 subdomainfinder request failed: %s", e)
        return []
    subs = data.get("subdomains", []) if isinstance(data, dict) else []
    return dedupe_strings(s.get("subdomain", "") for s in subs if isinstance(s, dict))


def google_exclusion_dork(domain: str, exclude: list[str] | None = None) -> str:
    """TBHM KB §12.2: the manual iterative `site:domain -www -watch -dev...`
    technique for surfacing subdomains Google has indexed but your other
    sources haven't. This returns the dork QUERY STRING only (not a
    scraper) -- mass-querying Google programmatically violates its terms
    of service and gets IPs blocked, which TBHM itself works around
    manually rather than automating. Paste the result into a browser."""
    exclude = exclude or []
    parts = [f"site:{domain}"] + [f"-{e}" for e in exclude]
    return " ".join(parts)


def passive_enumerate(
    config: Config,
    domain: str,
    *,
    use_subfinder: bool = True,
    use_amass: bool = True,
    use_bbot: bool = False,
    use_crtsh: bool = True,
    use_c99: bool = False,
    use_assetfinder: bool = True,
) -> dict[str, list[str]]:
    """Run every available passive source and return per-source results
    (not pre-merged) so the pipeline's dedupe step can track which
    technique(s) found each subdomain -- feeds the source-reliability
    scorecard idea."""
    out: dict[str, list[str]] = {}
    if use_subfinder:
        out["subfinder"] = run_subfinder(config, domain)
    if use_amass:
        out["amass"] = run_amass(config, domain)
    if use_bbot:
        out["bbot"] = run_bbot(config, domain)
    if use_crtsh:
        try:
            out["crtsh"] = crtsh_lookup(domain)
        except Exception as e:
            logger.warning("crt.sh lookup failed: %s", e)
            out["crtsh"] = []
    if use_c99:
        out["c99"] = c99_subdomainfinder(config, domain)
    if use_assetfinder:
        out["assetfinder"] = run_assetfinder(config, domain)
    return out
