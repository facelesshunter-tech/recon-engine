"""Attack-surface prioritization (TBHM KB §18, "Prioritizing Recon Data").

Turns a list of enriched LiveHost objects (post-httpx, post-screenshotting,
post-favicon-fingerprint) into a ranked worklist, using exactly the signal
categories the deck lists under "Stuff to watch for (other)":

  Logins, Default content, 302's, Basic Auth, Old looking frameworks,
  Outdated Priv Pol / Trademark, SSL VPN and IT Portals

...plus the specific edge-device CVE class the deck highlights as the
reason SSL VPN/IT portals deserve special attention, reproduced here as a
literal lookup table (product -> CVE IDs) so a host whose tech-fingerprint
matches one of these products gets a large, explicit score bump.
"""

from __future__ import annotations

import logging
import re

from recon_engine.models import LiveHost
from recon_engine.utils.http import get_json

logger = logging.getLogger("recon_engine.scoring")

EPSS_API = "https://api.first.org/data/v1/epss"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# Exact CVE timeline from the deck's "Stuff to watch for (other)" slide.
EDGE_DEVICE_CVE_WATCHLIST: dict[str, list[str]] = {
    "citrix": ["CVE-2023-6548", "CVE-2023-6549"],
    "ivanti": ["CVE-2023-46805", "CVE-2024-21887", "CVE-2024-21893"],
    "cisco": ["CVE-2020-3259"],
    "fortinet": ["CVE-2022-42475", "CVE-2023-27997", "CVE-2024-21762"],
    "palo alto": ["CVE-2024-3400"],
    "pan-os": ["CVE-2024-3400"],
}

LOGIN_TITLE_PATTERNS = re.compile(r"\b(log ?in|sign ?in|admin|portal|vpn|console|dashboard|sso)\b", re.IGNORECASE)
DEFAULT_CONTENT_PATTERNS = re.compile(
    r"\b(welcome to nginx|apache2 ubuntu default page|iis windows server|it works!|default web site page)\b",
    re.IGNORECASE,
)
OLD_FRAMEWORK_HINTS = ("php/4", "php/5.", "asp.net 1.", "apache/1.", "apache/2.0", "iis/6", "iis/7")


def score_host(host: LiveHost) -> LiveHost:
    """Mutates and returns `host` with risk_score and risk_reasons filled
    in. Higher score = more interesting to a human reviewer first."""
    score = 0.0
    reasons: list[str] = []

    title = (host.title or "")
    tech_blob = " ".join(host.tech).lower()

    if LOGIN_TITLE_PATTERNS.search(title):
        score += 2.0
        reasons.append("login/admin/VPN/portal-style title")

    if DEFAULT_CONTENT_PATTERNS.search(title):
        score += 1.0
        reasons.append("default/unconfigured app content")

    if host.status_code in (301, 302, 307, 308):
        score += 0.5
        reasons.append(f"redirect ({host.status_code}) -- may reveal internal routing/auth flow")

    if host.status_code == 401:
        score += 1.5
        reasons.append("HTTP Basic Auth prompt")

    for hint in OLD_FRAMEWORK_HINTS:
        if hint in tech_blob:
            score += 1.0
            reasons.append(f"old-looking framework signature: {hint}")
            break

    for product, cves in EDGE_DEVICE_CVE_WATCHLIST.items():
        if product in tech_blob or product in title.lower():
            score += 5.0
            reasons.append(f"matches edge-device CVE watchlist product '{product}': {', '.join(cves)}")
            bonus, intel_reasons = _cve_intel_bonus(cves)
            score += bonus
            reasons.extend(intel_reasons)

    if host.favicon_match:
        score += 2.0
        reasons.append(f"favicon-fingerprinted as: {host.favicon_match}")

    host.risk_score = score
    host.risk_reasons = reasons
    return host


def rank(hosts: list[LiveHost]) -> list[LiveHost]:
    scored = [score_host(h) for h in hosts]
    return sorted(scored, key=lambda h: h.risk_score, reverse=True)


# ---- EPSS / CISA KEV enhancement -------------------------------------
#
# A scoped, deliberate addition (not general vulnerability-intel tooling):
# sharpens the existing edge-device CVE-watchlist scoring with two free,
# no-key public data feeds, both verified directly against their real
# APIs before being wired in here:
#
#   - EPSS (api.first.org): a 0-1 probability that a given CVE will be
#     exploited in the wild in the next 30 days -- lets the scorer
#     distinguish "technically on the watchlist" from "actively,
#     overwhelmingly likely to be exploited" (CVE-2024-3400, for
#     instance, scores ~0.9999 -- essentially certain).
#   - CISA KEV (cisa.gov): the authoritative US-government list of CVEs
#     with CONFIRMED real-world exploitation already happening. A host
#     matching a KEV-listed CVE is not a theoretical risk.
#
# Neither call happens during score_host()/rank() themselves (those stay
# fast and offline) -- call refresh_cve_intel() once per session/run to
# populate the module-level cache, then scores automatically reflect it.

_epss_cache: dict[str, float] = {}
_kev_cache: set[str] = set()
_intel_loaded = False


def refresh_cve_intel(*, timeout: int = 30) -> None:
    """Fetches current EPSS scores for the watchlist's own CVEs and the
    full CISA KEV catalog, caching both at module level. Safe to call
    multiple times; safe to not call at all (scoring still works with
    plain CVE-watchlist matching if this is skipped or the network calls
    fail -- matches every other module's graceful-degradation pattern)."""
    global _intel_loaded
    all_cves = sorted({cve for cves in EDGE_DEVICE_CVE_WATCHLIST.values() for cve in cves})

    epss_data = get_json(EPSS_API, params={"cve": ",".join(all_cves)}, timeout=timeout)
    if epss_data:
        for entry in epss_data.get("data", []):
            cve = entry.get("cve")
            try:
                score = float(entry.get("epss", 0))
            except (TypeError, ValueError):
                continue
            if cve:
                _epss_cache[cve] = score
    else:
        logger.warning("EPSS fetch failed -- scoring will proceed without EPSS enhancement")

    kev_data = get_json(CISA_KEV_URL, timeout=timeout)
    if kev_data:
        for vuln in kev_data.get("vulnerabilities", []):
            cve_id = vuln.get("cveID")
            if cve_id:
                _kev_cache.add(cve_id)
    else:
        logger.warning("CISA KEV fetch failed -- scoring will proceed without KEV enhancement")

    _intel_loaded = True


def _cve_intel_bonus(cves: list[str]) -> tuple[float, list[str]]:
    """For every edge-device-watchlist match, returns extra score and
    specific reasons per CVE that EPSS/KEV data makes look more urgent,
    on top of the flat +5.0 the product match itself already earns.
    Returns (0.0, []) if refresh_cve_intel() was never called -- plain
    CVE-watchlist matching still works without this enhancement."""
    if not _intel_loaded:
        return 0.0, []
    bonus = 0.0
    reasons: list[str] = []
    for cve in cves:
        if cve in _kev_cache:
            bonus += 3.0
            reasons.append(f"{cve} is on CISA's Known Exploited Vulnerabilities list -- confirmed real-world exploitation")
        epss = _epss_cache.get(cve)
        if epss is not None and epss >= 0.5:
            bonus += 2.0
            reasons.append(f"{cve} has an EPSS exploitation-probability score of {epss:.2f} (>=0.5)")
    return bonus, reasons
