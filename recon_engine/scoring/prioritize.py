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

import re

from recon_engine.models import LiveHost

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

    if host.favicon_match:
        score += 2.0
        reasons.append(f"favicon-fingerprinted as: {host.favicon_match}")

    host.risk_score = score
    host.risk_reasons = reasons
    return host


def rank(hosts: list[LiveHost]) -> list[LiveHost]:
    scored = [score_host(h) for h in hosts]
    return sorted(scored, key=lambda h: h.risk_score, reverse=True)
