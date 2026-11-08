"""Reverse IP / virtual-host co-hosting lookup (TBHM KB §7).

"Rev IP/Domain to: Virtual Hosts, Backlinks, Redirects, and more" -- the
host.io API, exactly as demonstrated against bmw.com in the deck (co-hosted
domains sharing an IP/ASN, inbound backlinks, and domains that redirect to
the target).
"""

from __future__ import annotations

import logging

from recon_engine.config import Config
from recon_engine.utils.http import get_json
from recon_engine.utils.dedupe import dedupe_strings

logger = logging.getLogger("recon_engine.reverse_ip")

HOSTIO_BASE = "https://host.io/api"


def _request(config: Config, path: str, params: dict | None = None) -> dict | None:
    token = config.api_key("hostio")
    if not token:
        logger.warning("no host.io API token configured (config.api_keys.hostio) -- reverse IP lookup skipped")
        return None
    p = dict(params or {})
    p["token"] = token
    return get_json(f"{HOSTIO_BASE}/{path}", params=p, timeout=30)


def domain_summary(config: Config, domain: str) -> dict:
    """URL, IP, ASN, country, server header, DNS records for a domain --
    the base lookup everything else pivots from."""
    data = _request(config, f"full/{domain}")
    return data or {}


def co_hosted_domains(config: Config, domain: str) -> list[str]:
    """Other domains sharing the same IP (same ASN/virtual-hosting
    neighborhood) -- the bmw.com -> bmw.de/bmw.co.uk/bmw.fr example."""
    summary = domain_summary(config, domain)
    web = summary.get("web", {})
    ip = web.get("ip")
    if not ip:
        return []
    data = _request(config, f"domains/ip/{ip}")
    if not data:
        return []
    return dedupe_strings(d.get("domain", "") for d in data.get("domains", []))


def backlinks(config: Config, domain: str) -> list[str]:
    """Domains that link to the target -- OSINT/phishing-infrastructure
    value, and occasionally reveals partner/subsidiary sites."""
    data = _request(config, f"domains/link/{domain}")
    if not data:
        return []
    return dedupe_strings(d.get("domain", "") for d in data.get("domains", []))


def redirects_to(config: Config, domain: str) -> list[str]:
    """Domains that redirect to the target -- often brand-protection
    registrations (bmw.social, bmw.careers, etc. in the deck's example),
    each itself a legitimate, in-scope-adjacent apex domain."""
    data = _request(config, f"domains/redirect/{domain}")
    if not data:
        return []
    return dedupe_strings(d.get("domain", "") for d in data.get("domains", []))
