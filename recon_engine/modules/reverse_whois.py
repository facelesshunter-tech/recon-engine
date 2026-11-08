"""Reverse WHOIS (TBHM KB §5).

Find other apex domains owned by the same registrant org/email -- directly
widens scope the way the deck's twitch.tv/Justin.tv historical-ownership
example demonstrates.

Implements the whoxy.com API exactly as shown in the deck
(`api.whoxy.com/?key=...&reverse=whois&email=...`), with graceful
degradation when no key is configured (whoxy is a paid service -- TBHM
itself prices it at ~$10/1000 queries).
"""

from __future__ import annotations

import logging

from recon_engine.config import Config
from recon_engine.utils.http import get_json

logger = logging.getLogger("recon_engine.reverse_whois")

WHOXY_BASE = "http://api.whoxy.com/"


def reverse_whois_by_email(config: Config, email: str) -> list[str]:
    return _reverse_whois(config, "email", email)


def reverse_whois_by_company(config: Config, company: str) -> list[str]:
    return _reverse_whois(config, "company", company)


def reverse_whois_by_keyword(config: Config, keyword: str) -> list[str]:
    return _reverse_whois(config, "keyword", keyword)


def _reverse_whois(config: Config, field: str, value: str) -> list[str]:
    key = config.api_key("whoxy")
    if not key:
        logger.warning(
            "no whoxy API key configured (config.api_keys.whoxy) -- "
            "reverse WHOIS skipped. See config/config.example.yaml."
        )
        return []
    params = {"key": key, "reverse": "whois", field: value}
    data = get_json(WHOXY_BASE, params=params, timeout=60)
    if not data:
        return []
    domains = []
    for entry in data.get("search_result", []):
        d = entry.get("domain_name")
        if d:
            domains.append(d)
    return domains


def historical_whois(config: Config, domain: str) -> list[dict]:
    """TBHM's 'Historical WHOIS' example (twitch.tv's ownership trail from
    WhoisGuard -> Justin.tv -> Twitch Interactive) -- surfaces ownership
    changes that hint at past acquisitions/rebrands."""
    key = config.api_key("whoxy")
    if not key:
        logger.warning("no whoxy API key configured -- historical WHOIS skipped")
        return []
    data = get_json(WHOXY_BASE, params={"key": key, "history": "1", "domain": domain}, timeout=60)
    if not data:
        return []
    return data.get("whois_records", [])
