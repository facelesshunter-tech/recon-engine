"""Shared HTTP client helper for the API-based modules (reverse WHOIS, DMARC
pivot, reverse DNS via shared-nameserver, reverse IP, acquisitions, etc.).

Centralizing this gives every API-based module consistent timeouts, a
descriptive User-Agent (good citizenship for third-party free-tier APIs),
and one place to add retry/backoff later.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

import requests

logger = logging.getLogger("recon_engine.http")

USER_AGENT = "recon-engine/0.1 (+https://github.com/facelesshunter-tech/recon-engine)"


def get_json(
    url: str,
    *,
    params: Optional[dict[str, Any]] = None,
    headers: Optional[dict[str, str]] = None,
    timeout: int = 30,
) -> Optional[dict[str, Any]]:
    hdrs = {"User-Agent": USER_AGENT}
    if headers:
        hdrs.update(headers)
    try:
        resp = requests.get(url, params=params, headers=hdrs, timeout=timeout)
    except requests.RequestException as e:
        logger.warning("request to %s failed: %s", url, e)
        return None
    if resp.status_code != 200:
        logger.warning("request to %s returned HTTP %s", url, resp.status_code)
        return None
    try:
        return resp.json()
    except ValueError:
        logger.warning("request to %s did not return JSON", url)
        return None


def post_json(
    url: str,
    *,
    json_body: Optional[dict[str, Any]] = None,
    headers: Optional[dict[str, str]] = None,
    timeout: int = 30,
) -> Optional[dict[str, Any]]:
    hdrs = {"User-Agent": USER_AGENT, "Content-Type": "application/json"}
    if headers:
        hdrs.update(headers)
    try:
        resp = requests.post(url, json=json_body, headers=hdrs, timeout=timeout)
    except requests.RequestException as e:
        logger.warning("request to %s failed: %s", url, e)
        return None
    if resp.status_code != 200:
        logger.warning("request to %s returned HTTP %s", url, resp.status_code)
        return None
    try:
        return resp.json()
    except ValueError:
        return None
