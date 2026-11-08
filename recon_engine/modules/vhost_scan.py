"""VHost (virtual host) scanning (TBHM KB §16).

A single IP can silently answer for hostnames that were never surfaced by
DNS/subdomain enumeration, distinguished only by the HTTP Host header. The
deck names VHostScan (codingo/VHostScan) by name and demonstrates it
finding the real vhost among several identically-responding decoys on a
bank.htb target.
"""

from __future__ import annotations

import logging

from recon_engine.config import Config
from recon_engine.utils.subprocess_runner import run

logger = logging.getLogger("recon_engine.vhost_scan")


def scan(
    config: Config,
    target_ip: str,
    wordlist: str | None = None,
    *,
    base_host: str | None = None,
    timeout: int = 1800,
) -> str:
    """Runs VHostScan against a target IP. `base_host` lets VHostScan
    detect catch-all/wildcard responses by comparing against a known-good
    baseline vhost, exactly as the deck's bank.htb example does implicitly
    (it correctly separated the real vhost from decoys with identical
    content hashes)."""
    path = config.tool_path("VHostScan")
    if not path:
        logger.warning("VHostScan not found on PATH -- install with: pip install VHostScan")
        return ""
    argv = [path, "-t", target_ip]
    if wordlist:
        argv += ["-w", wordlist]
    if base_host:
        argv += ["-b", base_host]
    result = run(argv, timeout=timeout)
    if not result.ok and not result.stdout:
        logger.warning("VHostScan exited %s: %s", result.returncode, result.stderr.strip()[:300])
    return result.stdout
