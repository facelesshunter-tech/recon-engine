"""Active subdomain brute-forcing (TBHM KB §14).

Wraps puredns (the tool TBHM says it personally uses -- "a wrapper and
feature enhancer to massdns") rather than massdns directly, matching the
deck's own stated preference and exact invocation shape:
`puredns bruteforce <wordlist> <domain> -r resolvers.txt`.
"""

from __future__ import annotations

import logging
from pathlib import Path

from recon_engine.config import Config
from recon_engine.utils.subprocess_runner import run
from recon_engine.utils.dedupe import dedupe_strings

logger = logging.getLogger("recon_engine.subdomain_bruteforce")

# trickest/resolvers is the fresh-resolver-list source TBHM names explicitly,
# specifically recommending resolvers-trusted.txt for re-validating results
# obtained against the (noisier) public resolver list.
TRICKEST_RESOLVERS_URL = "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt"
TRICKEST_RESOLVERS_TRUSTED_URL = "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt"


def fetch_resolvers(dest: Path, *, trusted: bool = False) -> Path:
    import requests

    url = TRICKEST_RESOLVERS_TRUSTED_URL if trusted else TRICKEST_RESOLVERS_URL
    resp = requests.get(url, timeout=30)
    resp.raise_for_status()
    dest.write_text(resp.text)
    return dest


def bruteforce(
    config: Config,
    domain: str,
    wordlist: Path,
    resolvers: Path,
    *,
    timeout: int = 1800,
) -> list[str]:
    path = config.tool_path("puredns")
    if not path:
        logger.warning("puredns not found on PATH -- install from github.com/d3mondev/puredns")
        return []
    argv = [path, "bruteforce", str(wordlist), domain, "-r", str(resolvers), "-q"]
    result = run(argv, timeout=timeout)
    if not result.ok and not result.stdout:
        logger.warning("puredns exited %s: %s", result.returncode, result.stderr.strip()[:300])
    return dedupe_strings(result.stdout.splitlines())


def resolve(
    config: Config,
    candidates: list[str],
    resolvers: Path,
    *,
    timeout: int = 1800,
) -> list[str]:
    """`puredns resolve` -- used by the permutation module to validate
    dnsgen/alterx-generated candidate names, matching TBHM's exact pipeline:
    `cat subdomains.txt | dnsgen - | puredns resolve --resolvers resolvers.txt`."""
    path = config.tool_path("puredns")
    if not path:
        logger.warning("puredns not found on PATH -- install from github.com/d3mondev/puredns")
        return []
    argv = [path, "resolve", "--resolvers", str(resolvers), "-q"]
    result = run(argv, stdin_text="\n".join(candidates), timeout=timeout)
    return dedupe_strings(result.stdout.splitlines())
