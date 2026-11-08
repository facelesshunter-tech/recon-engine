"""Permutation / alteration scanning (TBHM KB §15).

Generates structural variants of already-known subdomains (dev1/dev2,
dev-1/dev-2, dev.1/dev.2 patterns) that a flat wordlist brute-force can't
find, then resolves them -- exactly the pipeline the deck shows:
`cat subdomains.txt | dnsgen - | puredns resolve --resolvers resolvers.txt`.

Both dnsgen and the newer alterx (Project Discovery) are supported;
dnsgen is tried first since it's the tool actually demonstrated live in
the deck, with alterx as the named alternative.
"""

from __future__ import annotations

import logging
from pathlib import Path

from recon_engine.config import Config
from recon_engine.utils.subprocess_runner import run
from recon_engine.utils.dedupe import dedupe_strings
from recon_engine.modules.subdomain_bruteforce import resolve as puredns_resolve

logger = logging.getLogger("recon_engine.permutation")


def generate_dnsgen(config: Config, known_subdomains: list[str]) -> list[str]:
    path = config.tool_path("dnsgen")
    if not path:
        logger.warning("dnsgen not found on PATH -- install with: pip install dnsgen")
        return []
    result = run([path, "-"], stdin_text="\n".join(known_subdomains), timeout=300)
    return dedupe_strings(result.stdout.splitlines())


def generate_alterx(config: Config, known_subdomains: list[str]) -> list[str]:
    path = config.tool_path("alterx")
    if not path:
        logger.warning("alterx not found on PATH -- install from github.com/projectdiscovery/alterx")
        return []
    result = run([path, "-silent"], stdin_text="\n".join(known_subdomains), timeout=300)
    return dedupe_strings(result.stdout.splitlines())


def permute_and_resolve(
    config: Config,
    known_subdomains: list[str],
    resolvers: Path,
    *,
    engine: str = "dnsgen",
) -> list[str]:
    """Generates candidate permutations with the chosen engine, then
    resolves them with puredns -- dnsgen on its own only generates names,
    it does NOT resolve them (an explicit caveat in the deck)."""
    if engine == "alterx":
        candidates = generate_alterx(config, known_subdomains)
    else:
        candidates = generate_dnsgen(config, known_subdomains)
    if not candidates:
        return []
    return puredns_resolve(config, candidates, resolvers)
