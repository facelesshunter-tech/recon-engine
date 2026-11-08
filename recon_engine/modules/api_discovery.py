"""API route/endpoint brute-forcing (Kiterunner).

Kiterunner is built specifically around Assetnote's hosted, continuously-
updated API-route wordlists (`-A apiroutes-210228`, the tool's own
documented default) rather than plain wordlist files -- its `-w` flag
requires the compiled `.kite` protobuf format, NOT a flat text wordlist
(verified directly: pointing it at a plain text file fails with a
protobuf decode error). Building a valid local kitebuilder JSON schema by
hand was not attempted here with confidence -- see the honesty note
below.

IMPORTANT automation-safety finding, verified directly: without
`--kitebuilder-full-scan`, kr's default two-phase scan behavior asks an
interactive `[y/n]` terminal prompt ("Continue Scanning with full
wordlist?") when its first phase finds nothing -- which would hang a
subprocess call indefinitely with no TTY to answer it. This module
always passes `--kitebuilder-full-scan` for exactly that reason.

Honesty note on verification: this module's info/status JSON line
parsing was confirmed against real kr output. Its per-route HIT record
parsing (the fields below a discovered endpoint would actually contain)
was NOT independently confirmed against a real positive match in this
environment -- `wordlist.assetnote.io` was unreachable (DNS failure) from
the sandbox this was built in, and a hand-built local test schema
produced zero loaded routes rather than a genuine hit to observe. The
field names used below (method/url/status_code/content_length) follow
Kiterunner's publicly documented output convention and the same shape
every other live-probe module in this project uses, but should be
treated as the best-available inference, not a confirmed-correct parse,
until verified against a real scan with network access to Assetnote's
wordlist server.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass

from recon_engine.config import Config
from recon_engine.utils.subprocess_runner import run

logger = logging.getLogger("recon_engine.api_discovery")

DEFAULT_WORDLIST = "apiroutes-210228"


@dataclass
class APIRouteHit:
    method: str
    url: str
    status_code: int | None = None
    content_length: int | None = None


def scan(
    config: Config,
    target: str,
    *,
    wordlist: str = DEFAULT_WORDLIST,
    max_wordlist_lines: int | None = 20000,
    custom_kite_file: str | None = None,
    timeout: int = 1800,
) -> list[APIRouteHit]:
    """Scans one host for API routes. Pass `custom_kite_file` (a path to
    an already-compiled .kite file) to use a local wordlist instead of
    Assetnote's hosted one -- useful if you're in a network-restricted
    environment, same as this module was built in."""
    path = config.tool_path("kr") or config.tool_path("kiterunner")
    if not path:
        logger.warning(
            "kiterunner (kr) not found on PATH -- download a release binary from "
            "github.com/assetnote/kiterunner (no clean `go install` path -- "
            "it ships prebuilt releases instead)"
        )
        return []

    argv = [path, "scan", target, "-o", "json", "-q", "--kitebuilder-full-scan"]
    if custom_kite_file:
        argv += ["-w", custom_kite_file]
    else:
        wl_spec = f"{wordlist};{max_wordlist_lines}" if max_wordlist_lines else wordlist
        argv += ["-A", wl_spec]

    result = run(argv, timeout=timeout)
    hits: list[APIRouteHit] = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        # Skip the info/status lines (confirmed shape: has "level" and
        # "message" keys, no "url") -- only keep what look like actual
        # per-route hit records.
        if "url" not in record:
            continue
        hits.append(
            APIRouteHit(
                method=record.get("method", ""),
                url=record.get("url", ""),
                status_code=record.get("status_code"),
                content_length=record.get("content_length"),
            )
        )
    if not result.ok and not hits:
        logger.warning("kiterunner exited %s: %s", result.returncode, result.stderr.strip()[:300])
    return hits
