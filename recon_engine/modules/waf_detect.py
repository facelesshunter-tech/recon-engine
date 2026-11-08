"""WAF fingerprinting (wafw00f).

Knowing a target's behind a WAF changes the whole downstream approach --
flagged earlier as a real, confirmed gap in the original TBHM-derived
toolset (TBHM itself never covers WAF detection, despite reconftw listing
wafw00f as one of its own dependencies). Feeds reporting/architecture.py's
per-host breakdown alongside tls_probe.py and httpx's tech-detect.

Note on technique: wafw00f works by sending a small number of requests
containing deliberately WAF-triggering patterns (XSS/SQLi/path-traversal-
shaped query strings) and observing how each host responds -- this is how
WAF fingerprinting inherently works, not something unusual added here.
Same authorized-targets-only scope as every other live-traffic module in
this project applies.
"""

from __future__ import annotations

import json
import logging
import tempfile
from dataclasses import dataclass
from pathlib import Path

from recon_engine.config import Config
from recon_engine.utils.subprocess_runner import run

logger = logging.getLogger("recon_engine.waf_detect")


@dataclass
class WAFResult:
    url: str
    detected: bool = False
    firewall: str = ""
    manufacturer: str = ""


def detect(config: Config, urls: list[str], *, timeout: int = 600) -> dict[str, WAFResult]:
    path = config.tool_path("wafw00f")
    if not path:
        logger.warning("wafw00f not found on PATH -- install with: pip install wafw00f")
        return {}
    if not urls:
        return {}

    # wafw00f's -i flag is a real file reader, not a stdin-capable "-" --
    # verified directly (it fails with "File - could not be read" otherwise)
    # -- so targets have to go through an actual temp file.
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tmp:
        tmp.write("\n".join(urls))
        in_path = Path(tmp.name)
    out_path = in_path.with_suffix(".out.json")

    argv = [path, "-i", str(in_path), "-o", str(out_path), "-f", "json"]
    result = run(argv, timeout=timeout)

    out: dict[str, WAFResult] = {}
    in_path.unlink(missing_ok=True)
    if not out_path.is_file() or out_path.stat().st_size == 0:
        if not result.ok:
            logger.warning("wafw00f exited %s: %s", result.returncode, result.stderr.strip()[:300])
        out_path.unlink(missing_ok=True)
        return {}

    try:
        records = json.loads(out_path.read_text())
    except json.JSONDecodeError:
        logger.warning("wafw00f produced unparseable JSON output")
        out_path.unlink(missing_ok=True)
        return {}
    out_path.unlink(missing_ok=True)

    for record in records:
        url = record.get("url", "")
        if not url:
            continue
        out[url] = WAFResult(
            url=url,
            detected=record.get("detected", False),
            firewall=record.get("firewall", "") or "",
            manufacturer=record.get("manufacturer", "") or "",
        )
    return out
