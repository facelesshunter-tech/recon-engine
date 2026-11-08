"""Screenshotting for recon triage (TBHM KB §17).

The deck names several tools and explicitly says "this whole section is
very much user preference" -- no single canonical tool. This module
supports the two newer/faster ones named (go-stare, gowitness-via-docker)
plus EyeWitness specifically because TBHM calls out its default-credential
-checker as a still-unmatched feature worth using it for even though it's
the oldest tool in the list.
"""

from __future__ import annotations

import logging
from pathlib import Path

from recon_engine.config import Config
from recon_engine.utils.subprocess_runner import run

logger = logging.getLogger("recon_engine.screenshotting")


def go_stare(config: Config, hosts: list[str], output_dir: Path, *, timeout: int = 1800) -> Path:
    path = config.tool_path("go-stare")
    if not path:
        logger.warning("go-stare not found on PATH -- install from github.com/dwisiswant0/go-stare")
        return output_dir
    output_dir.mkdir(parents=True, exist_ok=True)
    run([path, "-o", str(output_dir)], stdin_text="\n".join(hosts), timeout=timeout)
    return output_dir


def gowitness_docker(config: Config, httpx_output_file: Path, data_dir: Path, *, threads: int = 5, timeout: int = 1800) -> None:
    """Matches the deck's exact docker invocation:
    `docker run --rm -v $(pwd):/data leonjza/gowitness gowitness file httpxOutput --threads 5`."""
    docker_path = config.tool_path("docker")
    if not docker_path:
        logger.warning("docker not found on PATH -- gowitness-via-docker skipped")
        return
    data_dir.mkdir(parents=True, exist_ok=True)
    argv = [
        docker_path,
        "run",
        "--rm",
        "-v",
        f"{data_dir}:/data",
        "leonjza/gowitness",
        "gowitness",
        "file",
        f"/data/{httpx_output_file.name}",
        "--threads",
        str(threads),
    ]
    result = run(argv, timeout=timeout)
    if not result.ok:
        logger.warning("gowitness docker run failed: %s", result.stderr.strip()[:300])


def eyewitness(config: Config, hosts_file: Path, output_dir: Path, *, timeout: int = 1800) -> Path:
    """Run for its default-credential-checker, per TBHM's explicit
    preference, not for raw screenshot speed."""
    path = config.tool_path("eyewitness") or config.tool_path("EyeWitness")
    if not path:
        logger.warning("EyeWitness not found on PATH -- install from github.com/RedSiege/EyeWitness")
        return output_dir
    output_dir.mkdir(parents=True, exist_ok=True)
    argv = [path, "-f", str(hosts_file), "-d", str(output_dir), "--no-prompt"]
    run(argv, timeout=timeout)
    return output_dir
