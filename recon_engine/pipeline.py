"""The orchestrator that ties every module together into the single,
"feed results forward" pipeline TBHM describes throughout the deck:
discovery -> dedupe -> liveness/tech-detect -> screenshot/fingerprint ->
score -> report, with every asset ever seen persisted so later runs can
report what's new (the "recon is a cycle" / continuous-monitoring idea).

This is intentionally a straight-line pipeline, not an unbounded
auto-recursive one: TBHM's "recon is a cycle" framing (new apex domains
found via acquisitions/GitHub/AI should trigger re-running earlier
stages against them) is realized here as "run recon-engine again with
the new apex domain as the target," using the AssetStore's new-asset
tracking to tell you when that's worth doing -- not as automatic
unbounded recursion within a single run, which would have no natural
stopping point and could silently balloon scope far beyond what was
authorized for a given target.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from pathlib import Path

from recon_engine.config import Config
from recon_engine.models import Asset, AssetType, LiveHost, Source
from recon_engine.state import AssetStore
from recon_engine.utils.dedupe import dedupe_assets
from recon_engine.modules import (
    subdomain_passive,
    subdomain_bruteforce,
    permutation,
    github_recon,
    live_validation,
    screenshotting,
    favicon_fingerprint,
)
from recon_engine.scoring.prioritize import rank
from recon_engine.reporting import export

logger = logging.getLogger("recon_engine.pipeline")


@dataclass
class PipelineOptions:
    use_subfinder: bool = True
    use_amass: bool = True
    use_bbot: bool = False
    use_crtsh: bool = True
    use_github: bool = False
    use_bruteforce: bool = False
    use_permutation: bool = False
    use_screenshots: bool = False
    use_favicon: bool = False
    wordlist: Path | None = None
    resolvers: Path | None = None
    favicon_db: Path | None = None
    output_dir: Path = field(default_factory=lambda: Path("./recon-output"))


class Pipeline:
    def __init__(self, config: Config, options: PipelineOptions | None = None):
        self.config = config
        self.options = options or PipelineOptions()
        db_path = self.options.output_dir / "assets.db"
        self.store = AssetStore(db_path)

    def run(self, target: str) -> dict:
        logger.info("starting recon pipeline for %s", target)
        scan_start = time.time()
        scan_id = self.store.start_scan(target)
        stages_run: list[str] = []

        subdomains: list[Asset] = []

        # --- passive subdomain enumeration --------------------------------
        passive_results = subdomain_passive.passive_enumerate(
            self.config,
            target,
            use_subfinder=self.options.use_subfinder,
            use_amass=self.options.use_amass,
            use_bbot=self.options.use_bbot,
            use_crtsh=self.options.use_crtsh,
        )
        for source_name, values in passive_results.items():
            stages_run.append(f"subdomain_passive:{source_name}")
            source = Source.SUBDOMAIN_PASSIVE
            for v in values:
                subdomains.append(Asset(value=v, asset_type=AssetType.SUBDOMAIN, source=source, target=target))

        # --- GitHub recon --------------------------------------------------
        if self.options.use_github:
            stages_run.append("github_recon")
            for v in github_recon.github_subdomains(self.config, target):
                subdomains.append(
                    Asset(value=v, asset_type=AssetType.SUBDOMAIN, source=Source.GITHUB_RECON, target=target)
                )

        # --- dedupe known subdomains before spending bruteforce/permutation
        # budget on them again --------------------------------------------
        subdomains = dedupe_assets(subdomains)
        known_values = [a.value for a in subdomains] or [target]

        # --- active bruteforce ----------------------------------------------
        if self.options.use_bruteforce and self.options.wordlist and self.options.resolvers:
            stages_run.append("subdomain_bruteforce")
            for v in subdomain_bruteforce.bruteforce(
                self.config, target, self.options.wordlist, self.options.resolvers
            ):
                subdomains.append(
                    Asset(value=v, asset_type=AssetType.SUBDOMAIN, source=Source.SUBDOMAIN_BRUTEFORCE, target=target)
                )

        # --- permutation/alteration -----------------------------------------
        if self.options.use_permutation and self.options.resolvers:
            stages_run.append("permutation")
            for v in permutation.permute_and_resolve(self.config, known_values, self.options.resolvers):
                subdomains.append(
                    Asset(value=v, asset_type=AssetType.SUBDOMAIN, source=Source.PERMUTATION, target=target)
                )

        subdomains = dedupe_assets(subdomains)
        new_assets = self.store.upsert_many(subdomains)
        logger.info(
            "%d total subdomains known for %s (%d new this run)", len(subdomains), target, len(new_assets)
        )

        # --- live validation / tech fingerprinting --------------------------
        stages_run.append("live_validation")
        all_hosts = [a.value for a in subdomains] or [target]
        live_hosts: list[LiveHost] = live_validation.probe(self.config, all_hosts)

        # --- favicon fingerprinting ------------------------------------------
        if self.options.use_favicon and self.options.favicon_db:
            stages_run.append("favicon_fingerprint")
            url_hashes = {}
            for h in live_hosts:
                hv = favicon_fingerprint.compute_hash(h.url)
                if hv is not None:
                    h.favicon_hash = str(hv)
                    url_hashes[h.url] = hv
            matches = favicon_fingerprint.match_against_database(url_hashes, self.options.favicon_db)
            for h in live_hosts:
                if h.url in matches:
                    h.favicon_match = matches[h.url]

        # --- screenshotting ----------------------------------------------------
        if self.options.use_screenshots:
            stages_run.append("screenshotting")
            screenshot_dir = self.options.output_dir / "screenshots" / target
            screenshotting.go_stare(self.config, all_hosts, screenshot_dir)

        # --- scoring / prioritization ---------------------------------------
        stages_run.append("scoring")
        ranked_hosts = rank(live_hosts)

        # --- export ----------------------------------------------------------
        stages_run.append("export")
        json_path = export.export_json(
            target, new_assets_as_dicts(new_assets), ranked_hosts, self.options.output_dir / f"{target}.json"
        )
        md_path = export.export_markdown(
            target, new_assets_as_dicts(new_assets), ranked_hosts, self.options.output_dir / f"{target}.md"
        )

        self.store.finish_scan(scan_id, stages_run)
        elapsed = time.time() - scan_start
        logger.info("pipeline finished for %s in %.1fs -- stages: %s", target, elapsed, ", ".join(stages_run))

        return {
            "target": target,
            "elapsed_seconds": elapsed,
            "stages_run": stages_run,
            "total_subdomains": len(subdomains),
            "new_assets": len(new_assets),
            "live_hosts": len(live_hosts),
            "json_report": str(json_path),
            "markdown_report": str(md_path),
        }

    def change_report(self, target: str, since_epoch: float) -> list[dict]:
        """The 'attack-surface growth tracker' capability: what's appeared
        for this target since an arbitrary past timestamp (e.g. the start
        of the last scan), independent of running a new scan."""
        return self.store.new_since(target, since_epoch)

    def source_reliability(self, target: str | None = None) -> dict[str, int]:
        """The 'recon-source reliability scorecard' capability."""
        return self.store.source_reliability(target)

    def close(self) -> None:
        self.store.close()


def new_assets_as_dicts(assets: list[Asset]) -> list[dict]:
    return [
        {"value": a.value, "asset_type": a.asset_type.value, "sources": a.metadata.get("also_found_by", [a.source.value])}
        for a in assets
    ]
