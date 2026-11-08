"""recon-engine CLI.

    recon-engine scan example.com
    recon-engine scan example.com --github --bruteforce --wordlist words.txt --resolvers resolvers.txt
    recon-engine changes example.com --since-hours 24
    recon-engine sources --target example.com
    recon-engine config-check
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

import click

from recon_engine.config import Config
from recon_engine.pipeline import Pipeline, PipelineOptions
from recon_engine.utils.logging import setup_logging


@click.group()
@click.option("--config", "config_path", default=None, help="Path to config.yaml (default: ~/.config/recon-engine/config.yaml)")
@click.option("--verbose", "-v", is_flag=True)
@click.pass_context
def cli(ctx, config_path, verbose):
    setup_logging(verbose)
    ctx.ensure_object(dict)
    ctx.obj["config"] = Config.load(config_path)


@cli.command()
@click.argument("target")
@click.option("--subfinder/--no-subfinder", default=True)
@click.option("--amass/--no-amass", default=True)
@click.option("--bbot/--no-bbot", default=False)
@click.option("--crtsh/--no-crtsh", default=True)
@click.option("--github", "use_github", is_flag=True, default=False, help="Run github-subdomains (needs GitHub tokens configured)")
@click.option("--bruteforce", "use_bruteforce", is_flag=True, default=False)
@click.option("--permutation", "use_permutation", is_flag=True, default=False)
@click.option("--screenshots", is_flag=True, default=False)
@click.option(
    "--screenshot-engine",
    type=click.Choice(["gowitness", "go-stare"]),
    default="gowitness",
    help="gowitness (default): structured output, feeds titles/screenshot paths back into the report. go-stare: faster, images only.",
)
@click.option("--favicon", is_flag=True, default=False)
@click.option("--wordlist", type=click.Path(exists=True, path_type=Path), default=None)
@click.option("--resolvers", type=click.Path(exists=True, path_type=Path), default=None)
@click.option("--favicon-db", type=click.Path(exists=True, path_type=Path), default=None)
@click.option("--output-dir", type=click.Path(path_type=Path), default=Path("./recon-output"))
@click.pass_context
def scan(
    ctx,
    target,
    subfinder,
    amass,
    bbot,
    crtsh,
    use_github,
    use_bruteforce,
    use_permutation,
    screenshots,
    screenshot_engine,
    favicon,
    wordlist,
    resolvers,
    favicon_db,
    output_dir,
):
    """Run the full recon pipeline against TARGET (an apex domain)."""
    config: Config = ctx.obj["config"]

    if (use_bruteforce or use_permutation) and resolvers is None:
        from recon_engine.modules.subdomain_bruteforce import fetch_resolvers

        output_dir.mkdir(parents=True, exist_ok=True)
        resolvers = output_dir / "resolvers.txt"
        click.echo(f"No --resolvers given; fetching trickest/resolvers to {resolvers} ...")
        try:
            fetch_resolvers(resolvers)
        except Exception as e:
            click.echo(f"Failed to fetch resolvers ({e}); bruteforce/permutation will be skipped.", err=True)
            resolvers = None

    options = PipelineOptions(
        use_subfinder=subfinder,
        use_amass=amass,
        use_bbot=bbot,
        use_crtsh=crtsh,
        use_github=use_github,
        use_bruteforce=use_bruteforce,
        use_permutation=use_permutation,
        use_screenshots=screenshots,
        screenshot_engine=screenshot_engine,
        use_favicon=favicon,
        wordlist=wordlist,
        resolvers=resolvers,
        favicon_db=favicon_db,
        output_dir=output_dir,
    )
    pipeline = Pipeline(config, options)
    try:
        result = pipeline.run(target)
    finally:
        pipeline.close()

    click.echo(f"\nDone: {result['total_subdomains']} subdomains known ({result['new_assets']} new), "
               f"{result['live_hosts']} live hosts, {result['elapsed_seconds']:.1f}s")
    click.echo(f"JSON report:     {result['json_report']}")
    click.echo(f"Markdown report: {result['markdown_report']}")


@cli.command()
@click.argument("target")
@click.option("--since-hours", type=float, default=24.0, help="Report assets first seen in the last N hours")
@click.option("--output-dir", type=click.Path(path_type=Path), default=Path("./recon-output"))
@click.pass_context
def changes(ctx, target, since_hours, output_dir):
    """Report assets discovered for TARGET since N hours ago -- the
    attack-surface-growth-tracker capability. Run `scan` periodically
    first; this just reads what's already stored."""
    config: Config = ctx.obj["config"]
    pipeline = Pipeline(config, PipelineOptions(output_dir=output_dir))
    try:
        since = time.time() - since_hours * 3600
        new = pipeline.change_report(target, since)
    finally:
        pipeline.close()

    if not new:
        click.echo(f"No new assets for {target} in the last {since_hours} hours.")
        return
    click.echo(f"{len(new)} new asset(s) for {target} since {since_hours} hours ago:")
    for a in new:
        click.echo(f"  [{a['asset_type']}] {a['value']}  (via: {', '.join(a['sources'])})")


@cli.command()
@click.option("--target", default=None, help="Limit to one target; omit for all targets")
@click.option("--output-dir", type=click.Path(path_type=Path), default=Path("./recon-output"))
@click.pass_context
def sources(ctx, target, output_dir):
    """Show the recon-source reliability scorecard: how many assets each
    technique has contributed so far."""
    config: Config = ctx.obj["config"]
    pipeline = Pipeline(config, PipelineOptions(output_dir=output_dir))
    try:
        counts = pipeline.source_reliability(target)
    finally:
        pipeline.close()

    if not counts:
        click.echo("No data yet -- run `scan` first.")
        return
    for source_name, count in counts.items():
        click.echo(f"  {source_name:<28} {count}")


@cli.command("config-check")
@click.pass_context
def config_check(ctx):
    """Report which API-gated sources and external tools are currently
    configured/available, so you can see what `scan` will and won't use."""
    config: Config = ctx.obj["config"]

    api_sources = [
        "chaos", "github", "shodan", "c99", "whoxy", "whoisxmlapi", "hostio",
        "securitytrails", "crunchbase", "openai", "builtwith",
    ]
    click.echo("API keys:")
    for s in api_sources:
        status = "configured" if config.has(s) else "missing"
        click.echo(f"  {s:<16} {status}")

    tools = [
        "subfinder", "amass", "bbot", "puredns", "dnsgen", "alterx", "naabu",
        "rustscan", "smap", "httpx", "go-stare", "gowitness", "eyewitness", "docker",
        "VHostScan", "github-subdomains", "trufflehog", "favfreak", "waymore",
    ]
    click.echo("\nExternal tools:")
    for t in tools:
        status = config.tool_path(t) or "not found on PATH"
        click.echo(f"  {t:<20} {status}")

    if config.path:
        click.echo(f"\nConfig file: {config.path}")
    else:
        click.echo("\nNo config file found -- running with defaults/env vars only. "
                    "See config/config.example.yaml.")


def main():
    cli(obj={})


if __name__ == "__main__":
    sys.exit(main())
