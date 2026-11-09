from pathlib import Path

from recon_engine.config import Config
from recon_engine.pipeline import Pipeline, PipelineOptions, PASSIVE_SOURCE_MAP, MAX_WAF_DETECT_HOSTS
from recon_engine.models import Source
from recon_engine.modules import subdomain_bruteforce, permutation, live_validation


def test_passive_source_map_covers_every_passive_enumerate_key():
    # Every key subdomain_passive.passive_enumerate() can return (see its
    # own `out[...] = ...` assignments) must have a specific Source value
    # here -- otherwise that tool's discoveries silently fall back to the
    # generic SUBDOMAIN_PASSIVE bucket again, the exact bug this fixes.
    expected_keys = {"subfinder", "amass", "bbot", "crtsh", "c99", "assetfinder"}
    assert expected_keys == set(PASSIVE_SOURCE_MAP.keys())


def test_passive_source_map_values_are_distinct_source_members():
    values = list(PASSIVE_SOURCE_MAP.values())
    assert len(values) == len(set(values)), "two tools must not share one Source value"
    for v in values:
        assert isinstance(v, Source)


def test_waf_detect_host_cap_is_configured():
    assert MAX_WAF_DETECT_HOSTS > 0


def test_permutation_seed_includes_bruteforce_results(tmp_path, monkeypatch):
    """Regression test for the exact bug found live against tesla.com:
    permutation's seed list must be computed AFTER bruteforce runs, so
    anything bruteforce discovers actually gets mutated too -- not just
    whatever passive discovery already knew about."""
    captured_seed = {}

    def fake_bruteforce(config, domain, wordlist, resolvers, **kwargs):
        return ["bruteforced.tesla.com"]

    def fake_permute_and_resolve(config, known_subdomains, resolvers, **kwargs):
        captured_seed["seed"] = list(known_subdomains)
        return []

    def fake_probe(config, hosts, **kwargs):
        return []

    monkeypatch.setattr(subdomain_bruteforce, "bruteforce", fake_bruteforce)
    monkeypatch.setattr(permutation, "permute_and_resolve", fake_permute_and_resolve)
    monkeypatch.setattr(live_validation, "probe", fake_probe)

    options = PipelineOptions(
        use_subfinder=False, use_amass=False, use_bbot=False, use_crtsh=False, use_assetfinder=False,
        use_bruteforce=True, use_permutation=True,
        wordlist=Path("/nonexistent-wordlist.txt"), resolvers=Path("/nonexistent-resolvers.txt"),
        use_dns_intel=False, use_tls_probe=False, use_cve_intel=False,
        output_dir=tmp_path,
    )
    pipeline = Pipeline(Config({}), options)
    try:
        pipeline.run("tesla.com")
    finally:
        pipeline.close()

    assert "bruteforced.tesla.com" in captured_seed["seed"]
