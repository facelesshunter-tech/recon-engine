import tempfile
import time
from pathlib import Path

from recon_engine.models import Asset, AssetType, Source
from recon_engine.state import AssetStore


def test_upsert_tracks_new_vs_seen():
    with tempfile.TemporaryDirectory() as tmp:
        store = AssetStore(Path(tmp) / "assets.db")
        a = Asset(value="dev.example.com", asset_type=AssetType.SUBDOMAIN, source=Source.SEED, target="example.com")
        assert store.upsert(a) is True   # brand new
        assert store.upsert(a) is False  # already seen
        store.close()


def test_new_since_filters_by_timestamp():
    with tempfile.TemporaryDirectory() as tmp:
        store = AssetStore(Path(tmp) / "assets.db")
        cutoff = time.time()
        time.sleep(0.01)
        a = Asset(value="new.example.com", asset_type=AssetType.SUBDOMAIN, source=Source.SEED, target="example.com")
        store.upsert(a)
        new = store.new_since("example.com", cutoff)
        assert len(new) == 1
        assert new[0]["value"] == "new.example.com"
        store.close()


def test_source_reliability_counts():
    with tempfile.TemporaryDirectory() as tmp:
        store = AssetStore(Path(tmp) / "assets.db")
        store.upsert(Asset(value="a.example.com", asset_type=AssetType.SUBDOMAIN, source=Source.SUBDOMAIN_PASSIVE, target="example.com"))
        store.upsert(Asset(value="b.example.com", asset_type=AssetType.SUBDOMAIN, source=Source.SUBDOMAIN_PASSIVE, target="example.com"))
        store.upsert(Asset(value="c.example.com", asset_type=AssetType.SUBDOMAIN, source=Source.GITHUB_RECON, target="example.com"))
        counts = store.source_reliability("example.com")
        assert counts["subdomain_passive"] == 2
        assert counts["github_recon"] == 1
        store.close()
