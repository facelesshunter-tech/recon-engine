"""Open cloud-storage-bucket search (TBHM KB §22.5, "Other (Greyhatwarfare)").

The deck's final slide names Greyhatwarfare with no further elaboration
beyond the title. Greyhatwarfare (buckets.grayhatwarfare.com) indexes
publicly-exposed, misconfigured cloud storage buckets (S3, Azure Blob,
GCS, DigitalOcean Spaces) and exposes a documented search API -- directly
useful alongside the amazonaws.com cloud-storage watch-for mentioned in
KB §13.3's GitHub-recon advice.
"""

from __future__ import annotations

import logging

from recon_engine.config import Config
from recon_engine.utils.http import get_json

logger = logging.getLogger("recon_engine.open_storage")

GREYHATWARFARE_BASE = "https://buckets.grayhatwarfare.com/api/v2"


def search_buckets(config: Config, keyword: str, *, limit: int = 100) -> list[dict]:
    key = config.api_key("greyhatwarfare")
    if not key:
        logger.warning("no greyhatwarfare API key configured (config.api_keys.greyhatwarfare) -- bucket search skipped")
        return []
    data = get_json(
        f"{GREYHATWARFARE_BASE}/files",
        params={"keywords": keyword, "limit": limit},
        headers={"Authorization": f"Bearer {key}"},
        timeout=30,
    )
    if not data:
        return []
    return data.get("files", [])


def search_bucket_names(config: Config, keyword: str, *, limit: int = 100) -> list[str]:
    """Search for bucket *names* containing a keyword, rather than files
    inside buckets -- useful for finding e.g. `<company>-backups` or
    `<company>-prod` style bucket-naming patterns directly."""
    key = config.api_key("greyhatwarfare")
    if not key:
        logger.warning("no greyhatwarfare API key configured (config.api_keys.greyhatwarfare) -- bucket search skipped")
        return []
    data = get_json(
        f"{GREYHATWARFARE_BASE}/buckets",
        params={"keywords": keyword, "limit": limit},
        headers={"Authorization": f"Bearer {key}"},
        timeout=30,
    )
    if not data:
        return []
    return [b.get("bucket", "") for b in data.get("buckets", []) if b.get("bucket")]
