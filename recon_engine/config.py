"""Central configuration loader.

Every API-gated source named anywhere in the TBHM Day One deck has a slot
here (see config/config.example.yaml). A module checks `Config.has(name)`
before attempting to use a gated source, and degrades gracefully (skips
with a warning) rather than crashing when a key is missing -- recon-engine
is meant to be useful on day one with zero keys configured, and to get
progressively more powerful as you add keys, exactly as TBHM itself
recommends prioritizing (Chaos -> GitHub tokens -> Shodan -> free/cheap ->
paid).
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import Any, Optional

import yaml

DEFAULT_CONFIG_PATH = Path.home() / ".config" / "recon-engine" / "config.yaml"


class Config:
    def __init__(self, data: dict[str, Any], path: Optional[Path] = None):
        self._data = data
        self.path = path

    # ---- loading -----------------------------------------------------

    @classmethod
    def load(cls, path: Optional[str] = None) -> "Config":
        candidates = []
        if path:
            candidates.append(Path(path))
        candidates.append(Path.cwd() / "config" / "config.yaml")
        candidates.append(DEFAULT_CONFIG_PATH)

        for candidate in candidates:
            if candidate and candidate.is_file():
                with open(candidate, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f) or {}
                return cls(data, path=candidate)

        # No config found -- run with an empty config rather than failing.
        # Every module must tolerate this (free-tier sources + installed
        # binaries still work with zero keys configured).
        return cls({}, path=None)

    # ---- API keys ------------------------------------------------------

    def api_key(self, source: str) -> Optional[str]:
        """Look up an API key, preferring environment variables over the
        config file so secrets never have to live on disk if you don't
        want them to: RECON_ENGINE_<SOURCE>_API_KEY."""
        env_name = f"RECON_ENGINE_{source.upper()}_API_KEY"
        if env_name in os.environ:
            return os.environ[env_name]
        return (self._data.get("api_keys", {}) or {}).get(source)

    def api_keys_list(self, source: str) -> list[str]:
        """Some sources (GitHub tokens especially -- TBHM explicitly
        recommends a *pool* of tokens to round-robin around rate limits)
        support multiple keys."""
        keys = (self._data.get("api_keys", {}) or {}).get(source)
        if keys is None:
            single = self.api_key(source)
            return [single] if single else []
        if isinstance(keys, str):
            return [keys]
        return list(keys)

    def has(self, source: str) -> bool:
        return bool(self.api_key(source) or self.api_keys_list(source))

    # ---- external tool binaries ----------------------------------------

    def tool_path(self, tool: str) -> Optional[str]:
        """Resolve an external binary: explicit config override, else PATH."""
        override = (self._data.get("tools", {}) or {}).get(tool)
        if override:
            return override
        return shutil.which(tool)

    def tool_available(self, tool: str) -> bool:
        return self.tool_path(tool) is not None

    # ---- generic settings ------------------------------------------------

    def get(self, *keys: str, default: Any = None) -> Any:
        node: Any = self._data
        for k in keys:
            if not isinstance(node, dict) or k not in node:
                return default
            node = node[k]
        return node

    @property
    def resolvers_path(self) -> Optional[str]:
        return self.get("recon", "resolvers_path", default=None)

    @property
    def output_dir(self) -> Path:
        d = self.get("recon", "output_dir", default="./recon-output")
        return Path(d)
