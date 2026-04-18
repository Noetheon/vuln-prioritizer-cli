"""Small filesystem cache for provider responses."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
from typing import Any

from vuln_prioritizer.utils import iso_utc_now


class FileCache:
    """JSON file cache with TTL semantics."""

    def __init__(self, cache_dir: Path, ttl_hours: int) -> None:
        self.cache_dir = cache_dir
        self.ttl = timedelta(hours=ttl_hours)
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def get_json(self, namespace: str, key: str) -> Any | None:
        """Return cached JSON payload if present and not expired."""
        path = self._path_for(namespace, key)
        if not path.exists():
            return None

        try:
            document = json.loads(path.read_text(encoding="utf-8"))
            cached_at_raw = document.get("cached_at")
            if not cached_at_raw:
                return None
            cached_at = datetime.fromisoformat(cached_at_raw)
            if cached_at.tzinfo is None:
                cached_at = cached_at.replace(tzinfo=timezone.utc)
            if datetime.now(timezone.utc) - cached_at > self.ttl:
                return None
            return document.get("payload")
        except (OSError, json.JSONDecodeError, ValueError):
            return None

    def set_json(self, namespace: str, key: str, payload: Any) -> None:
        """Persist a JSON-serializable payload."""
        path = self._path_for(namespace, key)
        path.parent.mkdir(parents=True, exist_ok=True)
        document = {"cached_at": iso_utc_now(), "payload": payload}
        path.write_text(json.dumps(document, indent=2, sort_keys=True), encoding="utf-8")

    def _path_for(self, namespace: str, key: str) -> Path:
        digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
        return self.cache_dir / namespace / f"{digest}.json"
