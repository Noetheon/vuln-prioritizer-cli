from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from vuln_prioritizer.cache import FileCache


def test_file_cache_round_trip(tmp_path: Path) -> None:
    cache = FileCache(tmp_path / "cache", ttl_hours=24)

    cache.set_json("nvd", "CVE-2026-0001", {"value": 1, "name": "demo"})

    assert cache.get_json("nvd", "CVE-2026-0001") == {"value": 1, "name": "demo"}


def test_file_cache_returns_none_for_expired_document(tmp_path: Path) -> None:
    cache = FileCache(tmp_path / "cache", ttl_hours=1)
    path = cache._path_for("epss", "CVE-2026-0002")
    path.parent.mkdir(parents=True, exist_ok=True)
    expired_at = (datetime.now(UTC) - timedelta(hours=2)).isoformat()
    path.write_text(
        json.dumps({"cached_at": expired_at, "payload": {"epss": 0.9}}),
        encoding="utf-8",
    )

    assert cache.get_json("epss", "CVE-2026-0002") is None


def test_file_cache_returns_none_for_invalid_json(tmp_path: Path) -> None:
    cache = FileCache(tmp_path / "cache", ttl_hours=24)
    path = cache._path_for("kev", "catalog")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("{invalid", encoding="utf-8")

    assert cache.get_json("kev", "catalog") is None
