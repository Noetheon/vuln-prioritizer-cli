"""Input parsing for TXT and CSV CVE lists."""

from __future__ import annotations

import csv
from pathlib import Path

from vuln_prioritizer.models import InputItem
from vuln_prioritizer.utils import normalize_cve_id


def parse_input_file(
    path: Path,
    max_cves: int | None = None,
) -> tuple[list[InputItem], list[str], int]:
    """Parse an input file and return normalized, deduplicated CVE identifiers."""
    if not path.exists() or not path.is_file():
        raise ValueError(f"Input file does not exist: {path}")

    suffix = path.suffix.lower()
    if suffix not in {".txt", ".csv"}:
        raise ValueError("Unsupported input format. Use .txt or .csv files.")

    warnings: list[str] = []
    seen: set[str] = set()
    normalized: list[InputItem] = []

    rows = _read_txt(path) if suffix == ".txt" else _read_csv(path)
    for line_number, raw_value in rows:
        cve_id = normalize_cve_id(raw_value)
        if not cve_id:
            warnings.append(f"Ignored invalid CVE identifier at line {line_number}: {raw_value!r}")
            continue
        if cve_id in seen:
            warnings.append(f"Ignored duplicate CVE identifier: {cve_id}")
            continue
        seen.add(cve_id)
        normalized.append(InputItem(cve_id=cve_id))

    total_rows = len(rows)

    if max_cves is not None and len(normalized) > max_cves:
        warnings.append(
            f"Applied --max-cves {max_cves}; truncated the analysis set from "
            f"{len(normalized)} to {max_cves} CVEs."
        )
        normalized = normalized[:max_cves]

    if not normalized:
        raise ValueError("No valid CVE identifiers were found in the input file.")

    return normalized, warnings, total_rows


def _read_txt(path: Path) -> list[tuple[int, str]]:
    rows: list[tuple[int, str]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            rows.append((line_number, stripped))
    return rows


def _read_csv(path: Path) -> list[tuple[int, str]]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames:
            raise ValueError("CSV input is missing a header row.")
        field_map = {field.strip().lower(): field for field in reader.fieldnames if field}
        cve_field = field_map.get("cve") or field_map.get("cve_id")
        if not cve_field:
            raise ValueError("CSV input must contain a 'cve' or 'cve_id' column.")

        rows: list[tuple[int, str]] = []
        for row_number, row in enumerate(reader, start=2):
            value = (row.get(cve_field) or "").strip()
            if not value:
                continue
            rows.append((row_number, value))
        return rows
