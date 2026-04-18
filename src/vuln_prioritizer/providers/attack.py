"""Optional offline ATT&CK context provider."""

from __future__ import annotations

import csv
from pathlib import Path
import re

from vuln_prioritizer.models import AttackData
from vuln_prioritizer.utils import normalize_cve_id

SEPARATOR_RE = re.compile(r"[;|]")


class AttackProvider:
    """Load optional ATT&CK mappings from a local CSV file."""

    def fetch_many(
        self,
        cve_ids: list[str],
        *,
        enabled: bool,
        offline_file: Path | None = None,
    ) -> tuple[dict[str, AttackData], list[str]]:
        if not enabled:
            return {}, []

        if offline_file is None:
            return {}, ["ATT&CK mode requested, but no offline ATT&CK mapping file was provided."]

        if not offline_file.exists() or not offline_file.is_file():
            return {}, [f"ATT&CK mapping file not found: {offline_file}"]

        if offline_file.suffix.lower() != ".csv":
            return {}, ["ATT&CK mapping file must be a CSV file."]

        with offline_file.open("r", encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle)
            if not reader.fieldnames:
                return {}, ["ATT&CK mapping CSV is missing a header row."]

            field_map = {field.strip().lower(): field for field in reader.fieldnames if field}
            cve_field = field_map.get("cve_id") or field_map.get("cve")
            if not cve_field:
                return {}, ["ATT&CK mapping CSV must contain a cve_id column."]

            techniques_field = field_map.get("attack_techniques")
            tactics_field = field_map.get("attack_tactics")
            note_field = field_map.get("attack_note")

            index: dict[str, AttackData] = {}
            requested = set(cve_ids)
            for row in reader:
                cve_id = normalize_cve_id(row.get(cve_field))
                if not cve_id or cve_id not in requested:
                    continue

                index[cve_id] = AttackData(
                    cve_id=cve_id,
                    attack_techniques=_split_multi_value(row.get(techniques_field, "")) if techniques_field else [],
                    attack_tactics=_split_multi_value(row.get(tactics_field, "")) if tactics_field else [],
                    attack_note=(row.get(note_field) or "").strip() or None if note_field else None,
                )

        return index, []


def _split_multi_value(raw_value: str) -> list[str]:
    return [part.strip() for part in SEPARATOR_RE.split(raw_value) if part.strip()]
