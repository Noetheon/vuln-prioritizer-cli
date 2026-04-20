# Contracts

## Scope

This document describes the current public contract for the implemented CLI and report surfaces. It is intentionally based on the code that exists today, not on roadmap-only behavior.

The project exposes three kinds of interfaces:

- CLI flags and exit behavior
- machine-readable exports
- human-readable reports

The strongest contract today is the JSON export surface.

## Public machine-readable surfaces

The following outputs are the current documented machine interfaces:

- `analyze --format json`
- `compare --format json`
- `explain --format json`
- `analyze --format sarif`
- `report html --input <analysis-json>`

Published JSON schemas in `docs/schemas/` cover:

- `analysis-report.schema.json`
- `compare-report.schema.json`
- `explain-report.schema.json`

`report html` is a secondary renderer over the analysis JSON contract. It does not define its own independent source model.

## JSON envelope contract

All documented JSON exports share the same pattern:

- `metadata`
- `attack_summary`
- one primary payload key

Primary payload keys by command:

- `analyze`: `findings`
- `compare`: `comparisons`
- `explain`: `finding`, plus `nvd`, `epss`, `kev`, `attack`, and `comparison`

### `metadata.schema_version`

Every documented JSON export includes `metadata.schema_version`.

Current value:

- `1.0.0`

Consumer guidance:

- treat an unknown major version as unsupported
- tolerate additive fields on the same major version
- ignore unknown object members rather than failing on extra fields

The bundled schemas target the currently emitted version, `1.0.0`.

## Semantic contract

The field names are only part of the contract. The meaning of several fields matters for downstream consumers.

### Base priority

`priority_label` is the primary priority decision.

Current rule:

- it is derived from `CVSS + EPSS + KEV`
- ATT&CK is contextual
- asset context is contextual
- VEX can suppress a finding from the default visible list, but it does not create a new opaque risk score

### ATT&CK context

ATT&CK fields are optional enrichment.

Current guarantees:

- ATT&CK is local-file sourced only
- no heuristic or LLM-generated CVE-to-ATT&CK mapping is performed
- `attack_relevance` is contextual and explainable
- absence of ATT&CK data is represented as unmapped context, not guessed context

### Provenance

`provenance` is an aggregated per-CVE view over occurrence-level input evidence.

Current meaning:

- `occurrence_count` counts total known occurrences for the CVE
- `active_occurrence_count` excludes VEX-suppressed occurrences
- `suppressed_occurrence_count` counts occurrences suppressed by VEX
- `source_formats`, `components`, `affected_paths`, `fix_versions`, and `targets` are deduplicated summaries
- `occurrences` contains the raw normalized occurrence list used for aggregation

### VEX semantics

Current VEX contract:

- VEX is evaluated per occurrence, not per naked CVE string alone
- `suppressed_by_vex` means all known occurrences are suppressed
- `under_investigation` remains visible
- exact text in `vex_justification` and `vex_action_statement` is informative, not enum-stable

### Context fields

`context_summary` and `context_recommendation` are explanatory fields.

Current guarantee:

- they do not silently replace `priority_label`
- they may change wording between releases without a schema break

## CLI contract

### Supported format combinations

The public combinations currently intended for use are:

- `analyze`: `table`, `markdown`, `json`, `sarif`
- `compare`: `table`, `markdown`, `json`
- `explain`: `table`, `markdown`, `json`
- `attack validate`: `table`, `markdown`, `json`
- `attack coverage`: `table`, `markdown`, `json`
- `attack navigator-layer`: JSON file output
- `report html`: HTML file output

Important boundary:

- `table` is a terminal view and must not be combined with `--output`
- `sarif` is a documented export only for `analyze`

### Exit behavior

Current command behavior for the main flows:

- `0`: successful execution
- `1`: a no-result or policy-triggered failure condition, for example `--fail-on` matched findings or `explain` could not produce a visible finding
- `2`: input validation failure

Consumers should treat warning text as informational and not parse it as a stable error taxonomy.

## Compatibility and deprecation policy

This repository is documenting its contract before `v1.0.0`, so the policy is intentionally conservative and explicit.

### JSON compatibility

- breaking machine-readable changes must update `metadata.schema_version`
- additive fields on the same major version are allowed
- narrative fields such as `rationale`, `recommended_action`, `context_summary`, `context_recommendation`, and warning strings are not text-stable parsing targets

### CLI compatibility

- existing documented flags are intended to remain stable where practical
- removals or renames should be called out in release notes
- compatibility aliases may remain even when a newer flag exists

Current compatibility alias:

- `--offline-attack-file` remains the legacy local-CSV ATT&CK path alias

### Non-contract surfaces

The following are intentionally not covered by the published JSON schemas:

- terminal table layout
- Markdown table layout
- wording of warnings and recommendation text
- undocumented JSON payloads from helper commands such as `attack validate` and `attack coverage`

Those surfaces are useful, but they should not be treated as strict automation contracts unless they are later given their own published schemas.
