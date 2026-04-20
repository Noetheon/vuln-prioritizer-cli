# Support Matrix

## Command matrix

| Command | Primary input | Supported file outputs | Current machine contract | Notes |
| --- | --- | --- | --- | --- |
| `analyze` | `--input PATH` | `markdown`, `json`, `sarif` | JSON schema + SARIF 2.1.0 | `table` is terminal-only. |
| `compare` | `--input PATH` | `markdown`, `json` | JSON schema | Comparison is `CVSS-only` vs enriched. |
| `explain` | `--cve CVE-...` | `markdown`, `json` | JSON schema | Single-CVE detailed view. |
| `attack validate` | ATT&CK local files | `markdown`, `json` | No published schema yet | Validates local mapping and metadata artifacts. |
| `attack coverage` | `--input PATH` | `markdown`, `json` | No published schema yet | Uses the same input loader for CVE extraction. |
| `attack navigator-layer` | `--input PATH` | Navigator layer JSON | Navigator JSON, no local schema here | Exports a frequency-based ATT&CK Navigator layer. |
| `data status` | none | none | none | Terminal inspection only. |
| `report html` | analysis JSON | `html` | Consumes analysis JSON contract | No live enrichment during rendering. |

## Input-format matrix

| `--input-format` | Auto-detect | `analyze` / `compare` | `attack coverage` / `navigator-layer` | Normalized provenance currently preserved | Notes |
| --- | --- | --- | --- | --- | --- |
| `cve-list` | `.txt`, `.csv` | yes | yes | `cve_id`, source line/row | Historical compatibility path. |
| `trivy-json` | JSON with `Results` | yes | yes | component, version, purl, package type, path, fix versions, target image | Default target kind is `image`. |
| `grype-json` | JSON with `matches` | yes | yes | component, version, purl, package type, path, fix versions, target image | Keeps the first artifact location as current path evidence. |
| `cyclonedx-json` | JSON with `bomFormat=CycloneDX` and vulnerabilities | yes | yes | component refs, purl, versions, dependency context when present | Used for SBOM+vuln exports, not plain BOMs without vulnerabilities. |
| `spdx-json` | JSON with `spdxVersion` | yes | yes | package names, versions, file names when available | Current support is JSON only. |
| `dependency-check-json` | JSON with `scanInfo` and `dependencies` | yes | yes | dependency path, package/file names, severity, fix/version hints where present | Current support is JSON only. |
| `github-alerts-json` | JSON array or alert-like object | yes | yes | advisory source, package context when present | Contract assumes a pinned JSON export shape, not arbitrary API responses. |

## Feature overlay matrix

| Feature | `analyze` | `compare` | `explain` | Notes |
| --- | --- | --- | --- | --- |
| ATT&CK enrichment | yes | yes | yes | Sources: `none`, `local-csv`, `ctid-json`. No remote ATT&CK dependency. |
| Asset context CSV | yes | yes | yes | Exact join on `(target_kind, target_ref)` only. |
| VEX files | yes | yes | yes | Supports OpenVEX JSON and CycloneDX VEX JSON. |
| Policy profiles | yes | yes | yes | Built-ins: `default`, `enterprise`, `conservative`. |
| Custom policy file | yes | yes | yes | YAML-defined profiles, selected by `--policy-profile`. |
| `--show-suppressed` | yes | yes | yes | Reveals findings fully suppressed by VEX. |
| `--fail-on` | yes | no | no | Returns exit code `1` when the threshold is met. |

## Explain-specific context notes

`explain` does not load a scanner or SBOM file. It builds a single inline occurrence from `--cve` and optional manual targeting fields.

To make asset context or VEX matching meaningful with `explain`, provide:

- `--target-kind`
- `--target-ref`
- optional `--asset-context`
- optional `--vex-file`

Without a matching target, the explain flow still works, but asset-join and exact-match VEX context may remain empty.

## Output notes

- Prefer JSON for automation.
- Prefer `--input-format` over `auto` in CI if reproducibility matters.
- `report html` expects an analysis JSON export, not compare JSON or explain JSON.
- `sarif` is part of the documented contract only for `analyze`.
