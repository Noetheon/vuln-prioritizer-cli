# Product Roadmap

This roadmap now records the release line that was implemented locally from the ATT&CK-focused `v0.3.0` baseline through the stable `v1.0.0` contract release.

The project remains a CLI for prioritizing known CVEs. It is not a scanner, not a web application, and does not use heuristic or AI-generated CVE-to-ATT&CK mappings.

## Current Release Surface

- `v1.0.0` provides `analyze`, `compare`, `explain`, `data status`, `report html`, and ATT&CK utility commands.
- `analyze` and `compare` support scanner/SBOM JSON input formats.
- The JSON export contract is versioned with `metadata.schema_version = 1.0.0`.
- Default prioritization stays grounded in `CVSS + EPSS + KEV`.
- ATT&CK, asset context, and VEX remain explicit contextual layers.

## Implemented Release Line

### `v0.3.1` Public Readiness

Status: shipped

- Release automation, CodeQL, and Dependabot.
- Public-facing quickstart, troubleshooting, and showcase materials.
- No new production scoring or parsing features.

### `v0.4.0` Real Security Inputs

Status: shipped

- New `--input-format` support for `trivy-json`, `grype-json`, and `cyclonedx-json`.
- Internal occurrence/provenance layer while keeping CVE-centric findings.
- `data status` for cache and source transparency.

### `v0.5.0` Asset Context

Status: shipped

- Optional `--asset-context` CSV support.
- Built-in `default`, `enterprise`, and `conservative` policy profiles.
- Additional importers for `spdx-json`, `dependency-check-json`, and a documented GitHub alerts export shape.

### `v0.6.0` VEX

Status: shipped

- `--vex-file` support for OpenVEX and CycloneDX VEX.
- Occurrence-level applicability decisions with exact matching only.
- Visible suppression and investigation state in reports and explain output.

### `v0.7.0` GitHub and CI Integration

Status: shipped

- `analyze --format sarif`.
- `--fail-on` exit policies.
- Published composite GitHub Action and PR comment integration.

### `v0.8.0` HTML Reporting

Status: shipped

- Static `report html` rendering from saved JSON analysis output.
- Executive summary, ATT&CK summary, asset impact, and VEX sections.

### `v0.9.0` Contracts and Customization

Status: shipped

- Versioned JSON output schema.
- JSON Schemas, compatibility rules, and support matrix.
- Optional YAML-based `--policy-file`.

### `v1.0.0` Stable OSS Release

Status: implemented locally; release workflow is wired for tagged GitHub Releases and PyPI publishing

- Stable CLI and JSON contracts.
- Documented and tested `pipx` installation.
- Stable scanner/SBOM inputs, Asset Context, VEX, and GitHub integration.

## Deliberate Non-Goals Through `v1.0.0`

- Web dashboard
- Database-backed service
- ServiceNow or Jira integration
- Mandatory live TAXII integration
- Heuristic or ML-based CVE-to-ATT&CK mapping

## Current Integration Materials

The repository contains example integration and output materials for the shipped surface:

- [docs/integrations/reporting_and_ci.md](./integrations/reporting_and_ci.md)
- [docs/examples/example_pr_comment.md](./examples/example_pr_comment.md)
- [docs/examples/example_results.sarif](./examples/example_results.sarif)
- [docs/examples/example_report.html](./examples/example_report.html)
- [.github/examples/README.md](../.github/examples/README.md)

These files now document current consumer workflows and example outputs for the implemented CLI/Action surface, even where filenames still reflect their earlier preview origin.
