# Reporting and CI Integration

This document describes the current SARIF, GitHub Action, PR comment, and HTML reporting integration surface.

## Current Production State

Today the CLI supports:

- `analyze --format markdown|json|sarif|table`
- `analyze --input-format auto|cve-list|trivy-json|grype-json|cyclonedx-json|spdx-json|dependency-check-json|github-alerts-json`
- `compare --input-format ...`
- `explain`
- `data status`
- `report html --input analysis.json --output report.html`
- `attack validate|coverage|navigator-layer`

The repository root also exposes a composite GitHub Action via [action.yml](../../action.yml).

## GitHub Action Contract

The composite action supports two modes:

- `mode: analyze`
- `mode: report-html`

Common inputs:

- `input`
- `output-path`

Analyze-mode inputs:

- `input-format`
- `output-format`
- `asset-context`
- `vex-files`
- `fail-on`
- `policy-profile`
- `policy-file`
- `show-suppressed`
- `attack-source`
- `attack-mapping-file`
- `attack-technique-metadata-file`

The action installs the package from the action checkout and writes the resolved output path to the `report-path` output.

## SARIF for GitHub Code Scanning

Current contract:

```bash
vuln-prioritizer analyze \
  --input trivy-results.json \
  --input-format trivy-json \
  --format sarif \
  --output results.sarif \
  --fail-on high
```

GitHub Code Scanning accepts SARIF 2.1.0 uploads. The current reporter emits SARIF `2.1.0` and is suitable for upload via `github/codeql-action/upload-sarif`.

### PR Comment Reporting

Current contract:

```bash
vuln-prioritizer analyze \
  --input trivy-results.json \
  --input-format trivy-json \
  --format markdown \
  --output vuln-prioritization.md
```

### Static HTML Reporting

Current contract:

```bash
vuln-prioritizer analyze \
  --input findings.json \
  --input-format trivy-json \
  --format json \
  --output analysis.json

vuln-prioritizer report html \
  --input analysis.json \
  --output report.html
```

HTML renders from saved JSON output, not from a separate live analysis path.

## Example Workflows

Consumer workflow examples:

- [.github/examples/code-scanning-sarif.yml](../../.github/examples/code-scanning-sarif.yml)
- [.github/examples/pr-comment-report.yml](../../.github/examples/pr-comment-report.yml)
- [.github/examples/html-report-artifact.yml](../../.github/examples/html-report-artifact.yml)

Example output artifacts:

- [docs/examples/future_pr_comment.md](../examples/future_pr_comment.md)
- [docs/examples/future_results.sarif](../examples/future_results.sarif)
- [docs/examples/future_report.html](../examples/future_report.html)

## Guardrails

- The primary priority model remains transparent and rule-based from CVSS, EPSS, and KEV.
- ATT&CK, asset context, and VEX remain explicit contextual layers and must not become undocumented weighting factors.
- CVE-to-ATT&CK mappings remain dateibasiert and must not use heuristic or LLM-generated mappings.
