# vuln-prioritizer

[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Status: active](https://img.shields.io/badge/status-active-brightgreen)](#roadmap)
[![Quality: local-first](https://img.shields.io/badge/quality-local--first-informational)](#development)

`vuln-prioritizer` is a small Python CLI for prioritizing known vulnerabilities. It reads CVE lists, enriches them with NVD, EPSS, and CISA KEV data, and produces a transparent ranking for operational remediation decisions.

## Why This Project Exists

Vulnerability queues are usually larger than the time and staffing available to resolve them. Teams often need to decide what to patch now, what to mitigate next, and what to watch closely.

CVSS alone is not enough for that decision:

- severity is not the same as exploitation likelihood
- a widely exploited issue can matter more than a theoretically severe one
- prioritization needs to be explainable to both engineers and decision-makers

`vuln-prioritizer` exists to make that decision process smaller, clearer, and easier to defend. It turns a plain CVE list into a transparent, operationally useful ranking using public data sources.

## Project Overview

Many teams still prioritize vulnerabilities primarily by CVSS. That is useful, but often incomplete for day-to-day decision-making:

- CVSS captures technical severity, but not current exploitation likelihood.
- EPSS provides a data-driven estimate of likely exploitation within the next 30 days.
- KEV indicates whether a vulnerability is already known to be exploited in the wild.

This CLI combines those signals into a transparent ranking for patching, mitigation, and monitoring decisions.

## Motivation

The project is intentionally small, readable, and demo-friendly:

- a working CLI as the primary artifact
- transparent methodology
- technical depth through API integrations, parsing, caching, and tests
- clear security and management value through prioritized remediation guidance

## Data Sources

- NVD CVE API 2.0: `https://services.nvd.nist.gov/rest/json/cves/2.0`
- NVD API 2.0 Transition Guide: `https://nvd.nist.gov/general/news/api-20-announcements`
- FIRST EPSS API: `https://api.first.org/data/v1/epss`
- CISA KEV Catalog: `https://www.cisa.gov/known-exploited-vulnerabilities-catalog`
- CISA KEV Mirror: `https://github.com/cisagov/kev-data`

Optional ATT&CK mapping is intentionally outside the MVP. If used, it should only come from a local mapping CSV.

## Installation

### Requirements

- Python 3.11 or 3.12

### Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -e .
```

Optionally configure an NVD API key via `.env`:

```bash
cp .env.example .env
```

Then set `NVD_API_KEY` in `.env`.

## Development

This repository currently uses **local quality gates** by design. If GitHub Actions are unavailable or intentionally disabled, you can still run the full development workflow locally:

```bash
make install
make check
```

Additional local helpers:

```bash
make format
make test
make typecheck
make package
make package-check
make release-check
make demo-report
make demo-compare
make demo-explain
make precommit-install
```

A slim GitHub Actions workflow is also included now, but the repository still treats local `make check` as the primary quality gate.

For release candidates or public-release preparation, use:

```bash
make release-check
```

This runs the local quality gate, regenerates demo artifacts, builds source and wheel distributions under `dist/`, and validates the generated package metadata locally.

## Highlights

- focused CLI for prioritizing known CVEs
- official/public data sources only
- deterministic priority rules with documented rationale
- Markdown and JSON outputs for reporting and reuse
- optional local ATT&CK mapping without unsafe heuristics
- local-first quality gates for environments where CI usage is limited

To enable automatic local hooks with `pre-commit`:

```bash
make precommit-install
```

## Usage

### Basic Run

```bash
vuln-prioritizer analyze --input data/sample_cves.txt
```

### Filter the Enriched Result Set

```bash
vuln-prioritizer analyze \
  --input data/sample_cves.txt \
  --priority high \
  --min-epss 0.40 \
  --sort-by epss
```

### Generate a Markdown Report

```bash
vuln-prioritizer analyze \
  --input data/sample_cves.txt \
  --output docs/example_report.md \
  --format markdown
```

### Explain a Single CVE

```bash
vuln-prioritizer explain --cve CVE-2021-44228
```

### Export a Single CVE Explanation as JSON

```bash
vuln-prioritizer explain \
  --cve CVE-2021-44228 \
  --output explain.json \
  --format json
```

### Generate a JSON Export

```bash
vuln-prioritizer analyze \
  --input data/sample_cves.txt \
  --output report.json \
  --format json
```

### Compare CVSS-only vs Enriched Prioritization

```bash
vuln-prioritizer compare \
  --input data/sample_cves.txt \
  --output docs/example_compare.md \
  --format markdown
```

### Use a Local ATT&CK Mapping File

```bash
vuln-prioritizer explain \
  --cve CVE-2021-44228 \
  --offline-attack-file data/optional_attack_to_cve.csv
```

### Important Options

- `--input`: TXT or CSV file containing CVEs
- `--output`: target file for Markdown or JSON output
- `--format markdown|json|table`: output mode
- `--no-attack`: explicitly disable ATT&CK context
- `--priority critical|high|medium|low`: repeatable filter on the enriched priority label
- `--kev-only`: keep only KEV-listed CVEs
- `--min-cvss FLOAT`: keep only findings with CVSS greater than or equal to the threshold
- `--min-epss FLOAT`: keep only findings with EPSS greater than or equal to the threshold
- `--sort-by priority|epss|cvss|cve`: override display and export ordering
- `--critical-epss-threshold FLOAT`: override the enriched `Critical` EPSS threshold
- `--critical-cvss-threshold FLOAT`: override the enriched `Critical` CVSS threshold
- `--high-epss-threshold FLOAT`: override the enriched `High` EPSS threshold
- `--high-cvss-threshold FLOAT`: override the enriched `High` CVSS threshold
- `--medium-epss-threshold FLOAT`: override the enriched `Medium` EPSS threshold
- `--medium-cvss-threshold FLOAT`: override the enriched `Medium` CVSS threshold
- `--max-cves N`: limit analysis to the first `N` unique CVEs
- `--offline-kev-file PATH`: use a local KEV JSON or CSV file
- `--offline-attack-file PATH`: use a local ATT&CK mapping CSV file
- `--nvd-api-key-env NAME`: use a custom environment variable name for the NVD API key
- `--no-cache`: disable the local file cache
- `--cache-dir PATH`: set a custom cache directory
- `--cache-ttl-hours N`: set the cache TTL in hours

## Example Input

TXT:

```text
CVE-2021-44228
CVE-2022-22965
CVE-2023-44487
CVE-2024-3094
```

CSV:

```csv
cve
CVE-2021-44228
CVE-2022-22965
CVE-2023-44487
CVE-2024-3094
```

## Example Output

The CLI always prints a compact terminal table. A full sample report is checked in at [docs/example_report.md](docs/example_report.md).
The comparison view is checked in at [docs/example_compare.md](docs/example_compare.md).
For the detailed single-CVE mode, a sample export is available at [docs/example_explain.json](docs/example_explain.json).
An optional local ATT&CK mapping template is included at [data/optional_attack_to_cve.csv](data/optional_attack_to_cve.csv).

## Priority Logic

The MVP rules are intentionally simple and easy to explain:

- `Critical`: KEV or `(EPSS >= 0.70 and CVSS >= 7.0)`
- `High`: `EPSS >= 0.40` or `CVSS >= 9.0`
- `Medium`: `CVSS >= 7.0` or `EPSS >= 0.10`
- `Low`: everything else

ATT&CK does not influence the priority class in the MVP. Optional ATT&CK context is only used to enrich the rationale.

## Configurable Thresholds

The default thresholds remain small and opinionated, but the CLI now supports policy overrides when you need a more aggressive or more conservative triage mode.

Example:

```bash
vuln-prioritizer analyze \
  --input data/sample_cves.txt \
  --high-epss-threshold 0.30 \
  --medium-cvss-threshold 6.5
```

Policy overrides are shown in the terminal summary and exported metadata so the resulting report stays auditable.

## Comparison Baseline

The `compare` command uses a deterministic `CVSS-only` baseline with standard severity bands:

- `Critical`: `CVSS >= 9.0`
- `High`: `CVSS >= 7.0`
- `Medium`: `CVSS >= 4.0`
- `Low`: missing CVSS or everything below `4.0`

The comparison output then shows whether the enriched model makes a CVE more urgent, less urgent, or leaves it unchanged.

## Tool Boundaries

- not a vulnerability scanner
- no asset discovery
- no database
- no web UI
- no ticketing or SIEM integration
- no heuristic or LLM-generated CVE-to-ATT&CK mapping
- no live ATT&CK/TAXII integration in the MVP

Missing or incomplete source data is treated as a warning, not an automatic failure. The tool attempts to produce a useful report whenever possible.

## Tests

```bash
pytest
```

The test suite covers parsing, provider behavior, scoring, reporting, caching, and CLI end-to-end flows with mocked providers.

## Caching

By default, the tool uses a small file cache under `.cache/vuln-prioritizer`. The cache speeds up repeated demo and analysis runs for:

- NVD single-CVE lookups
- EPSS CVE data
- the online-loaded KEV catalog

The cache is optional and can be disabled with `--no-cache`.

## Open Source Readiness

The repository already includes the core maintainer files needed for a future public release:

- [CHANGELOG.md](CHANGELOG.md)
- [LICENSE](LICENSE)
- [CONTRIBUTING.md](CONTRIBUTING.md)
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)
- [SECURITY.md](SECURITY.md)

The quality workflow is local-first by design. The included GitHub Actions workflow simply mirrors `make check` so local and hosted validation stay aligned.

The published package metadata is also set up for a later public release, including project URLs, classifiers, and a `py.typed` marker for typed-package consumers.

## Roadmap

### Implemented

- TXT and CSV input
- NVD, EPSS, and KEV enrichment
- configurable enriched priority policy thresholds
- richer run summaries with coverage, ATT&CK hits, and filter metadata
- post-enrichment filters and sort overrides
- `compare` command for `CVSS-only vs enriched`
- richer `explain` output with baseline comparison
- optional local ATT&CK mapping workflow with a checked-in template
- terminal, Markdown, and JSON outputs
- slim GitHub Actions CI mirroring `make check`

### Possible Future Work

- named policy presets for common operating modes
- additional cache strategies and reporting around cache hits
- release automation beyond tagging and changelog maintenance
