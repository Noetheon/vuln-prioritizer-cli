# vuln-prioritizer

`vuln-prioritizer` is a small Python CLI for prioritizing known vulnerabilities. It reads CVE lists, enriches them with NVD, EPSS, and CISA KEV data, and produces a transparent ranking for operational remediation decisions.

## Project Idea

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
make demo-report
make demo-explain
make precommit-install
```

To enable automatic local hooks with `pre-commit`:

```bash
make precommit-install
```

## Usage

### Basic Run

```bash
vuln-prioritizer analyze --input data/sample_cves.txt
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

### Important Options

- `--input`: TXT or CSV file containing CVEs
- `--output`: target file for Markdown or JSON output
- `--format markdown|json|table`: output mode
- `--no-attack`: explicitly disable ATT&CK context
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
For the detailed single-CVE mode, a sample export is available at [docs/example_explain.json](docs/example_explain.json).

## Priority Logic

The MVP rules are intentionally simple and easy to explain:

- `Critical`: KEV or `(EPSS >= 0.70 and CVSS >= 7.0)`
- `High`: `EPSS >= 0.40` or `CVSS >= 9.0`
- `Medium`: `CVSS >= 7.0` or `EPSS >= 0.10`
- `Low`: everything else

ATT&CK does not influence the priority class in the MVP. Optional ATT&CK context is only used to enrich the rationale.

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

- [LICENSE](LICENSE)
- [CONTRIBUTING.md](CONTRIBUTING.md)
- [SECURITY.md](SECURITY.md)

The current quality workflow is local-first by design. If GitHub Actions are added later, the CI pipeline can simply build on `make check`.

## Roadmap

### MVP

- TXT and CSV input
- NVD, EPSS, and KEV enrichment
- fixed priority rules
- terminal table output
- Markdown and JSON output

### V1.1

- better CLI summaries
- `CVSS-only vs enriched` comparison view
- expanded filtering options

### V1.2

- optional ATT&CK mapping via local file
- configurable thresholds once there is a clean policy model

### V1.3

- more cache strategies
- expanded `explain` output and comparison capabilities
