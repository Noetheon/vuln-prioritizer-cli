# vuln-prioritizer

[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Status: v0.3.0](https://img.shields.io/badge/status-v0.3.0-brightgreen)](./CHANGELOG.md)
[![Quality: local-first](https://img.shields.io/badge/quality-local--first-informational)](#development)

`vuln-prioritizer` is a small Python CLI for prioritizing known CVEs. It enriches local CVE lists with NVD, FIRST EPSS, and CISA KEV data, then adds an optional ATT&CK context layer sourced from explicit local CTID Mappings Explorer artifacts.

## Why This Project Exists

Security teams rarely patch everything at once. They need a defensible way to decide:

- what to patch immediately
- what to mitigate next
- what to watch closely
- what to explain upward to leadership

CVSS alone is not enough for that workflow. `vuln-prioritizer` combines:

- CVSS from NVD for technical severity
- EPSS for near-term exploitation likelihood
- CISA KEV for known real-world exploitation
- CTID/MITRE ATT&CK mappings for adversary-behavior and impact context

The differentiator in `v0.3.0` is the last layer: ATT&CK-aware vulnerability context based on official CTID Mappings Explorer artifacts, not on heuristic or LLM-generated CVE-to-ATT&CK guesses.

## Project Positioning

This project overlaps with general CVE prioritizers, but it is intentionally positioned as a threat-informed extension rather than a generic triage tool.

Reference point:

- `TURROKS/CVE_Prioritizer` combines CVSS, EPSS, CISA KEV, and VulnCheck-oriented enrichment.

This project adds:

- deterministic `compare` and `explain` workflows
- local-first evidence and demo artifacts
- CTID-based ATT&CK context for mapped CVEs
- ATT&CK coverage and Navigator export commands

See:

- [docs/reference_cve_prioritizer_gap_analysis.md](docs/reference_cve_prioritizer_gap_analysis.md)
- [docs/evidence/current_state_audit.md](docs/evidence/current_state_audit.md)

## Scope Boundaries

This tool is:

- a CLI for known CVEs
- local-first and demo-friendly
- explicit about data sources
- designed for vulnerability management and management-facing evidence

This tool is not:

- a scanner
- a SIEM integration
- a ticketing workflow
- a web app
- a database-backed platform
- a heuristic ATT&CK mapper

## Data Sources

- NVD CVE API 2.0: `https://services.nvd.nist.gov/rest/json/cves/2.0`
- FIRST EPSS API: `https://api.first.org/data/v1/epss`
- CISA KEV Catalog: `https://www.cisa.gov/known-exploited-vulnerabilities-catalog`
- CISA KEV mirror: `https://github.com/cisagov/kev-data`
- CTID Mappings Explorer: `https://center-for-threat-informed-defense.github.io/mappings-explorer/`
- CTID KEV mapping page: `https://center-for-threat-informed-defense.github.io/mappings-explorer/external/kev/`
- MITRE ATT&CK Data & Tools: `https://attack.mitre.org/resources/attack-data-and-tools/`

## ATT&CK Methodology

ATT&CK in `v0.3.0` is:

- optional
- local-file based
- explicit about provenance
- separate from the main priority score

ATT&CK in `v0.3.0` is not:

- inferred from CVE descriptions
- fetched from live TAXII
- used as an undocumented weighting factor

Default methodology:

- `Critical`: KEV or `(EPSS >= 0.70 and CVSS >= 7.0)`
- `High`: `EPSS >= 0.40` or `CVSS >= 9.0`
- `Medium`: `CVSS >= 7.0` or `EPSS >= 0.10`
- `Low`: everything else

ATT&CK adds:

- structured mappings
- technique metadata
- tactic visibility
- `attack_relevance`
- richer report and explain output

ATT&CK does not silently override the priority class.

## Installation

### Requirements

- Python 3.11 or 3.12

### Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -e .[dev]
```

Optionally configure an NVD API key via `.env`:

```bash
cp .env.example .env
```

Then set `NVD_API_KEY` in `.env`.

## Development

Local validation is the primary workflow:

```bash
make install
make check
```

Release-oriented validation:

```bash
make release-check
```

Helpful local targets:

```bash
make demo-report
make demo-compare
make demo-explain
make demo-attack-report
make demo-attack-compare
make demo-attack-explain
make demo-attack-coverage
make demo-attack-navigator
```

## Usage

### Baseline Analyze

```bash
vuln-prioritizer analyze --input data/sample_cves.txt
```

### ATT&CK-aware Analyze

```bash
vuln-prioritizer analyze \
  --input data/sample_cves_mixed.txt \
  --output docs/example_attack_report.md \
  --format markdown \
  --attack-source ctid-json \
  --attack-mapping-file data/attack/ctid_kev_enterprise_2025-07-28_attack-16.1_subset.json \
  --attack-technique-metadata-file data/attack/attack_techniques_enterprise_16.1_subset.json
```

### Compare CVSS-only vs Enriched, with ATT&CK Context

```bash
vuln-prioritizer compare \
  --input data/sample_cves_mixed.txt \
  --output docs/example_attack_compare.md \
  --format markdown \
  --attack-source ctid-json \
  --attack-mapping-file data/attack/ctid_kev_enterprise_2025-07-28_attack-16.1_subset.json \
  --attack-technique-metadata-file data/attack/attack_techniques_enterprise_16.1_subset.json
```

### Explain a Single Mapped CVE

```bash
vuln-prioritizer explain \
  --cve CVE-2023-34362 \
  --output docs/example_attack_explain.json \
  --format json \
  --attack-source ctid-json \
  --attack-mapping-file data/attack/ctid_kev_enterprise_2025-07-28_attack-16.1_subset.json \
  --attack-technique-metadata-file data/attack/attack_techniques_enterprise_16.1_subset.json
```

### Validate Local ATT&CK Inputs

```bash
vuln-prioritizer attack validate \
  --attack-mapping-file data/attack/ctid_kev_enterprise_2025-07-28_attack-16.1_subset.json \
  --attack-technique-metadata-file data/attack/attack_techniques_enterprise_16.1_subset.json
```

### ATT&CK Coverage Summary

```bash
vuln-prioritizer attack coverage \
  --input data/sample_cves_mixed.txt \
  --attack-mapping-file data/attack/ctid_kev_enterprise_2025-07-28_attack-16.1_subset.json \
  --attack-technique-metadata-file data/attack/attack_techniques_enterprise_16.1_subset.json
```

### ATT&CK Navigator Layer Export

```bash
vuln-prioritizer attack navigator-layer \
  --input data/sample_cves_attack.txt \
  --attack-mapping-file data/attack/ctid_kev_enterprise_2025-07-28_attack-16.1_subset.json \
  --attack-technique-metadata-file data/attack/attack_techniques_enterprise_16.1_subset.json \
  --output docs/example_attack_navigator_layer.json
```

### Legacy Local CSV Mapping

```bash
vuln-prioritizer explain \
  --cve CVE-2021-44228 \
  --offline-attack-file data/optional_attack_to_cve.csv
```

## Important Options

- `--attack-source none|local-csv|ctid-json`
- `--attack-mapping-file PATH`
- `--attack-technique-metadata-file PATH`
- `--offline-attack-file PATH`
- `--no-attack`
- `--priority critical|high|medium|low`
- `--kev-only`
- `--min-cvss FLOAT`
- `--min-epss FLOAT`
- `--sort-by priority|epss|cvss|cve`
- `--max-cves N`

## Included Example Inputs and Artifacts

Inputs:

- [data/sample_cves.txt](data/sample_cves.txt)
- [data/sample_cves_attack.txt](data/sample_cves_attack.txt)
- [data/sample_cves_mixed.txt](data/sample_cves_mixed.txt)
- [data/optional_attack_to_cve.csv](data/optional_attack_to_cve.csv)
- [data/attack/ctid_kev_enterprise_2025-07-28_attack-16.1_subset.json](data/attack/ctid_kev_enterprise_2025-07-28_attack-16.1_subset.json)
- [data/attack/attack_techniques_enterprise_16.1_subset.json](data/attack/attack_techniques_enterprise_16.1_subset.json)

Artifacts:

- [docs/example_report.md](docs/example_report.md)
- [docs/example_compare.md](docs/example_compare.md)
- [docs/example_explain.json](docs/example_explain.json)
- [docs/example_attack_report.md](docs/example_attack_report.md)
- [docs/example_attack_compare.md](docs/example_attack_compare.md)
- [docs/example_attack_explain.json](docs/example_attack_explain.json)
- [docs/example_attack_coverage.md](docs/example_attack_coverage.md)
- [docs/example_attack_navigator_layer.json](docs/example_attack_navigator_layer.json)

## Documentation Map

- [docs/methodology.md](docs/methodology.md)
- [docs/concept.md](docs/concept.md)
- [docs/executive_summary.md](docs/executive_summary.md)
- [docs/evidence.md](docs/evidence.md)
- [docs/evidence/current_state_audit.md](docs/evidence/current_state_audit.md)
- [docs/reference_cve_prioritizer_gap_analysis.md](docs/reference_cve_prioritizer_gap_analysis.md)
- [docs/releases/v0.3.0.md](docs/releases/v0.3.0.md)

## Limitations

- Demo regeneration still depends on live NVD/EPSS/KEV responses.
- ATT&CK coverage exists only where CTID mappings exist.
- The checked-in ATT&CK fixtures are curated subsets, not the full upstream datasets.
- ATT&CK context is designed for explanation and prioritization context, not for asset-aware risk scoring.
