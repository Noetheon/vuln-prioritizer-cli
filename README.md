# vuln-prioritizer

[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Status: v1.0.0](https://img.shields.io/badge/status-v1.0.0-brightgreen)](./CHANGELOG.md)
[![Quality: local-first](https://img.shields.io/badge/quality-local--first-informational)](#development)

`vuln-prioritizer` is a Python CLI for prioritizing known CVEs. It accepts plain CVE lists plus scanner/SBOM JSON inputs, enriches them with NVD, FIRST EPSS, and CISA KEV data, and then adds optional ATT&CK, asset-context, and VEX-aware explanatory layers without replacing the transparent base score.

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

The differentiator that started with the ATT&CK extension remains the same: ATT&CK-aware vulnerability context is based on official CTID Mappings Explorer artifacts, not on heuristic or LLM-generated CVE-to-ATT&CK guesses.

The current stable release adds the surrounding workflow surface that security teams need in practice:

- scanner- and SBOM-native JSON inputs
- occurrence-level provenance
- asset context and policy profiles
- OpenVEX and CycloneDX VEX support
- SARIF output and CI/CD-friendly exit codes
- static HTML rendering from saved analysis JSON
- a composite GitHub Action and published JSON schemas

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

## Current Methodology

The base priority model is:

- transparent
- rule-based
- still rooted in `CVSS + EPSS + KEV`

ATT&CK in the current release is:

- optional
- local-file based
- explicit about provenance
- separate from the main priority score

ATT&CK in the current release is not:

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

Asset context and VEX follow the same rule:

- asset context changes explanatory recommendation text, not the base `priority_label`
- VEX is occurrence-based and exact-match only
- VEX can suppress findings from the default visible list, but it does not create a second opaque score

## Installation

### Requirements

- Python 3.11 or 3.12

### Tagged Install with `pipx`

If you want an isolated CLI install without a local virtualenv, install a tagged release directly from GitHub:

```bash
pipx install git+https://github.com/Noetheon/vuln-prioritizer-cli.git@v1.0.0
vuln-prioritizer --help
```

Tagged releases are also wired for GitHub Releases and PyPI publishing in `.github/workflows/release.yml`. If a matching PyPI release is available, `pipx install vuln-prioritizer` is the intended stable public path.

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

## Quickstart

### Fastest Local Run

```bash
vuln-prioritizer analyze --input data/sample_cves.txt
```

That baseline flow enriches the sample list with live NVD, EPSS, and KEV context.

### ATT&CK-aware Demo Run

```bash
vuln-prioritizer analyze \
  --input data/sample_cves_mixed.txt \
  --format markdown \
  --output docs/example_attack_report.md \
  --attack-source ctid-json \
  --attack-mapping-file data/attack/ctid_kev_enterprise_2025-07-28_attack-16.1_subset.json \
  --attack-technique-metadata-file data/attack/attack_techniques_enterprise_16.1_subset.json
```

That uses the checked-in CTID and ATT&CK fixture subsets to add local ATT&CK context on top of the live enrichment flow.

### Scanner-native Analyze with VEX

```bash
vuln-prioritizer analyze \
  --input data/input_fixtures/trivy_report.json \
  --input-format trivy-json \
  --vex-file data/input_fixtures/openvex_statements.json \
  --format json \
  --output analysis.json
```

### Static HTML from Saved Analysis JSON

```bash
vuln-prioritizer report html \
  --input analysis.json \
  --output report.html
```

### Cache Maintenance and Data Transparency

```bash
vuln-prioritizer data status \
  --attack-mapping-file data/attack/ctid_kev_enterprise_2025-07-28_attack-16.1_subset.json \
  --attack-technique-metadata-file data/attack/attack_techniques_enterprise_16.1_subset.json
```

```bash
vuln-prioritizer data update --source kev

vuln-prioritizer data update \
  --source nvd \
  --source epss \
  --input data/sample_cves.txt

vuln-prioritizer data verify \
  --input data/sample_cves_mixed.txt \
  --attack-mapping-file data/attack/ctid_kev_enterprise_2025-07-28_attack-16.1_subset.json \
  --attack-technique-metadata-file data/attack/attack_techniques_enterprise_16.1_subset.json
```

## Development

Local validation is the primary workflow:

```bash
make install
make check
```

Hosted GitHub workflows are currently optional. The recommended local equivalent for CI plus packaging metadata is:

```bash
make workflow-check
```

Release-oriented validation:

```bash
make release-check
```

`make release-check` is the stricter local superset. It regenerates demo artifacts before running the packaging checks.

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

## Public Demo Artifacts

Use these checked-in artifacts when you want to review the project without rerunning the live providers first:

- Baseline report: [docs/example_report.md](docs/example_report.md)
- Baseline comparison: [docs/example_compare.md](docs/example_compare.md)
- Baseline explain output: [docs/example_explain.json](docs/example_explain.json)
- ATT&CK report: [docs/example_attack_report.md](docs/example_attack_report.md)
- ATT&CK comparison: [docs/example_attack_compare.md](docs/example_attack_compare.md)
- ATT&CK explain output: [docs/example_attack_explain.json](docs/example_attack_explain.json)
- ATT&CK coverage summary: [docs/example_attack_coverage.md](docs/example_attack_coverage.md)
- ATT&CK Navigator layer: [docs/example_attack_navigator_layer.json](docs/example_attack_navigator_layer.json)

For a public walkthrough or recording plan, start with:

- [docs/evidence.md](docs/evidence.md)
- [docs/evidence/screenshot_capture_list.md](docs/evidence/screenshot_capture_list.md)
- [docs/releases/v1.0.0.md](docs/releases/v1.0.0.md)

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
- `--input-format auto|cve-list|trivy-json|grype-json|cyclonedx-json|spdx-json|dependency-check-json|github-alerts-json`
- `--asset-context PATH`
- `--policy-profile NAME`
- `--policy-file PATH`
- `--target-kind generic|image|repository|filesystem|host`
- `--target-ref TEXT`
- `--vex-file PATH`
- `--show-suppressed`
- `--fail-on low|medium|high|critical`
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
- [data/input_fixtures/trivy_report.json](data/input_fixtures/trivy_report.json)
- [data/input_fixtures/grype_report.json](data/input_fixtures/grype_report.json)
- [data/input_fixtures/cyclonedx_bom.json](data/input_fixtures/cyclonedx_bom.json)
- [data/input_fixtures/spdx_bom.json](data/input_fixtures/spdx_bom.json)
- [data/input_fixtures/dependency_check_report.json](data/input_fixtures/dependency_check_report.json)
- [data/input_fixtures/github_alerts_export.json](data/input_fixtures/github_alerts_export.json)
- [data/input_fixtures/openvex_statements.json](data/input_fixtures/openvex_statements.json)
- [data/input_fixtures/cyclonedx_vex.json](data/input_fixtures/cyclonedx_vex.json)
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
- [docs/examples/example_pr_comment.md](docs/examples/example_pr_comment.md)
- [docs/examples/example_results.sarif](docs/examples/example_results.sarif)
- [docs/examples/example_report.html](docs/examples/example_report.html)

## Documentation Map

- [docs/methodology.md](docs/methodology.md)
- [docs/architecture.md](docs/architecture.md)
- [docs/contracts.md](docs/contracts.md)
- [docs/support_matrix.md](docs/support_matrix.md)
- [docs/schemas/analysis-report.schema.json](docs/schemas/analysis-report.schema.json)
- [docs/schemas/compare-report.schema.json](docs/schemas/compare-report.schema.json)
- [docs/schemas/explain-report.schema.json](docs/schemas/explain-report.schema.json)
- [docs/concept.md](docs/concept.md)
- [docs/executive_summary.md](docs/executive_summary.md)
- [docs/evidence.md](docs/evidence.md)
- [docs/evidence/current_state_audit.md](docs/evidence/current_state_audit.md)
- [docs/integrations/reporting_and_ci.md](docs/integrations/reporting_and_ci.md)
- [docs/reference_cve_prioritizer_gap_analysis.md](docs/reference_cve_prioritizer_gap_analysis.md)
- [docs/roadmap.md](docs/roadmap.md)
- [docs/releases/v1.0.0.md](docs/releases/v1.0.0.md)

## Troubleshooting

### The CLI cannot find or execute `vuln-prioritizer`

- If you used `pipx`, run `pipx ensurepath` and start a new shell.
- If you used a local virtualenv, make sure it is activated before calling the command.
- You can always fall back to `python3 -m vuln_prioritizer.cli --help`.

### Live enrichment is slow or partially missing

- NVD, EPSS, and KEV are queried from public live sources during normal runs.
- Temporary rate limits or upstream errors can reduce coverage for a single run.
- Configure `NVD_API_KEY` in `.env` if you need a more reliable NVD experience.

### ATT&CK output is empty or only shows `Unmapped`

- ATT&CK is optional and local-file based in the current release.
- Use `--attack-source ctid-json` together with both local ATT&CK files.
- Be explicit when a CVE is unmapped; CTID coverage is intentionally partial and deterministic.

### Asset context or VEX matching looks empty

- Asset context joins only on the exact pair `(target_kind, target_ref)`.
- VEX matching is exact-match and occurrence-based.
- For `explain`, provide `--target-kind` and `--target-ref` if you expect asset or VEX context to attach to the single inline occurrence.

### The checked-in examples differ from a fresh run

- Demo regeneration still depends on live NVD, EPSS, and KEV responses.
- The ATT&CK inputs are pinned local fixtures; the network-backed provider fields may still drift over time.

## Data Source FAQ

### Does this tool scan hosts, containers, or repositories?

No. `vuln-prioritizer` is a CLI for known CVEs. It prioritizes and explains supplied CVE identifiers; it does not discover vulnerabilities by itself.

### Which data is live and which data is local?

- NVD, FIRST EPSS, and CISA KEV are the normal live enrichment sources.
- ATT&CK support is local-file based and uses explicit CTID/MITRE artifacts.
- The repository includes small ATT&CK fixture subsets under `data/attack/` for demos and tests.
- Scanner/SBOM inputs, asset context, and VEX fixtures under `data/input_fixtures/` are deterministic local artifacts for tests and demos.

### Does ATT&CK change the main priority score?

No. The default priority label remains based on CVSS, EPSS, and KEV. ATT&CK adds context, rationale, and reporting detail.

### Why is ATT&CK coverage incomplete?

The project only uses explicit CTID mappings. If CTID does not map a CVE, the tool reports it as `Unmapped` rather than inventing a technique guess.

### Why are the example reports checked in?

They make the repo easier to evaluate offline, support demos and handoffs, and provide stable public artifacts even when live providers fluctuate.

## Limitations

- Demo regeneration still depends on live NVD/EPSS/KEV responses.
- ATT&CK coverage exists only where CTID mappings exist.
- The checked-in ATT&CK fixtures are curated subsets, not the full upstream datasets.
- ATT&CK context is designed for explanation and prioritization context, not for asset-aware risk scoring.
- Asset context joins are exact only; there is no fuzzy target matching.
- VEX support is JSON-only and exact-match oriented in the current release.
