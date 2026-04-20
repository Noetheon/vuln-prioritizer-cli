# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project aims to follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed

- Maintained local-first validation as the primary development path while keeping release metadata and CI aligned with the codebase.

## [0.3.0] - 2026-04-20

### Added

- CTID Mappings Explorer JSON support for local ATT&CK enrichment with pinned fixture coverage.
- Local ATT&CK technique metadata loading with tactic, URL, and revoked/deprecated flags.
- ATT&CK-aware `analyze`, `compare`, and `explain` outputs plus `attack validate`, `attack coverage`, and `attack navigator-layer`.
- Checked-in ATT&CK sample inputs, example artifacts, and local demo targets for the V0.3 workflow.
- Current-state audit and reference gap-analysis documentation for the ATT&CK extension release.

### Changed

- Expanded the ATT&CK data model from a flat CSV note to structured mappings, technique metadata, relevance labels, and report summaries.
- Added CVSS version tracking so NVD output shows which CVSS family produced the selected score.
- Kept the primary priority calculation rooted in CVSS, EPSS, and KEV while making ATT&CK a separate contextual signal.
- Updated repository positioning, methodology, evidence guidance, and release materials around the CTID/ATT&CK differentiator.

## [0.2.2] - 2026-04-19

### Added

- `CODE_OF_CONDUCT.md` and `.editorconfig` for stronger public-repository maintenance defaults.
- Direct cache tests covering round-trip, expiry, and invalid-cache-file handling.
- A `py.typed` package marker so typed-package consumers can rely on shipped inline type information.

### Changed

- Upgraded packaging metadata with classifiers, project URLs, and contributor-oriented author metadata.
- Switched package licensing metadata to SPDX-style fields for cleaner modern builds.
- Switched local packaging verification from wheel-only builds to source-and-wheel builds plus `twine check`.

## [0.2.1] - 2026-04-18

### Added

- `make package` and `make release-check` for repeatable local release verification.
- GitHub pull request and issue templates for public OSS maintenance.
- Dedicated release notes document for the current patch release.

### Changed

- Regenerated demo artifacts after the final maintainer-facing release sweep.
- Tightened contributor guidance around release-oriented local validation.

## [0.2.0] - 2026-04-18

### Added

- Post-enrichment filters for `analyze`: repeatable priority filters, `--kev-only`, `--min-cvss`, `--min-epss`, and `--sort-by`.
- New `compare` command for deterministic `CVSS-only vs enriched` reporting in terminal, Markdown, and JSON form.
- Configurable enriched priority thresholds via CLI policy override flags.
- Richer `explain` output with CVSS-only baseline comparison metadata and reasoning.
- Optional ATT&CK mapping template file plus stronger local CSV parsing and validation.
- Slim GitHub Actions CI workflow mirroring `make check`.

### Changed

- Expanded run summaries with filter metadata, filtered-out counts, NVD/EPSS/KEV/ATT&CK coverage, and policy override visibility.
- Updated project documentation to explain comparison logic, policy overrides, ATT&CK mapping usage, and the new reporting surface.
- Polished the README for open-source readiness with badges, a clearer project narrative, and maintainer-oriented navigation.

## [0.1.0] - 2026-04-18

### Added

- Initial `vuln-prioritizer` CLI with `analyze` and `explain` commands.
- NVD, EPSS, and CISA KEV enrichment providers.
- Fixed MVP priority rules with deterministic rationale and action guidance.
- Markdown and JSON outputs plus checked-in example artifacts.
- Optional local ATT&CK mapping support without heuristic CVE-to-ATT&CK inference.
- Local file caching for repeated runs.
- Local-first quality gates via `Makefile`, `ruff`, `mypy`, `pytest`, and `pre-commit`.
- Maintainer and open-source preparation files including `LICENSE`, `CONTRIBUTING.md`, and `SECURITY.md`.
