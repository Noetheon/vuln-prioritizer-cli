# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project aims to follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed

- Maintained local-first validation as the primary development path while keeping release metadata and CI aligned with the codebase.

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
