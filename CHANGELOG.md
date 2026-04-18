# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project aims to follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Post-enrichment filters for `analyze`: repeatable priority filters, `--kev-only`, `--min-cvss`, `--min-epss`, and `--sort-by`.
- New `compare` command for deterministic `CVSS-only vs enriched` reporting in terminal, Markdown, and JSON form.
- Checked-in comparison artifact support via `make demo-compare`.

### Changed

- Expanded run summaries with filter metadata, filtered-out counts, and NVD/EPSS/KEV coverage counts.
- Updated project documentation to explain comparison logic and the new reporting surface.
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
