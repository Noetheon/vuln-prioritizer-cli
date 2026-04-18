---
name: vuln-prioritizer-maintainer
description: Use when working on the vuln-prioritizer repository to preserve scope, run the correct local checks, regenerate demo artifacts, and avoid unsupported CVE-to-ATT&CK behavior.
---

# vuln-prioritizer-maintainer

Use this skill when editing the `vuln-prioritizer` repository.

## Scope rules

- The project prioritizes known CVEs. It is not a scanner.
- Official/public sources only: NVD, FIRST EPSS, CISA KEV.
- ATT&CK stays optional and must not use heuristic or LLM-generated CVE mappings.
- Keep the CLI small, readable, and demo-ready.

## Local-first workflow

Use local validation instead of relying on GitHub Actions.

Primary commands:

```bash
make install
make check
make demo-report
make demo-explain
```

## Change expectations

- Parser/provider/scoring changes require `pytest`.
- User-visible output changes require regenerating:
  - `docs/example_report.md`
  - `docs/example_explain.json`
- Keep tests mocked for provider behavior; do not make test success depend on live APIs.
- Keep local handoff notes untracked:
  - `Applied_Security_Project_Python_CLI_Notion_Pack.md`
  - `Codex_Handoff_Vuln_Prioritizer.md`

## File orientation

- CLI surface: `src/vuln_prioritizer/cli.py`
- Provider integrations: `src/vuln_prioritizer/providers/`
- Ranking logic: `src/vuln_prioritizer/scoring.py`
- Report generation: `src/vuln_prioritizer/reporter.py`
- Maintainer docs: `README.md`, `CONTRIBUTING.md`, `SECURITY.md`
