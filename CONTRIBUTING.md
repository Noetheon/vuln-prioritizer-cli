# Contributing

Thanks for contributing to `vuln-prioritizer`.

## Scope Guardrails

- This project prioritizes known CVEs. It is not a vulnerability scanner.
- Prefer official/public sources only: NVD, FIRST EPSS, CISA KEV.
- Do not add heuristic or LLM-generated CVE-to-ATT&CK mappings.
- Keep ATT&CK optional and offline-file-based unless the project scope changes explicitly.

## Local Development

```bash
python3 -m venv .venv
source .venv/bin/activate
make install
```

## Local Quality Gate

GitHub Actions are intentionally not required for day-to-day development. Run all checks locally:

```bash
make check
```

This runs:

- `ruff format --check`
- `ruff check`
- `mypy src`
- `pytest`

## Demo Artifacts

When output changes materially, regenerate the checked-in demo artifacts:

```bash
make demo-report
make demo-explain
```

## Commit Discipline

- Keep commits focused.
- Update tests with behavioral changes.
- Update `CHANGELOG.md` for user-visible or maintainer-relevant changes when appropriate.
- Do not commit local secrets or local handoff notes.
- Prefer deterministic mocks in tests over live network calls.
