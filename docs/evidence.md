# Evidence Guide

This file describes the repository artifacts that are useful for demonstrations, evaluations, or project handoff.

## Visible Artifacts

- CLI: `vuln-prioritizer analyze`
- comparison mode: `vuln-prioritizer compare`
- detailed mode: `vuln-prioritizer explain --cve ...`
- example input: [data/sample_cves.txt](../data/sample_cves.txt)
- example report: [docs/example_report.md](./example_report.md)
- example comparison report: [docs/example_compare.md](./example_compare.md)
- example explain export: [docs/example_explain.json](./example_explain.json)
- tests: `pytest`
- methodology: [docs/methodology.md](./methodology.md)
- executive summary: [docs/executive_summary.md](./executive_summary.md)

## Recommended Evidence Collection

1. Screenshot of a successful CLI run
2. Screenshot or export of the Markdown report
3. Screenshot of the comparison command or the checked-in comparison report
4. Test run with passing results
5. Short method summary from `docs/methodology.md`
6. Executive summary from `docs/executive_summary.md`

## Comparison Evidence: CVSS-only vs Enriched

The repository now includes a checked-in comparison artifact instead of only a manual slide idea:

- [docs/example_compare.md](./example_compare.md)

That artifact is suitable for demos because it shows, per CVE:

- the `CVSS-only` baseline
- the enriched priority
- whether the ranking changed
- the deterministic reason for the change or lack of change

Expected presentation talking points:

- a KEV-listed CVE remains operationally urgent even if its CVSS score is only moderate
- a CVE with elevated EPSS can move above its CVSS-only baseline
- some technically severe issues move down when EPSS stays low and KEV is absent
