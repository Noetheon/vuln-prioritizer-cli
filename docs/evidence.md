# Evidence Guide

This file describes the repository artifacts that are useful for demonstrations, evaluations, or project handoff.

## Visible Artifacts

- CLI: `vuln-prioritizer analyze`
- detailed mode: `vuln-prioritizer explain --cve ...`
- example input: [data/sample_cves.txt](../data/sample_cves.txt)
- example report: [docs/example_report.md](./example_report.md)
- example explain export: [docs/example_explain.json](./example_explain.json)
- tests: `pytest`
- methodology: [docs/methodology.md](./methodology.md)
- executive summary: [docs/executive_summary.md](./executive_summary.md)

## Recommended Evidence Collection

1. Screenshot of a successful CLI run
2. Screenshot or export of the Markdown report
3. Test run with passing results
4. Short method summary from `docs/methodology.md`
5. Executive summary from `docs/executive_summary.md`

## Comparison Idea: CVSS-only vs Enriched

A simple manual comparison for presentations or evaluations:

| View | Basis | Message |
| --- | --- | --- |
| CVSS-only | CVSS from NVD only | high severity, but limited exploit context |
| Enriched | CVSS + EPSS + KEV | better operational remediation order |

Expected examples:

- a KEV-listed CVE remains operationally urgent even if its CVSS score is only moderate
- a CVE with high EPSS and high CVSS outranks issues that are technically severe but currently less relevant
