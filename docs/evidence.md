# Evidence Guide

Diese Datei beschreibt die Artefakte, die fuer das Hochschulprojekt direkt nutzbar sind.

## Sichtbare Artefakte

- CLI: `vuln-prioritizer analyze`
- Detailansicht: `vuln-prioritizer explain --cve ...`
- Beispielinput: [data/sample_cves.txt](../data/sample_cves.txt)
- Beispielreport: [docs/example_report.md](./example_report.md)
- Beispiel-Explain-Export: [docs/example_explain.json](./example_explain.json)
- Tests: `pytest`
- Methodik: [docs/methodology.md](./methodology.md)
- Executive Summary: [docs/executive_summary.md](./executive_summary.md)

## Empfohlene Evidence-Sammlung

1. Screenshot eines erfolgreichen CLI-Laufs
2. Screenshot oder Export des Markdown-Reports
3. Testlauf mit gruenen Ergebnissen
4. kurzer Methodenhinweis aus `docs/methodology.md`
5. Executive-Sicht aus `docs/executive_summary.md`

## Vergleichsidee: CVSS-only vs enriched

Ein einfacher manueller Vergleich fuer die Praesentation:

| Sicht | Grundlage | Aussage |
| --- | --- | --- |
| CVSS-only | nur CVSS aus NVD | hohe Schwere, aber ohne Exploit-Kontext |
| Enriched | CVSS + EPSS + KEV | bessere operative Reihenfolge fuer Patch und Mitigation |

Beispielhafte Erwartung:

- eine KEV-gelistete CVE wird auch bei mittlerem CVSS operativ hoch priorisiert
- eine CVE mit hoher EPSS und hohem CVSS rutscht vor rein theoretisch schwere, aber aktuell weniger relevante Eintraege
