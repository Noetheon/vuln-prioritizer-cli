# vuln-prioritizer

`vuln-prioritizer` ist ein kleines Python-CLI zur Priorisierung bereits bekannter Schwachstellen. Das Tool liest CVE-Listen ein, reichert sie mit NVD-, EPSS- und KEV-Daten an und erzeugt daraus eine nachvollziehbare Priorisierung fuer den operativen Einsatz.

## Projektidee

Viele Teams priorisieren Schwachstellen immer noch hauptsaechlich ueber CVSS. Das greift operativ oft zu kurz:

- CVSS beschreibt technische Schwere, aber nicht aktuelle Ausnutzungswahrscheinlichkeit.
- EPSS liefert eine datengetriebene Ausnutzungswahrscheinlichkeit fuer die naechsten 30 Tage.
- KEV zeigt, ob eine Schwachstelle bereits real ausgenutzt wird.

Das CLI kombiniert diese Signale zu einem transparenten Ranking fuer Patch-, Mitigations- und Monitoring-Entscheidungen.

## Motivation

Das Projekt ist als sichtbares Sicherheitsartefakt fuer ein Hochschulmodul konzipiert:

- lauffaehiges CLI als Hauptartefakt
- nachvollziehbare Methodik
- technische Tiefe durch API-Integration, Parsing und Testabdeckung
- Management- bzw. CISO-Perspektive durch priorisierte Handlungsempfehlungen

## Datenquellen

- NVD CVE API 2.0: `https://services.nvd.nist.gov/rest/json/cves/2.0`
- NVD API 2.0 Transition Guide: `https://nvd.nist.gov/general/news/api-20-announcements`
- FIRST EPSS API: `https://api.first.org/data/v1/epss`
- CISA KEV Catalog: `https://www.cisa.gov/known-exploited-vulnerabilities-catalog`
- CISA KEV Mirror: `https://github.com/cisagov/kev-data`

Optionales ATT&CK-Mapping ist bewusst nicht Teil des MVP. Falls genutzt, dann nur mit einer lokalen Mapping-CSV.

## Installation

### Voraussetzungen

- Python 3.11 oder 3.12

### Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -e .
```

Optional kann ein NVD-API-Key per `.env` gesetzt werden:

```bash
cp .env.example .env
```

Danach `NVD_API_KEY` in `.env` eintragen.

## Nutzung

### Basislauf

```bash
vuln-prioritizer analyze --input data/sample_cves.txt
```

### Markdown-Report erzeugen

```bash
vuln-prioritizer analyze \
  --input data/sample_cves.txt \
  --output docs/example_report.md \
  --format markdown
```

### Einzelne CVE erklaeren

```bash
vuln-prioritizer explain --cve CVE-2021-44228
```

### Einzelne CVE als JSON exportieren

```bash
vuln-prioritizer explain \
  --cve CVE-2021-44228 \
  --output explain.json \
  --format json
```

### JSON-Export erzeugen

```bash
vuln-prioritizer analyze \
  --input data/sample_cves.txt \
  --output report.json \
  --format json
```

### Wichtige Optionen

- `--input`: TXT- oder CSV-Datei mit CVEs
- `--output`: Zieldatei fuer Markdown- oder JSON-Ausgabe
- `--format markdown|json|table`: Ausgabemodus
- `--no-attack`: ATT&CK-Kontext explizit deaktivieren
- `--max-cves N`: Analyse nach `N` eindeutigen CVEs abschneiden
- `--offline-kev-file PATH`: lokale KEV-JSON- oder CSV-Datei nutzen
- `--offline-attack-file PATH`: lokale ATT&CK-Mapping-CSV nutzen
- `--nvd-api-key-env NAME`: alternativen Umgebungsvariablennamen fuer den NVD-Key setzen
- `--no-cache`: Dateicache deaktivieren
- `--cache-dir PATH`: alternatives Cache-Verzeichnis setzen
- `--cache-ttl-hours N`: Cache-TTL in Stunden setzen

## Beispielinput

TXT:

```text
CVE-2021-44228
CVE-2022-22965
CVE-2023-44487
CVE-2024-3094
```

CSV:

```csv
cve
CVE-2021-44228
CVE-2022-22965
CVE-2023-44487
CVE-2024-3094
```

## Beispieloutput

Der Terminal-Output zeigt immer eine kompakte Tabelle. Ein vollstaendiger Beispielreport wird unter [docs/example_report.md](docs/example_report.md) abgelegt.
Fuer den neuen Detailmodus liegt ein Beispiel-Export unter [docs/example_explain.json](docs/example_explain.json).

## Priorisierungslogik

Die MVP-Regeln sind absichtlich einfach und dokumentierbar:

- `Critical`: KEV oder `(EPSS >= 0.70 und CVSS >= 7.0)`
- `High`: `EPSS >= 0.40` oder `CVSS >= 9.0`
- `Medium`: `CVSS >= 7.0` oder `EPSS >= 0.10`
- `Low`: alles andere

ATT&CK beeinflusst im MVP nicht die Prioritaetsklasse. Optionaler ATT&CK-Kontext wird nur zur Ergaenzung der Begruendung verwendet.

## Grenzen des Tools

- kein Schwachstellenscanner
- keine Asset Discovery
- keine Datenbank
- keine Weboberflaeche
- keine Ticketing- oder SIEM-Integration
- keine heuristische oder LLM-basierte CVE-zu-ATT&CK-Zuordnung
- keine Live-ATT&CK/TAXII-Integration im MVP

Fehlende oder unvollstaendige Quelldaten werden als Warnungen behandelt. Das Tool versucht, trotzdem einen nutzbaren Report zu erzeugen.

## Tests

```bash
pytest
```

Die Tests decken Parser, Provider-Parsing, Priorisierungslogik, Reporter und einen CLI-End-to-End-Lauf mit gemockten Providern ab.

## Caching

Standardmaessig nutzt das Tool einen kleinen Dateicache unter `.cache/vuln-prioritizer`. Der Cache beschleunigt wiederholte Demo- und Analyse-Laeufe fuer:

- NVD-Einzelabfragen
- EPSS-CVE-Daten
- den online geladenen KEV-Katalog

Der Cache ist optional und kann mit `--no-cache` deaktiviert werden.

## Roadmap

### MVP

- TXT- und CSV-Input
- NVD-, EPSS- und KEV-Anreicherung
- feste Priorisierungsregeln
- Terminal-Tabelle
- Markdown- und JSON-Output

### V1.1

- bessere CLI-Zusammenfassungen
- Vergleichsansicht `CVSS-only vs enriched`
- erweiterte Filteroptionen

### V1.2

- optionales ATT&CK-Mapping mit lokaler Datei
- konfigurierbare Schwellwerte, sobald eine saubere Policy-Struktur vorliegt

### V1.3

- weitere Cache-Strategien
- erweiterter `explain`-Befehl mit mehr Exportformaten oder Vergleichsansichten
