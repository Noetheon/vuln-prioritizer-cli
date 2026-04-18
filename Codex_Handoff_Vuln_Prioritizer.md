# Codex Handoff Package
## Applied Security Project
### Python CLI zur Priorisierung bekannter Schwachstellen mit CVSS, EPSS, KEV und optionalem ATT&CK-Kontext

Stand: 18.04.2026

---

# 1. Ziel dieses Dokuments

Dieses Dokument ist die technische und fachliche Übergabe an einen Coding Agent wie Codex.
Es soll sicherstellen, dass das Projekt fokussiert, prüfungstauglich und vollständig umsetzbar bleibt.

Wichtige Leitidee:
Das Projekt ist **kein Scanner für neue Schwachstellen**, sondern ein **Kommandozeilenwerkzeug zur Priorisierung bekannter CVEs**.

Es soll:
- CVE-Listen einlesen
- belastbare öffentliche Datenquellen abrufen
- Priorisierung nachvollziehbar berechnen
- technische und managementseitige Ausgaben erzeugen
- klein genug für das Hochschulmodul bleiben

---

# 2. Hochschulkontext und Randbedingungen

Das Modul erwartet laut Vorlesungsunterlagen:
- ein sicherheitsrelevantes Artefakt
- sichtbare Evidence
- technische Tiefe
- eine Management- bzw. CISO-Perspektive
- ein Thema, das in 4 bis 6 Wochen realistisch umsetzbar ist

Erlaubt sind laut Vorlesung unter anderem:
- Tooling
- Analyse
- Dokumentation
- Hardening
- Reifegrad- und Governance-Beiträge

Für dieses Projekt bedeutet das:
- ein lauffähiges Python CLI ist das sichtbare Artefakt
- Reports, Screenshots, Tests und Beispielausgaben sind Evidence
- die CISO-Perspektive ist die bessere Priorisierung begrenzter Patch- und Mitigationsressourcen

---

# 3. Fachliche Projektdefinition

## Arbeitstitel
Python CLI zur operativen Priorisierung bekannter Schwachstellen mit CVSS, EPSS, KEV und optionalem ATT&CK-Kontext

## Kurzbeschreibung
Das Tool liest eine Liste von CVEs ein und reichert sie mit öffentlich verfügbaren Sicherheitsdaten an.
Der Fokus liegt auf einer **nachvollziehbaren Priorisierung**, nicht auf einem komplexen Enterprise-System.

## Primärer Nutzen
- strukturierte operative Priorisierung
- bessere Entscheidungsunterstützung für Schwachstellenbearbeitung
- klarer Vergleich zwischen einfacher und angereicherter Priorisierung
- gute Übersetzbarkeit in eine Management-Story

---

# 4. Zwingende Projektgrenzen

## Muss enthalten
1. CLI
2. Input-Datei mit CVEs
3. NVD-Integration für CVE-Metadaten und CVSS
4. EPSS-Integration
5. KEV-Integration
6. Prioritätslogik
7. Markdown-Report
8. README
9. Tests
10. Beispiel-Daten

## Darf enthalten
1. JSON-Export
2. CSV-Export
3. optionale ATT&CK-Erweiterung
4. Caching
5. Konfigurierbare Schwellenwerte

## Darf NICHT Teil des MVP sein
1. Weboberfläche
2. Datenbank
3. Benutzerverwaltung
4. SIEM-Integration
5. komplexe Authentifizierung
6. Containerisierung als Hauptziel
7. Dashboard
8. Asset Discovery
9. Netzwerk-Scanning
10. automatische Ticket-Erstellung

---

# 5. Verifizierte Primärquellen und empfohlene Nutzung

## 5.1 NVD
NVD empfiehlt die 2.0 APIs als bevorzugten Weg, um aktuell zu bleiben.
Die CVE API Basis lautet:
`https://services.nvd.nist.gov/rest/json/cves/2.0`

Wichtige Punkte:
- `cveId` kann für gezielte Abfragen verwendet werden
- Pagination erfolgt mit `startIndex` und `resultsPerPage`
- Standard und Maximum für `resultsPerPage` liegt bei 2000
- API Keys werden über den Header `apiKey` übergeben
- ohne API Key gibt es reduzierte Request-Limits

Empfehlung für dieses Projekt:
- nur gezielte Einzel- oder Batch-Abfragen per `cveId`
- API-Key optional über Environment Variable
- robuste Fehlerbehandlung und Fallback ohne Key

## 5.2 FIRST EPSS
EPSS schätzt die Wahrscheinlichkeit, dass eine veröffentlichte CVE in den nächsten 30 Tagen in der Praxis ausgenutzt wird.

API Basis:
`https://api.first.org/data/v1/epss`

Wichtige Punkte:
- Einzelabfragen per `cve=...`
- Batch-Abfragen per kommaseparierter Liste möglich
- historische Daten sind verfügbar
- CSV Dumps existieren ebenfalls

Empfehlung:
- Batch-Abfragen für mehrere CVEs in einem Request
- Wert `epss` und `percentile` erfassen
- bei Nichtvorhandensein sauber `None` oder `N.A.` setzen

## 5.3 CISA KEV
CISA beschreibt den KEV Katalog als maßgebliche Quelle für bekannte real ausgenutzte Schwachstellen.
Das offizielle `cisagov/kev-data` Repository spiegelt den Katalog und enthält:
- CSV
- JSON
- JSON-Schema

Empfehlung:
- KEV JSON oder CSV beim Lauf laden
- per CVE-ID auf Membership prüfen
- nur Boolean plus optionale Metadaten wie Vendor, Product, Date Added, Required Action in den Report übernehmen

## 5.4 MITRE ATT&CK
MITRE ATT&CK ist eine offen verfügbare Wissensbasis real beobachteter Angreifer-Taktiken und -Techniken.
ATT&CK-Daten sind in STIX verfügbar und über eine offizielle TAXII-Schnittstelle zugänglich.

## 5.5 CTID Mappings Explorer und ATT&CK-zu-CVE-Methodik
Wichtiger Punkt:
Für dieses Projekt soll **keine unhaltbare Eigenlogik “CVE -> ATT&CK” erfunden** werden.

Stattdessen gibt es vom Center for Threat-Informed Defense eine offizielle Methodik:
- „Mapping ATT&CK to CVE for Impact“
- Ziel: ATT&CK-Techniken zur Beschreibung der Auswirkungen von CVEs nutzen
- frühere Mappings lagen im Archiv-Repo `attack_to_cve`
- aktuelle Mappings sind in das Mappings Explorer Projekt migriert

Empfehlung:
ATT&CK **nicht im MVP erzwingen**.
Wenn ATT&CK eingebaut wird, dann nur so:
- Option A: mit der historischen, offen verfügbaren CSV aus `attack_to_cve`
- Option B: mit einem lokal eingecheckten, dokumentierten Export aus Mappings Explorer
- Option C: als manueller, kleiner Mapping-Prototyp für wenige Beispiel-CVEs

Wichtig:
ATT&CK ist **optionale Erweiterung**, kein MVP-Muss.

---

# 6. Forschungsbasierte Designentscheidung

## Empfohlener MVP
Das MVP soll nur diese drei Signalsysteme produktiv nutzen:
1. CVSS aus NVD
2. EPSS aus FIRST
3. KEV-Status aus CISA

## Warum?
Diese drei Signale sind:
- offiziell
- stabil
- nachvollziehbar
- gut dokumentiert
- direkt technisch integrierbar
- ausreichend, um einen starken Projektnutzen zu zeigen

## ATT&CK-Entscheidung
ATT&CK wird **bewusst entkoppelt** und nur als Phase 2 behandelt.

Begründung:
- fachlich sinnvoll, aber methodisch heikler
- sollte auf offizieller CTID-Methodik beruhen
- darf das MVP nicht gefährden

---

# 7. Produktvision

Das Tool soll aus einer Eingabeliste von CVEs eine strukturierte, priorisierte Ergebnisliste erzeugen.

## Eingabe
- Textdatei mit einer CVE pro Zeile
oder
- CSV-Datei mit Spalte `cve`

## Ausgabe
- Terminal-Tabelle
- Markdown-Report
- optional JSON

## Kernoutput pro CVE
- CVE-ID
- kurze Beschreibung
- CVSS-Score
- CVSS-Severity
- EPSS-Wert
- EPSS-Percentile
- KEV-Status
- optional ATT&CK-Techniken
- Prioritätsklasse
- Begründung
- Handlungsempfehlung

---

# 8. Projektarchitektur

## Empfohlene Verzeichnisstruktur

```text
vuln-prioritizer-cli/
├─ README.md
├─ pyproject.toml
├─ requirements.txt
├─ .env.example
├─ data/
│  ├─ sample_cves.txt
│  ├─ sample_cves.csv
│  └─ optional_attack_to_cve.csv
├─ src/
│  └─ vuln_prioritizer/
│     ├─ __init__.py
│     ├─ cli.py
│     ├─ config.py
│     ├─ models.py
│     ├─ parser.py
│     ├─ scoring.py
│     ├─ reporter.py
│     ├─ utils.py
│     ├─ providers/
│     │  ├─ __init__.py
│     │  ├─ nvd.py
│     │  ├─ epss.py
│     │  ├─ kev.py
│     │  └─ attack.py
│     └─ services/
│        ├─ __init__.py
│        ├─ enrichment.py
│        └─ prioritization.py
├─ tests/
│  ├─ test_parser.py
│  ├─ test_scoring.py
│  ├─ test_reporter.py
│  └─ test_providers.py
└─ docs/
   ├─ concept.md
   ├─ evidence.md
   ├─ executive_summary.md
   └─ methodology.md
```

---

# 9. Datenmodell

Codex soll saubere Python-Dataclasses oder Pydantic-Modelle verwenden.

## `InputItem`
- `cve_id: str`

## `NvdData`
- `cve_id: str`
- `description: str | None`
- `cvss_base_score: float | None`
- `cvss_severity: str | None`
- `published: str | None`
- `last_modified: str | None`
- `cwes: list[str]`
- `references: list[str]`

## `EpssData`
- `cve_id: str`
- `epss: float | None`
- `percentile: float | None`
- `date: str | None`

## `KevData`
- `cve_id: str`
- `in_kev: bool`
- `vendor_project: str | None`
- `product: str | None`
- `date_added: str | None`
- `required_action: str | None`
- `due_date: str | None`

## `AttackData`
- `cve_id: str`
- `attack_techniques: list[str]`
- `attack_tactics: list[str]`
- `attack_note: str | None`

## `PrioritizedFinding`
- `cve_id: str`
- `description: str | None`
- `cvss_base_score: float | None`
- `cvss_severity: str | None`
- `epss: float | None`
- `epss_percentile: float | None`
- `in_kev: bool`
- `attack_techniques: list[str]`
- `priority_label: str`
- `priority_rank: int`
- `rationale: str`
- `recommended_action: str`

---

# 10. CLI-Spezifikation

## Primärer Befehl
```bash
vuln-prioritizer analyze --input data/sample_cves.txt --output report.md
```

## Pflichtargumente
- `--input`

## Optionale Argumente
- `--output`
- `--format markdown|json|table`
- `--no-attack`
- `--epss-threshold`
- `--cvss-threshold`
- `--kev-priority-override`
- `--max-cves`
- `--offline-kev-file`
- `--offline-attack-file`
- `--nvd-api-key-env NVD_API_KEY`

## Beispiel
```bash
vuln-prioritizer analyze   --input data/sample_cves.txt   --output report.md   --format markdown   --no-attack
```

## Zweiter optionaler Befehl
```bash
vuln-prioritizer explain --cve CVE-2025-12345
```

Zweck:
eine einzelne CVE mit allen Signalen und Begründungen ausgeben

---

# 11. Priorisierungslogik

Die Logik muss bewusst **einfach, transparent und dokumentiert** bleiben.

## Grundidee
- KEV = starker Risikotreiber
- EPSS = Exploit-Wahrscheinlichkeit
- CVSS = technische Schwere
- ATT&CK = optionaler Kontext, nicht Pflichtsignal im MVP

## Empfohlene Prioritätsklassen
- `Critical`
- `High`
- `Medium`
- `Low`

## MVP-Regeln
### Critical
- `in_kev == True`
oder
- `epss >= 0.70` und `cvss_base_score >= 7.0`

### High
- `epss >= 0.40`
oder
- `cvss_base_score >= 9.0`

### Medium
- `cvss_base_score >= 7.0`
oder
- `epss >= 0.10`

### Low
- alles andere

## ATT&CK-Einfluss in Phase 2
ATT&CK darf **höchstens eine sanfte Kontextanhebung** liefern, zum Beispiel:
- wenn Impact-Mapping Initial Access oder Privilege Escalation enthält, dann Begründung ergänzen
- ATT&CK soll nicht die Kernlogik dominieren

---

# 12. Handlungsempfehlungen

Codex soll für jede Prioritätsklasse standardisierte Empfehlungen generieren.

## Beispiele
### Critical
- sofort patchen oder mitigieren
- Exposure prüfen
- Detection oder Monitoring prüfen
- mögliche Business-Auswirkung eskalieren

### High
- zeitnah patchen
- Workaround oder Mitigation prüfen
- betroffene Produkte und Assets inventarisieren

### Medium
- regulär priorisieren
- Abhängigkeit zu kritischen Systemen prüfen

### Low
- dokumentieren
- beobachten
- im normalen Zyklus behandeln

---

# 13. Implementierungsstrategie

## Phase 1
Repository anlegen und Grundstruktur bauen

## Phase 2
Parser implementieren
- TXT
- CSV

## Phase 3
NVD Provider implementieren
- gezielte CVE-Abfrage
- robustes Parsing der JSON-Struktur
- API-Key aus Environment unterstützen

## Phase 4
EPSS Provider implementieren
- Batch-Abfrage
- Parsing von `epss` und `percentile`

## Phase 5
KEV Provider implementieren
- JSON oder CSV laden
- Membership schnell prüfen

## Phase 6
Priorisierungsservice bauen
- Regeln anwenden
- rationale und Handlungsempfehlung erzeugen

## Phase 7
Markdown-Reporter bauen
- schöne Tabelle
- Projektgeeignete Darstellung
- kurze Zusammenfassung oben

## Phase 8
Tests und Beispiel-Daten

## Phase 9
Optionaler ATT&CK-Modus
- nur wenn MVP stabil ist

---

# 14. ATT&CK-Modul: konkrete Empfehlung an Codex

## Klare Vorgabe
Codex soll ATT&CK **nicht erzwingen** und nicht mit unsauberer Heuristik halluzinieren.

## Zulässige Implementierung
### Standard
`attack.py` ist standardmäßig deaktiviert oder liefert leere Felder.

### Optional
Wenn eine lokale CSV-Datei mit ATT&CK-CVE-Mappings vorhanden ist, kann das Modul:
- per CVE-ID suchen
- Techniken extrahieren
- Taktiken extrahieren
- diese in den Report aufnehmen

## Nicht zulässig
- CVE-Beschreibungen mit LLM-Logik frei auf ATT&CK mappen
- ungeprüfte Drittquellen scrapen
- ATT&CK als harte Voraussetzung für das Funktionieren des Tools einbauen

## Optionaler Dateiname
`data/optional_attack_to_cve.csv`

---

# 15. Caching und Robustheit

## Empfohlen
- einfacher Dateicache im `.cache/` Verzeichnis
- Cache-Key pro Quelle und CVE-Liste
- TTL optional

## Mindestanforderung
- Tool muss ohne Cache funktionieren
- Tool darf bei API-Problemen nicht komplett abstürzen
- fehlende Datenquellen müssen mit Warnung behandelt werden

## Fehlerfälle
- ungültige CVE-ID
- CVE nicht in NVD
- EPSS nicht vorhanden
- KEV-Datei nicht erreichbar
- leere Eingabedatei
- doppelte CVEs

---

# 16. Teststrategie

## Parser-Tests
- TXT-Datei korrekt lesen
- CSV-Datei korrekt lesen
- Duplikate entfernen
- ungültige Zeilen ignorieren oder melden

## Provider-Tests
- NVD-Response parsen
- EPSS-Response parsen
- KEV-Datensatz prüfen

## Priorisierungs-Tests
- KEV => Critical
- hohe EPSS + hoher CVSS => Critical
- hoher CVSS allein => High
- mittlerer CVSS => Medium
- sonst Low

## Reporter-Tests
- Markdown enthält Kopfzeilen
- alle Pflichtfelder erscheinen
- `N.A.` bei fehlenden Daten

## Integrationstest
- Sample-CVE-Datei -> Report wird erzeugt

---

# 17. README-Anforderungen

Codex soll ein README schreiben, das mindestens diese Punkte enthält:
1. Projektidee
2. Motivation
3. Datenquellen
4. Installation
5. Nutzung
6. Beispielinput
7. Beispieloutput
8. Priorisierungslogik
9. Grenzen des Tools
10. Roadmap

---

# 18. Evidence-Anforderungen für das Hochschulprojekt

Codex soll bei der Arbeit an das Prüfungsformat denken.

Es müssen am Ende leicht sammelbar sein:
- Screenshot eines CLI-Laufs
- Beispiel-Report
- Beispiel-Vergleich:
  - nur CVSS
  - CVSS + EPSS + KEV
- Git-Commits
- Testlauf
- kurze technische Doku
- kurze Executive Summary

---

# 19. Management- bzw. CISO-Story

Codex soll in Dokumentation und Beispieltexten diese Story unterstützen:

## Problem
Viele bekannte Schwachstellen konkurrieren um begrenzte Bearbeitungskapazität.

## Risiko
Wenn Priorisierung zu grob oder zu spät erfolgt, können besonders relevante Schwachstellen zu lange offen bleiben.

## Maßnahme
Ein kleines, nachvollziehbares Priorisierungstool kombiniert technische Schwere mit Relevanzsignalen.

## Nutzen
- bessere Entscheidungsbasis
- gezielterer Ressourceneinsatz
- nachvollziehbare Begründungen
- stärkere Verbindung von technischem Befund und Management-Entscheidung

---

# 20. Empfohlene Libraries

## Erlaubt und sinnvoll
- `requests`
- `click` oder `typer`
- `pydantic` oder `dataclasses`
- `rich` für Terminal-Tabellen
- `pytest`
- `python-dotenv`

## Optional
- `tabulate`
- `tenacity` für Retry
- `httpx`

## Empfehlung
Für dieses Projekt:
- `typer`
- `requests`
- `pydantic`
- `rich`
- `pytest`
- `python-dotenv`

---

# 21. Akzeptanzkriterien

Das Projekt gilt als MVP-fertig, wenn:

1. eine Datei mit CVEs eingelesen werden kann
2. NVD-Daten für diese CVEs geladen werden
3. EPSS-Daten geladen werden
4. KEV-Mitgliedschaft geprüft wird
5. eine Priorität berechnet wird
6. ein Markdown-Report geschrieben wird
7. ein sinnvoller CLI-Output im Terminal erscheint
8. mindestens einige Tests grün laufen
9. das README Installation und Nutzung erklärt
10. das Tool auch ohne ATT&CK stabil funktioniert

---

# 22. Nicht-funktionale Anforderungen

- Python 3.11 oder 3.12
- klare Typisierung
- kleine, lesbare Module
- keine riesige God-Class
- Fehlerbehandlung sauber
- Logs bzw. Fehlermeldungen verständlich
- Defaults konservativ
- keine Netzwerk-Anfragen außerhalb der dokumentierten Quellen
- kein Web-Scraping als Kernlogik

---

# 23. Roadmap

## MVP
- Input
- NVD
- EPSS
- KEV
- Priorisierung
- Markdown-Report

## V1.1
- JSON-Export
- Filteroptionen
- bessere CLI-Ausgabe
- `.env` Support

## V1.2
- optional ATT&CK-Integration mit lokaler Mapping-Datei
- Vergleichsansicht „simple vs enriched“

## V1.3
- Konfigurationsdatei
- Caching
- kleine Executive-Zusammenfassung im Report

---

# 24. Konkreter Arbeitsauftrag an Codex

## Kurzversion
Implementiere ein kleines Python CLI, das eine Liste bekannter CVEs einliest, die CVEs mit NVD, EPSS und KEV anreichert, daraus eine nachvollziehbare Priorität berechnet und das Ergebnis als Markdown-Report und Terminal-Ausgabe darstellt. ATT&CK ist optional und darf das MVP nicht blockieren.

## Ausführliche Anweisung
1. Lege ein sauberes Python-Projekt mit `src/` Layout an.
2. Nutze `typer` für die CLI.
3. Implementiere Parser für TXT und CSV.
4. Implementiere einen NVD-Provider mit optionalem API-Key aus Environment.
5. Implementiere einen EPSS-Provider mit Batch-Support.
6. Implementiere einen KEV-Provider auf Basis des offiziellen KEV-JSON oder CSV.
7. Implementiere eine einfache, transparente Priorisierungslogik.
8. Generiere einen Markdown-Report.
9. Nutze `rich` für eine saubere Terminal-Ausgabe.
10. Schreibe Tests.
11. Schreibe README und Beispiel-Dateien.
12. Behandle ATT&CK nur als optionales Modul mit lokaler Mapping-Datei.
13. Halte das Projekt klein, nachvollziehbar und prüfungstauglich.
14. Füge keine Weboberfläche und keine Datenbank hinzu.
15. Dokumentiere Grenzen und Annahmen explizit.

---

# 25. Prompt zum direkten Einfügen in Codex

```text
You are implementing a small Python CLI project for a university security module.

Project goal:
Build a command-line tool that reads a list of CVE IDs, enriches them with NVD CVSS data, FIRST EPSS data, and CISA KEV status, then produces a transparent priority ranking and a Markdown report.

Important constraints:
- Keep the scope small and demo-ready
- No web UI
- No database
- No SIEM integration
- No ticketing integration
- ATT&CK is optional and must not block the MVP
- Do not invent unsupported CVE->ATT&CK mappings
- Use official/public sources only
- Prioritize readability, maintainability, and tests

Recommended stack:
- Python 3.11+
- typer
- requests
- pydantic
- rich
- pytest
- python-dotenv

Mandatory functionality:
1. Read CVEs from TXT and CSV
2. Query NVD CVE API 2.0
3. Query FIRST EPSS API
4. Load CISA KEV JSON or CSV
5. Compute transparent priority labels
6. Print results in terminal
7. Write Markdown report
8. Include sample input files
9. Include tests
10. Include README

Suggested structure:
- src/vuln_prioritizer/
- providers/nvd.py
- providers/epss.py
- providers/kev.py
- scoring.py
- reporter.py
- cli.py

Priority logic:
- Critical: in KEV OR (EPSS >= 0.70 and CVSS >= 7.0)
- High: EPSS >= 0.40 OR CVSS >= 9.0
- Medium: CVSS >= 7.0 OR EPSS >= 0.10
- Low: otherwise

Output fields:
- CVE ID
- Description
- CVSS base score
- CVSS severity
- EPSS
- EPSS percentile
- KEV status
- Priority label
- Rationale
- Recommended action

ATT&CK handling:
- Keep disabled by default
- Only support local mapping file if provided
- No heuristic hallucinated mapping

Deliver:
- clean repository structure
- working CLI
- tests
- README
- example data
- example generated report
```

---

# 26. Quellensammlung für das eigentliche Projekt

Diese Quellen sollen in README, Konzeptpapier oder Doku referenziert werden:

1. NVD CVE API 2.0  
2. NVD Developers / API Transition Guide  
3. FIRST EPSS und EPSS API  
4. CISA Known Exploited Vulnerabilities Catalog  
5. cisagov/kev-data  
6. MITRE ATT&CK  
7. MITRE ATT&CK Data & Tools  
8. CTID Mapping ATT&CK to CVE for Impact  
9. CTID Mappings Explorer  
10. TURROKS/CVE_Prioritizer

---

# 27. Letzte fachliche Empfehlung

Wenn Zeit knapp wird:
- ATT&CK komplett weglassen
- stattdessen MVP mit NVD + EPSS + KEV perfekt machen
- einen sehr guten Vergleichsreport erzeugen
- die ATT&CK-Erweiterung nur im Ausblick oder als optionales Modul erwähnen

Das ist für das Hochschulprojekt methodisch sauberer als ein halb fertiger, unsauberer ATT&CK-Teil.
