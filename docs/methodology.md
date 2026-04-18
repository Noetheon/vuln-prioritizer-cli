# Methodik

## Eingabe

Unterstuetzt werden:

- TXT-Dateien mit einer CVE pro Zeile
- CSV-Dateien mit Spalte `cve` oder `cve_id`

Die Eingabe wird normalisiert, validiert und dedupliziert. Ungueltige Zeilen werden nicht hart abgebrochen, sondern als Warnung dokumentiert.

## Datenanreicherung

### NVD

- ein Request pro CVE ueber `cveId`
- bevorzugte englische Beschreibung
- CVSS-Auswahl in Reihenfolge `v4.0 -> v3.1 -> v3.0 -> v2`

### EPSS

- Batch-Abfragen mit Chunking unter dem Query-Limit
- uebernommen werden `epss`, `percentile` und das Datum aus der Antwort

### KEV

- Standard: offizieller CISA-JSON-Feed
- Fallback: offizieller `cisagov/kev-data`-Mirror
- Optional: lokale JSON- oder CSV-Datei

### ATT&CK

- im MVP deaktiviert
- nur lokales CSV-Mapping
- kein heuristisches Mapping aus Freitext

## Caching

- optionaler Dateicache unter `.cache/vuln-prioritizer`
- NVD und EPSS werden pro CVE zwischengespeichert
- der online geladene KEV-Katalog wird als Index zwischengespeichert
- TTL ist per CLI steuerbar; mit `--no-cache` laeuft das Tool komplett ohne Cache

## Priorisierung

- `Critical`: KEV oder `(EPSS >= 0.70 und CVSS >= 7.0)`
- `High`: `EPSS >= 0.40` oder `CVSS >= 9.0`
- `Medium`: `CVSS >= 7.0` oder `EPSS >= 0.10`
- `Low`: alles andere

## Sortierung

Sortiert wird nach:

1. Prioritaetsrang
2. KEV-Mitgliedschaft
3. EPSS absteigend
4. CVSS absteigend
5. CVE-ID

## Fehlerbehandlung

- fehlende NVD-Daten erzeugen Default-Felder statt Abbruch
- fehlende EPSS-Daten werden als `N.A.` dargestellt
- KEV-Ausfaelle erzeugen Warnungen
- nur leere oder vollstaendig unbrauchbare Inputs fuehren zu Exit-Code `2`
