# Applied Security Project  
## Projektgrundlage für Thema: Python CLI für CVE Priorisierung mit EPSS, KEV und ATT&CK

> Stand: 18.04.2026  
> Verwendungszweck: Notion-Grundlage, Konzeptpapier, Pitch-Vorbereitung, spätere Projektdokumentation

---

# 1. Kurzfassung

## Arbeitstitel
**Blue-Team-orientiertes Python CLI zur Priorisierung von Schwachstellen mit CVSS, EPSS, KEV und ATT&CK-Kontext**

## Projektidee in einem Satz
Ich entwickle ein Python-Kommandozeilenwerkzeug, das eine Liste von CVEs einliest und sie nicht nur nach Schweregrad, sondern nach Verteidigungsrelevanz priorisiert, indem es CVSS-Daten, EPSS-Werte, den CISA-KEV-Status und optional ATT&CK-Kontext zu einem handlungsorientierten Report zusammenführt.

## Warum das Thema gut zum Modul passt
Das Projekt verbindet technische Umsetzung mit Management-Nutzen:
- technisch: CLI, API-Anbindungen, Datenverarbeitung, Priorisierungslogik, Reportgenerierung
- CISO-Perspektive: bessere Priorisierung knapper Patch- und Mitigationsressourcen

---

# 2. Notion-tauglicher Themensteckbrief

## Projekt / Repo / Portal
**Projektname**  
Blue Team Vulnerability Prioritizer CLI

**Repository / Organisation**  
Eigenes GitHub-Repository

**Portal / Quelle**  
GitHub, FIRST EPSS, CISA KEV, NVD, MITRE ATT&CK / CTID Mappings Explorer

**Team / Maintainer (optional)**  
Eigenprojekt

## Startpunkt
**Issue / CVE / Advisory**  
N.A. als Upstream-Issue, da Eigenprojekt

**Scorecard-Befund / Doc-Lücke**  
Bestehende öffentliche Priorisierungstools kombinieren bereits CVSS, EPSS und KEV, aber eine verständliche ATT&CK-orientierte Verteidigungsperspektive fehlt oft oder ist nicht der Kernfokus.

**Misconfiguration / fehlendes Tooling**  
Blue Teams haben häufig viele offene CVEs, aber kein kleines, nachvollziehbares Tool, das bekannte Schwachstellen in eine operative Reihenfolge für Fix, Mitigation oder Monitoring übersetzt.

## Problem Statement
Viele Organisationen können nicht jede bekannte Schwachstelle sofort beheben und priorisieren daher oft nur anhand von CVSS. Das reicht für die operative Verteidigung häufig nicht aus, weil CVSS Schwere beschreibt, aber nicht direkt, was aktuell besonders relevant für Ausnutzung und Verteidigung ist.

## Artefakt + Evidence
**Was ist am Ende sichtbar?**
- Python CLI
- GitHub-Repository
- Beispiel-Eingabedateien
- Markdown- oder JSON-Report
- dokumentierte Priorisierungslogik
- Screenshots bzw. Terminal-Output

**Evidence**
- CLI-Ausgabe
- Beispiel-Report
- Git-Commits
- Testfälle
- Vorher/Nachher-Vergleich einer simplen versus erweiterten Priorisierung

## CISO-Story
Das Projekt reduziert das Risiko, dass kritische Schwachstellen wegen schlechter Priorisierung zu spät behandelt werden. Geschützt werden vor allem kritische Systeme, Geschäftsprozesse und die begrenzte Reaktionsfähigkeit des Security-Teams, weil knappe Ressourcen gezielter eingesetzt werden können.

---

# 3. Einfache Erklärung des Themas

## Was ist eine CLI?
CLI bedeutet Command Line Interface. Das ist einfach ein Programm, das im Terminal gestartet wird. Statt auf Buttons in einer Weboberfläche zu klicken, übergibt man dem Tool Befehle oder Dateien.

## Was ist eine CVE?
Eine CVE ist eine öffentlich registrierte Schwachstelle mit eindeutiger Kennung, zum Beispiel `CVE-2025-12345`.

## Was ist CVSS?
CVSS beschreibt, wie schwer eine Schwachstelle grundsätzlich ist. Das hilft, aber allein reicht es nicht unbedingt für operative Priorisierung.

## Was ist EPSS?
EPSS ist ein Wahrscheinlichkeitswert, der schätzt, wie wahrscheinlich eine veröffentlichte CVE in den nächsten 30 Tagen in der Praxis ausgenutzt wird.

## Was ist KEV?
KEV ist eine offizielle Liste von CISA mit Schwachstellen, die bereits real ausgenutzt wurden.

## Was bringt ATT&CK?
ATT&CK gibt zusätzlichen Verteidigungskontext. Es hilft dabei, eine CVE nicht nur als „schweren Bug“, sondern als Teil möglicher Angreifertechniken oder Angriffspfade zu betrachten.

## Kernnutzen in Blue-Team-Sprache
Das Tool soll helfen, aus einer langen CVE-Liste die Schwachstellen herauszufiltern, die aus Verteidigersicht zuerst geprüft, gepatcht, mitigiert oder überwacht werden sollten.

---

# 4. Fachliche Begründung

## Warum CVSS allein oft nicht reicht
CVSS ist wichtig, weil es den potenziellen Impact einer Schwachstelle beschreibt. Für operative Entscheidungen fehlt aber oft zusätzlicher Kontext:
- Wie wahrscheinlich ist eine Ausnutzung bald?
- Wird die Schwachstelle bereits aktiv ausgenutzt?
- Passt sie zu relevanten Angreifertechniken?
- Welche Maßnahmen sollte das Blue Team daraus ableiten?

## Warum EPSS dazu passt
EPSS liefert eine datengetriebene Wahrscheinlichkeit für beobachtete Ausnutzung in den nächsten 30 Tagen.

## Warum KEV dazu passt
KEV zeigt, dass eine Schwachstelle bereits real ausgenutzt wird und daher nicht nur theoretisch relevant ist.

## Warum ATT&CK ein sinnvoller Zusatz ist
ATT&CK ist nicht zwingend für das MVP nötig, aber stark für den CISO- und Blue-Team-Mehrwert. Damit kann das Tool im Report z. B. zusätzlich sagen:
- eher Initial Access relevant
- eher Privilege Escalation relevant
- eher Credential Access relevant

Das verbessert die Einordnung für Detection, Monitoring und Priorisierung.

---

# 5. Forschungs- und Projektfrage

## Leitfrage
Wie kann ein kleines Python-CLI-Tool bekannte Schwachstellen so anreichern und priorisieren, dass Blue Teams schneller erkennen, welche CVEs zuerst behandelt werden sollten?

## Unterfragen
1. Welche Zusatzinformationen neben CVSS sind für operative Priorisierung am nützlichsten?
2. Wie kann EPSS und KEV technisch in ein kleines CLI eingebunden werden?
3. Wie kann ein optionaler ATT&CK-Kontext die Priorisierung aus Verteidigersicht verbessern?
4. Wie lässt sich das Ergebnis nachvollziehbar und managementtauglich darstellen?

---

# 6. Projektziel

## Oberziel
Entwicklung eines kleinen, nachvollziehbaren und praxistauglichen Python CLI zur CVE-Priorisierung.

## Konkrete Ziele
- CVE-Input einlesen
- NVD-Daten für CVSS abrufen oder übernehmen
- EPSS-Werte abrufen
- KEV-Status prüfen
- optional ATT&CK- bzw. Mapping-Kontext ergänzen
- Priorität berechnen
- Ergebnis als Terminal-Ansicht und Report ausgeben

---

# 7. Scope und Nicht-Scope

## Im Scope
- Python CLI
- Verarbeitung von CVE-Listen
- Einbindung von EPSS
- Einbindung von KEV
- Einfache Priorisierungslogik
- Markdown- oder JSON-Ausgabe
- Dokumentation und Beispielnutzung
- Optional: ATT&CK-Kontext für Teilmenge oder über Mapping-Ansatz

## Nicht im Scope
- Webanwendung
- Datenbank
- Benutzerverwaltung
- SIEM-Integration
- Vollständige Echtzeit-Automatisierung
- Perfekte ATT&CK-Abdeckung für alle CVEs
- Vollständiges Enterprise Vulnerability Management System

## Sinnvolle harte Scope-Grenze
MVP zuerst mit:
- Input: Liste von CVEs
- Datenquellen: NVD, EPSS, KEV
- Output: Priorisierte Liste mit Begründung

ATT&CK dann als optionale Stufe 2.

---

# 8. MVP

## Minimal Viable Product
Ein lauffähiges Python CLI, das:
1. eine Text- oder CSV-Datei mit CVEs einliest
2. für jede CVE CVSS, EPSS und KEV zusammenführt
3. eine einfache Prioritätsbewertung berechnet
4. das Ergebnis als Markdown-Report und Terminal-Output ausgibt

## Warum das als MVP gut ist
- klein genug
- vollständig demo-fähig
- keine unnötigen Nebenbaustellen
- passt gut in 4 bis 6 Wochen

---

# 9. Erweiterte Version

## Optionale Erweiterungen nach dem MVP
- ATT&CK- bzw. Mapping-Kontext
- Filter nach Priorität
- Sortierung nach Teams oder Asset-Kritikalität
- CSV-Export
- einfache Policy-Regeln wie:
  - KEV = immer hoch
  - EPSS > Schwelle = hoch
  - CVSS hoch + EPSS mittel = mittel bis hoch

---

# 10. Datenquellen und warum sie sinnvoll sind

## NVD
Nutzen:
- CVE-Metadaten
- CVSS
- Beschreibungen
- standardisierte Vulnerability-Daten

## FIRST EPSS
Nutzen:
- Wahrscheinlichkeitswert für baldige reale Ausnutzung

## CISA KEV
Nutzen:
- zeigt, ob eine Schwachstelle bereits real ausgenutzt wird

## MITRE ATT&CK
Nutzen:
- liefert Techniken und Taktiken als Blue-Team-Kontext

## CTID / Mappings Explorer
Nutzen:
- kann als Brücke dienen zwischen Schwachstellen-/Verteidigungsperspektive und ATT&CK-orientierter Einordnung

---

# 11. Mögliche technische Architektur

## Einfaches Datenflussmodell
1. Benutzer gibt CVEs ein  
2. CLI liest die CVEs  
3. Tool fragt Datenquellen ab  
4. Tool normalisiert die Daten  
5. Tool berechnet Priorität  
6. Tool gibt Report aus  

## Beispielhafte Komponenten
- `input_reader.py`
- `nvd_client.py`
- `epss_client.py`
- `kev_client.py`
- `attack_mapper.py`
- `scoring.py`
- `reporter.py`
- `cli.py`

---

# 12. Beispiel für die Priorisierungslogik

## Einfache erste Logik
**sehr hoch**
- KEV = ja  
oder
- EPSS >= 0.7 und CVSS >= 7.0

**hoch**
- EPSS >= 0.4
- oder CVSS >= 9.0
- oder ATT&CK-Kontext = Initial Access / Privilege Escalation

**mittel**
- CVSS hoch, aber EPSS niedrig
- kein KEV
- kein besonders kritischer ATT&CK-Kontext

**niedrig**
- niedriger CVSS
- niedriger EPSS
- kein KEV

## Wichtig
Diese Logik ist bewusst einfach und nachvollziehbar. Für das Modul ist Nachvollziehbarkeit wichtiger als ein „perfekter“ Algorithmus.

---

# 13. Beispielausgabe

## Beispielinput
- CVE-2024-12345
- CVE-2025-54321
- CVE-2026-11111

## Beispielreport
| CVE | CVSS | EPSS | KEV | ATT&CK-Kontext | Priorität | Empfehlung |
|---|---:|---:|---|---|---|---|
| CVE-2025-54321 | 8.8 | 0.82 | Ja | Initial Access | Sehr hoch | Sofort patchen oder mitigieren |
| CVE-2024-12345 | 9.1 | 0.21 | Nein | Privilege Escalation | Hoch | Zeitnah patchen und Logs prüfen |
| CVE-2026-11111 | 6.5 | 0.03 | Nein | N.A. | Niedrig | Beobachten |

---

# 14. Warum ATT&CK nur Zusatz und nicht Pflicht sein sollte

Das Projekt funktioniert bereits sehr gut mit CVSS, EPSS und KEV. ATT&CK ist ein Mehrwert, aber nicht notwendig, um einen starken MVP zu bauen.

## Gute Formulierung für die Präsentation
„Der Hauptnutzen meines Tools liegt in der operativen Priorisierung mit CVSS, EPSS und KEV. Die ATT&CK-Perspektive ist ein optionaler Zusatz, um die Ergebnisse aus Blue-Team-Sicht noch verteidigungsnäher einzuordnen.“

---

# 15. Mögliche Deliverables für das Modul

## Technische Deliverables
- GitHub-Repository
- Python CLI
- Beispiel-CVE-Datei
- Markdown- oder JSON-Report
- Installationsanleitung
- kurze Architekturbeschreibung
- Screenshots oder Terminal-Output

## Management Deliverables
- Executive Summary
- Priorisierungsbegründung
- Nutzenargumentation für Security-Team / CISO
- Aufwand-Nutzen-Betrachtung

---

# 16. Evidence-Plan

## Was du als Nachweis sammeln kannst
1. Screenshot oder Terminal-Output mit Input und Output
2. Beispiel-Report aus echter oder fiktiver CVE-Liste
3. Git-Commits und Versionsstände
4. Testfälle für einzelne CVEs
5. Vorher/Nachher:
   - nur CVSS-Sortierung
   - CVSS + EPSS + KEV + optional ATT&CK

## Gute Evidence-Idee
Zeige dieselbe CVE-Liste einmal nur nach CVSS sortiert und einmal mit deiner erweiterten Priorisierungslogik. Genau daran wird der Mehrwert sichtbar.

---

# 17. Risikoanalyse für dein eigenes Projekt

## Risiko 1
ATT&CK-Mapping wird zu groß oder zu unklar.  
**Gegenmaßnahme:** ATT&CK nur als optionale Erweiterung einplanen.

## Risiko 2
Zu viele Features gleichzeitig.  
**Gegenmaßnahme:** zuerst nur CLI, NVD, EPSS, KEV und Report.

## Risiko 3
API-Format oder Quellintegration ist aufwendiger als gedacht.  
**Gegenmaßnahme:** zunächst mit kleinen Testdaten und wenigen CVEs arbeiten.

## Risiko 4
Projekt wird zu „theoretisch“.  
**Gegenmaßnahme:** früh sichtbare CLI-Demo und Report erzeugen.

---

# 18. CISO-Perspektive

## Welches Risiko wird reduziert?
Das Risiko, dass begrenzte Ressourcen in der Schwachstellenbearbeitung falsch eingesetzt werden und wirklich kritische CVEs zu spät behandelt werden.

## Welche Assets werden geschützt?
- kritische Systeme
- Geschäftsprozesse
- Verfügbarkeit von Security-Teams
- Reaktionsgeschwindigkeit des Blue Teams

## Warum ist das priorisierbar?
Weil der Aufwand überschaubar ist und der Nutzen direkt in bessere Priorisierung, weniger Blindflug und klarere Entscheidungen übersetzt werden kann.

## Business Impact
- geringere Wahrscheinlichkeit, dass real ausnutzbare CVEs zu lange offen bleiben
- bessere Transparenz für technische und managementseitige Entscheidungen
- bessere Kommunikation zwischen Blue Team und Management

---

# 19. Konzeptpapier-Rohfassung

## Ausgangslage / Kontext
In der operativen Schwachstellenbearbeitung reicht der Schweregrad einer CVE allein oft nicht aus, um begrenzte Patch- und Mitigationsressourcen sinnvoll einzusetzen. Für eine praxistaugliche Priorisierung sind zusätzliche Informationen nötig, insbesondere reale Ausnutzungswahrscheinlichkeit, bekannte aktive Ausnutzung und verteidigungsrelevanter Kontext.

## Ziel des Projekts
Ziel ist die Entwicklung eines Python-CLI-Tools, das CVE-Listen einliest und sie anhand von CVSS, EPSS, KEV und optional ATT&CK-Kontext priorisiert. Das Ergebnis soll als nachvollziehbarer technischer Report und als Grundlage für Management-Entscheidungen nutzbar sein.

## Erste Management-These
Ein kleines, nachvollziehbares Priorisierungstool kann helfen, wirklich kritische Schwachstellen schneller zu identifizieren und damit die Wirksamkeit begrenzter Security-Ressourcen zu erhöhen.

## Scope / Nicht-Scope
Im Scope liegen CLI, API-Anbindungen, einfache Priorisierungslogik und Reportausgabe. Nicht im Scope liegen Weboberfläche, Datenbank, vollständige Automatisierung und tiefe Enterprise-Integrationen.

## Vorgehen / Arbeitsschritte
1. Datenquellen und Format der Eingabe definieren  
2. MVP für CVSS, EPSS und KEV bauen  
3. Reportausgabe implementieren  
4. optionale ATT&CK-Erweiterung prüfen  
5. Priorisierungslogik evaluieren und dokumentieren  
6. CISO-Nutzen und Executive Summary ableiten  

## Geplanter Output
Ein GitHub-Repository mit Python-CLI, Beispiel-Eingaben, Reports, Dokumentation und einer begründeten Priorisierungslogik.

## Evidence-Plan
Terminal-Output, Beispiel-Reports, Git-Commits, Testläufe, Vergleich einfacher und erweiterter Priorisierung.

## Risiken / Blocker
Unklare ATT&CK-Mappings und zu großer Scope. Das wird durch ein bewusst kleines MVP mit optionaler ATT&CK-Erweiterung abgefangen.

---

# 20. 3-Minuten-Pitch Rohfassung

„Ich möchte an einem Python CLI zur Priorisierung von Schwachstellen arbeiten. Ausgangspunkt ist, dass Security-Teams häufig sehr viele offene CVEs haben, aber nur begrenzte Ressourcen, um sie zu patchen oder zu mitigieren. Deshalb reicht es oft nicht, nur nach CVSS zu priorisieren. Ich möchte ein kleines Tool bauen, das eine Liste von CVEs einliest und sie mit CVSS, EPSS und dem CISA-KEV-Katalog anreichert. Optional soll zusätzlich ein ATT&CK-Kontext ergänzt werden, damit die Ergebnisse aus Blue-Team-Sicht noch verständlicher werden.

Das konkrete Problem ist also nicht das Finden neuer Schwachstellen, sondern die bessere Priorisierung bereits bekannter Schwachstellen. Sichtbar wäre am Ende ein eigenes GitHub-Repository mit Python-Code, einer lauffähigen CLI, Beispiel-Input und einem priorisierten Report. Als Evidence hätte ich Terminal-Output, Beispiel-Reports und einen Vergleich zwischen einer simplen CVSS-Sortierung und einer erweiterten Priorisierung.

Das Thema ist realistisch, weil ich das Artefakt selbst kontrolliere und nicht von einem Upstream-Merge abhänge. Der CISO-Nutzen liegt darin, dass knappe Ressourcen gezielter eingesetzt werden können und wirklich relevante CVEs schneller erkannt werden. Bis Termin 2 möchte ich einen MVP mit CVE-Input, EPSS- und KEV-Anreicherung und einer ersten Priorisierungslogik zeigen.“

---

# 21. Mögliche Rückfragen und Antworten

## Warum nicht einfach CVSS benutzen?
Weil CVSS primär die Schwere beschreibt, aber nicht direkt die operative Relevanz für Ausnutzung und Verteidigung.

## Warum ist das ein Blue-Team-Tool?
Weil es Verteidigern hilft zu entscheiden, was zuerst gefixt, mitigiert oder überwacht werden sollte.

## Warum ATT&CK überhaupt?
Nicht als Pflicht, sondern als Zusatz für mehr Kontext. Es kann helfen, die Priorisierung verteidigungsnäher zu erklären.

## Warum kein Dashboard?
Weil der Scope klein bleiben soll. Eine CLI ist für das Modul schneller umsetzbar und vollständig ausreichend.

## Was ist dein sichtbarstes Artefakt?
Die lauffähige CLI plus der erzeugte priorisierte Report.

---

# 22. Vorschlag für Repository-Struktur

```text
blue-team-vuln-prioritizer/
├─ README.md
├─ requirements.txt
├─ pyproject.toml
├─ data/
│  ├─ sample_cves.txt
│  └─ sample_report.md
├─ src/
│  ├─ cli.py
│  ├─ input_reader.py
│  ├─ nvd_client.py
│  ├─ epss_client.py
│  ├─ kev_client.py
│  ├─ attack_mapper.py
│  ├─ scoring.py
│  └─ reporter.py
├─ tests/
│  ├─ test_scoring.py
│  └─ test_parser.py
└─ docs/
   ├─ concept.md
   ├─ evidence.md
   └─ executive_summary.md
```

---

# 23. Möglicher Arbeitsplan bis zur Prüfung

## Bis 16.05 Konzept & Scoping
- Thema final festziehen
- Datenquellen festlegen
- MVP definieren
- Repo anlegen
- erste Architektur notieren

## Bis 20.05 Technik-Sprechstunde
- Eingabeformat bauen
- NVD, EPSS, KEV abrufen
- erste CLI-Ausgabe zeigen

## Bis 10.06 CISO-Coaching
- Priorisierungslogik erklären können
- Beispielreport fertig
- ATT&CK als Zusatz prüfen
- Executive-Story formulieren

## Bis 13.06 Präsentationstraining
- Demo fertig
- Screenshots und Evidence sammeln
- Pitch finalisieren
- Management-Slides schärfen

## Bis 20.06 Prüfung
- funktionierende Demo
- sauberes Konzeptpapier
- Executive Summary
- Finalpräsentation

---

# 24. Quellen, die du wirklich zitieren solltest

## Primärquellen
- FIRST EPSS
- CISA KEV Catalog
- NVD
- MITRE ATT&CK
- CTID / Mappings Explorer
- GitHub-Repo `TURROKS/CVE_Prioritizer`

## Wichtiger Hinweis
Diese Notion-Zusammenfassung ist deine Arbeitsgrundlage. Für das eigentliche Projekt oder eine schriftliche Dokumentation solltest du die Primärquellen selbst zitieren und nicht diesen zusammengefassten Text als alleinige Quelle verwenden.

---

# 25. Eigene nächste Schritte

## Sofort
- GitHub-Repo anlegen
- Projektnamen festlegen
- Python 3.11 oder 3.12 wählen
- kleines Input-Format definieren
- MVP Features festschreiben

## Danach
- NVD anbinden
- EPSS anbinden
- KEV prüfen
- erste Priorisierungslogik bauen
- Report erzeugen

## Erst danach
- ATT&CK- oder Mappings-Erweiterung entscheiden

---

# 26. Ein sehr guter finaler Merksatz für dich

**Das Projekt ist kein Scanner für neue Schwachstellen, sondern ein Blue-Team-Priorisierungstool, das bekannte CVEs in eine verständliche Reihenfolge für Fix, Mitigation oder Monitoring übersetzt.**
