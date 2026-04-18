# Konzept

## Ziel

`vuln-prioritizer` priorisiert bekannte CVEs fuer die operative Schwachstellenbearbeitung. Das Tool ist kein Scanner und kein komplettes Vulnerability-Management-System, sondern ein bewusst kleines CLI mit nachvollziehbarer Logik.

## Fachliche Leitidee

- NVD liefert technische Metadaten und CVSS.
- FIRST EPSS liefert einen Wahrscheinlichkeitswert fuer zeitnahe Ausnutzung.
- CISA KEV liefert ein starkes Signal fuer bereits beobachtete Ausnutzung.

Durch die Kombination dieser drei Quellen entsteht eine belastbarere Priorisierung als mit CVSS allein.

## Zielgruppe

- Blue Teams
- Vulnerability Management
- Security Engineering
- Management- oder CISO-nahe Reporting-Use-Cases

## Abgrenzung

Nicht im Scope:

- Asset Discovery
- Netzwerk-Scanning
- Ticket-Automation
- SIEM-Anbindung
- Web-UI
- Datenbank
