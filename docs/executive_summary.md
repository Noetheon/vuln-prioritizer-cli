# Executive Summary

## Problem

Security-Teams muessen haeufig mehr bekannte Schwachstellen bewerten, als kurzfristig behoben werden koennen. Eine reine CVSS-Priorisierung bildet operative Relevanz nur unvollstaendig ab.

## Massnahme

`vuln-prioritizer` kombiniert:

- technische Schwere aus NVD/CVSS
- Ausnutzungswahrscheinlichkeit aus FIRST EPSS
- real beobachtete Ausnutzung aus CISA KEV

## Nutzen

- bessere Entscheidungsgrundlage fuer Patch- und Mitigationsreihenfolgen
- transparente, dokumentierte Priorisierungsregeln
- gut erklaerbarer Transfer in Management- und CISO-Kommunikation

## Ergebnisform

Das Tool liefert:

- eine priorisierte Terminal-Tabelle fuer den operativen Einsatz
- einen Markdown-Report fuer Doku, Evidence und Management-Kommunikation
- optional JSON fuer spaetere Weiterverarbeitung
