# Concept

## Goal

`vuln-prioritizer` prioritizes known CVEs for operational vulnerability management. The tool is not a scanner and not a full vulnerability management platform. It is a deliberately small CLI with transparent logic.

The main user-facing workflows are:

- `analyze` for enriched prioritization
- `compare` for `CVSS-only vs enriched`
- `explain` for a single-CVE deep dive

## Core Security Idea

- NVD provides technical metadata and CVSS.
- FIRST EPSS provides a probability signal for near-term exploitation.
- CISA KEV provides a strong signal for known real-world exploitation.

Combining these three sources creates a more useful prioritization model than CVSS alone.

## Target Audience

- Blue teams
- Vulnerability management teams
- Security engineering teams
- Management and CISO-adjacent reporting use cases

## Scope Boundaries

Out of scope:

- asset discovery
- network scanning
- ticket automation
- SIEM integration
- web UI
- database storage
