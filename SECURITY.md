# Security Policy

## Supported Use

`vuln-prioritizer` is a defensive prioritization CLI for known CVEs. It is not a scanning engine, exploit framework, or asset discovery platform.

## Reporting a Security Issue

If you discover a security issue in this repository, please report it privately to the maintainer before opening a public issue.

Until a dedicated disclosure channel exists, avoid posting proof-of-concept exploit details in public tickets.

## Project-Specific Notes

- The tool consumes public vulnerability data from NVD, FIRST EPSS, and CISA KEV.
- Network integrations should remain limited to documented, official sources.
- Optional ATT&CK support must stay offline-mapping-based unless the project explicitly adopts a reviewed live approach.
