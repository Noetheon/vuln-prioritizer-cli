# Executive Summary

## Problem

Security teams often need to assess more known vulnerabilities than they can remediate immediately. A CVSS-only prioritization model does not fully reflect operational urgency.

## Approach

`vuln-prioritizer` combines:

- technical severity from NVD/CVSS
- likely exploitation from FIRST EPSS
- observed real-world exploitation from CISA KEV

## Benefit

- better remediation sequencing for patching and mitigation
- transparent, documented prioritization rules
- a clear bridge between technical findings and management-facing communication

## Output

The tool provides:

- a prioritized terminal table for operational use
- a Markdown report for documentation and reporting
- optional JSON output for future integrations or downstream processing
