# Vulnerability Prioritization Comment

## Summary

- Findings shown: 2
- Critical: 2
- KEV-listed: 2
- Input format: `trivy-json`
- Under investigation: 1

## Top Findings

| CVE | Priority | CVSS | EPSS | KEV | Sources | Recommendation |
| --- | --- | ---: | ---: | --- | --- | --- |
| CVE-2024-3094 | Critical | 10.0 | 0.843 | yes | trivy-json | Escalate validation and remediation because context indicates internet-facing exposure, production environment. |
| CVE-2024-4577 | Critical | 9.8 | 0.594 | yes | trivy-json | Review the affected components and assets in context before final remediation scheduling. |

## Notes

- ATT&CK is optional and is not enabled in this example comment.
- This artifact reflects the current CLI report shape and is intended for PR-comment style publication.
