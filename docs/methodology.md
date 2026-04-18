# Methodology

## Input

Supported input formats:

- TXT files with one CVE per line
- CSV files with a `cve` or `cve_id` column

Input is normalized, validated, and deduplicated. Invalid lines do not immediately abort the run; they are recorded as warnings.

## Data Enrichment

### NVD

- one request per CVE via `cveId`
- English description preferred
- CVSS selection order: `v4.0 -> v3.1 -> v3.0 -> v2`

### EPSS

- batch requests with chunking under the documented query limit
- fields used: `epss`, `percentile`, and response date

### KEV

- default source: official CISA JSON feed
- fallback: official `cisagov/kev-data` mirror
- optional local JSON or CSV file

### ATT&CK

- disabled in the MVP by default
- local CSV mapping only
- no heuristic mapping from free text

## Caching

- optional file cache under `.cache/vuln-prioritizer`
- NVD and EPSS are cached per CVE
- the online KEV catalog is cached as an indexed dataset
- TTL is configurable via CLI; with `--no-cache` the tool runs entirely without cache

## Prioritization

- `Critical`: KEV or `(EPSS >= 0.70 and CVSS >= 7.0)`
- `High`: `EPSS >= 0.40` or `CVSS >= 9.0`
- `Medium`: `CVSS >= 7.0` or `EPSS >= 0.10`
- `Low`: everything else

## Sorting

Results are sorted by:

1. priority rank
2. KEV membership
3. EPSS descending
4. CVSS descending
5. CVE ID

## Error Handling

- missing NVD data produces default fields instead of aborting the run
- missing EPSS data is rendered as `N.A.`
- KEV failures produce warnings
- only empty or completely unusable input results in exit code `2`
