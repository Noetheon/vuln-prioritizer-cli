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

These defaults are now implemented through a policy model. The CLI can override them with explicit threshold flags while preserving the default behavior when no overrides are provided.

## Filtering

Filters are applied only after enrichment and priority calculation.

- `--priority` matches the enriched priority label
- `--kev-only` keeps KEV-listed findings only
- `--min-cvss` and `--min-epss` exclude findings with missing values
- `--sort-by` changes display order, not the computed priority rank

## Comparison Mode

The `compare` command evaluates the same enriched findings against a deterministic `CVSS-only` baseline:

- `Critical`: `CVSS >= 9.0`
- `High`: `CVSS >= 7.0`
- `Medium`: `CVSS >= 4.0`
- `Low`: missing CVSS or everything below `4.0`

`delta_rank` is calculated as `cvss_only_rank - enriched_rank`.
Positive values mean the enriched model treats the CVE as more urgent than the baseline. Negative values mean the enriched model lowers the operational urgency.

## Explain Mode

`explain` now includes the same baseline comparison logic as `compare` for a single CVE:

- CVSS-only baseline label
- enriched label
- delta versus the baseline
- deterministic reason for the change or non-change

## Sorting

Results are sorted by:

1. priority rank
2. KEV membership
3. EPSS descending
4. CVSS descending
5. CVE ID

With `--sort-by`, users can temporarily switch the output order to EPSS, CVSS, or CVE ID while keeping the same underlying priority calculation.

## Error Handling

- missing NVD data produces default fields instead of aborting the run
- missing EPSS data is rendered as `N.A.`
- KEV failures produce warnings
- only empty or completely unusable input results in exit code `2`
