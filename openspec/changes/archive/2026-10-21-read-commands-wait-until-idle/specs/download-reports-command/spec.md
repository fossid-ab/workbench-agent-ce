# Spec Delta

## MODIFIED Requirements

### Requirement: Shared report behavior
`download-reports` MUST follow `target-resolution-and-scan-reuse`, `preflight-and-status-waiting` for scan scope, `report-validation-and-results`, and `handler-errors-and-redaction`. Report type catalogs remain API definitions and are not restated here. Scan-scoped pre-flight MUST complete successfully before any report is generated.

#### Scenario: Scan report
- **WHEN** the scope is `scan` and the scan exists
- **THEN** the command resolves both targets without creating them, waits for scan completion, and downloads the resolved report types

#### Scenario: Scan-scoped pre-flight does not complete
- **WHEN** the shared read pre-flight wait times out or raises an API or network error
- **THEN** the command does not generate or download reports
