# download-reports-command Specification

## Purpose
Generate and download one or more scan or project reports, continuing past individual report failures. This is the collaboration surface for `handlers/download_reports.py`.

## Requirements

### Requirement: Shared report behavior
`download-reports` MUST follow `target-resolution-and-scan-reuse`, `preflight-and-status-waiting` for scan scope, `report-validation-and-results`, and `handler-errors-and-redaction`. Report type catalogs remain API definitions and are not restated here. Scan-scoped pre-flight MUST complete successfully before any report is generated.

#### Scenario: Scan report
- **WHEN** the scope is `scan` and the scan exists
- **THEN** the command resolves both targets without creating them, waits for scan completion, and downloads the resolved report types

#### Scenario: Scan-scoped pre-flight does not complete
- **WHEN** the shared read pre-flight wait times out or raises an API or network error
- **THEN** the command does not generate or download reports

### Requirement: Output directory
The command SHALL create `--report-save-path` when it does not exist. Creation failure MUST propagate as a filesystem error.

#### Scenario: Missing output directory
- **WHEN** the save path does not exist and can be created
- **THEN** the directory exists before the first report is requested

### Requirement: Scope resolution
Scan scope SHALL require both project and scan lookup. Project scope MUST resolve the project only, with `scan_required=False`, and MUST NOT run the scan pre-flight check.

#### Scenario: Project report
- **WHEN** the scope is `project`
- **THEN** no scan code is required and no scan idle check runs

### Requirement: Per-report isolation
Reports SHALL be requested sequentially in sorted type order. The command MUST pass selection type, selection view, disclaimer, and `include_vex` only when those options are set, except `include_vex` which is always forwarded. Notice and asynchronous report types MUST print that generation is being awaited. Timeout, API, network, filesystem, validation, and unexpected errors for one report MUST be counted and MUST NOT stop the remaining reports.

#### Scenario: One report times out
- **WHEN** the first report raises `ProcessTimeoutError` and a later report downloads
- **THEN** the command continues, counts both outcomes, and still attempts the later report

### Requirement: Partial success
The handler SHALL return true when `success_count` is greater than zero, even if other reports failed. It MUST return false when every report fails. The report summary MUST include failed type names.

#### Scenario: All reports fail
- **WHEN** every requested report raises
- **THEN** the handler returns false and the summary lists every failed type
