# preflight-and-status-waiting Specification

## Purpose
Wait for in-progress Workbench operations on an existing scan before a command mutates it or reads its results, and skip those waits for a scan that was just created.

## Requirements

### Requirement: New scans skip idle checks
Write commands SHALL skip pre-flight waiting when `scan_is_new` is true. A newly created scan is treated as idle since no operations have been performed on that scan.

#### Scenario: First upload to a new scan
- **WHEN** `scan`, `scan-git`, `blind-scan`, `analyze`, `import-sbom`, or `import-da` creates the scan
- **THEN** it does not call `scan_pre_flight_check`

### Requirement: Existing scans wait for relevant operations
An existing scan SHALL be checked before the command continues. If a relevant operation is active, CE MUST wait using `scan_number_of_tries` and `scan_wait_time`. A status check that cannot be queried MUST be logged and skipped rather than failing the command.

#### Scenario: Scan Operations (KB, Dependency Analysis) still running
- **WHEN** `scan` reuses a scan whose KB scan or Dependency Analysis is active
- **THEN** the command waits for that scan to finish before clearing or uploading content

#### Scenario: Status endpoint is unavailable
- **WHEN** a pre-flight status call raises an exception
- **THEN** that individual check is skipped and the command continues to the next check

### Requirement: Command-specific process sets
Each pre-flight function SHALL wait only for the processes its command can interrupt or must observe.

#### Scenario: Upload and analyze scans
- **WHEN** `scan` or `analyze` reuses a scan
- **THEN** pre-flight waits for archive extraction, KB scan, and dependency analysis

#### Scenario: Git scan
- **WHEN** `scan-git` reuses a scan
- **THEN** pre-flight waits for Git clone, KB scan, and dependency analysis

#### Scenario: Blind scan
- **WHEN** `blind-scan` reuses a scan
- **THEN** pre-flight waits for KB scan and dependency analysis

#### Scenario: Dependency import
- **WHEN** `import-da` reuses a scan
- **THEN** pre-flight waits for dependency analysis only

#### Scenario: SBOM import ignores an unrelated KB scan
- **WHEN** `import-sbom` reuses a scan
- **THEN** its pre-flight check waits for report import and does not wait for a KB scan

#### Scenario: Read commands
- **WHEN** `show-results`, `evaluate-gates`, or scan-scoped `download-reports` runs
- **THEN** pre-flight waits for KB scan and dependency analysis

#### Scenario: Project-scoped reports
- **WHEN** `download-reports` uses project scope
- **THEN** it does not run a scan pre-flight check

### Requirement: Read-only pre-flight failure
`show-results`, scan-scoped `download-reports`, and `evaluate-gates` SHALL wait for KB scan and dependency analysis to become idle before continuing. A pre-flight timeout, API error, or network error MUST abort the command so results, reports, or gates are not produced from an unverified scan.

#### Scenario: Show-results cannot verify completion
- **WHEN** a `show-results` status wait raises `ProcessTimeoutError`, `ApiError`, or `NetworkError`
- **THEN** the command does not fetch results

#### Scenario: Report generation starts after a status failure
- **WHEN** the KB or dependency-analysis wait raises during scan-scoped `download-reports`
- **THEN** the command does not generate or download reports

#### Scenario: Gates cannot confirm the scan is idle
- **WHEN** `evaluate_gates_pre_flight_check` raises `ProcessTimeoutError`
- **THEN** `evaluate-gates` returns false and does not query pending files, policy, or vulnerabilities

### Requirement: Read-only pre-flight error handling
`show-results` and scan-scoped `download-reports` MUST propagate pre-flight timeout, API, and network errors to the handler error path. `evaluate-gates` MUST catch those errors, print a gate-evaluation failure, and return false without running gate checks.

#### Scenario: Show-results propagates wait failure
- **WHEN** the shared read pre-flight raises during `show-results`
- **THEN** the handler error path surfaces the failure

#### Scenario: Evaluate-gates maps wait failure to false
- **WHEN** the shared read pre-flight raises during `evaluate-gates`
- **THEN** the command returns false without running gate checks
