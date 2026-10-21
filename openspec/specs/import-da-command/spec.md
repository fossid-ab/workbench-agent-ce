# import-da-command Specification

## Purpose
Upload an external dependency-analysis results file and run import-only dependency analysis. This is the collaboration surface for `handlers/import_da.py`.

## Requirements

### Requirement: Shared import behavior
`import-da` MUST follow `target-resolution-and-scan-reuse`, `preflight-and-status-waiting`, `report-validation-and-results`, and `handler-errors-and-redaction`. Path existence and filename checks remain CLI validation and are not repeated here.

#### Scenario: New dependency import
- **WHEN** `import-da` is given a valid results file and a new scan name
- **THEN** it creates the scan, uploads the file, waits for import, and prints the import summary

### Requirement: Upload and start failures
The command SHALL upload the file with `upload_da_results` and then call `start_da_import`. A failure from either call MUST raise `WorkbenchAgentError` and MUST NOT be reported as a successful import.

#### Scenario: Upload fails
- **WHEN** `upload_da_results` raises
- **THEN** the command raises `WorkbenchAgentError` and does not start the import

### Requirement: Import wait
The command SHALL wait with `scan_number_of_tries` and a 3-second interval. `ProcessTimeoutError` and `ProcessError` MUST propagate unchanged. Any other wait exception MUST raise `WorkbenchAgentError`.

#### Scenario: Import times out
- **WHEN** the dependency-analysis wait raises `ProcessTimeoutError`
- **THEN** that timeout propagates and the command does not print a success summary

### Requirement: Completion result
The handler SHALL return true only after the wait completes. It MUST then print the import summary, including `--show-summary` when requested.

#### Scenario: Import completes
- **WHEN** the dependency-analysis wait returns successfully
- **THEN** the handler prints the import summary and returns true
