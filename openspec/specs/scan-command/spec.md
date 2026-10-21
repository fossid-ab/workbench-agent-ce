# scan-command Specification

## Purpose
Upload a local directory or archive to a Workbench scan, extract it, and run the shared scan workflow. This is the collaboration surface for `handlers/scan.py`.

## Requirements

### Requirement: Shared scan behavior
`scan` MUST follow `target-resolution-and-scan-reuse`, `preflight-and-status-waiting`, `upload-and-temporary-data`, `scan-execution-workflow`, and `handler-errors-and-redaction`. This spec adds only behavior owned by the upload command.

#### Scenario: Successful directory scan
- **WHEN** `scan` is given a directory, project, and scan that can be created
- **THEN** it creates the targets, uploads an archive, extracts it, and delegates to `execute_scan_workflow`

### Requirement: Existing content handling
For an existing scan, `scan` SHALL remove all uploaded content before upload unless `--incremental-upload` is set. A removal failure MUST be printed as a warning and MUST NOT stop the upload. A new scan MUST NOT be cleared.

#### Scenario: Incremental reuse
- **WHEN** `scan` reuses a scan with `--incremental-upload`
- **THEN** existing content is kept and the new archive is uploaded

#### Scenario: Clear fails
- **WHEN** content removal raises for an existing scan
- **THEN** the command warns and continues with the upload

### Requirement: Archive extraction gate
After upload, `scan` SHALL request archive extraction with `--recursively-extract-archives` and `--jar-file-extraction`. When extraction is triggered, it MUST wait with `scan_number_of_tries` and a 5-second interval. Status `FAILED` or `CANCELLED` MUST raise `ProcessError` and MUST NOT start the scan workflow. When extraction is not triggered, the command MUST continue.

#### Scenario: Extraction fails
- **WHEN** the extraction status is `FAILED`
- **THEN** `scan` raises `ProcessError` and does not call `execute_scan_workflow`

#### Scenario: Nothing to extract
- **WHEN** Workbench reports that extraction was not triggered
- **THEN** `scan` prints that there are no archives and starts the scan workflow

### Requirement: Command success
`handle_scan` SHALL return the boolean returned by `execute_scan_workflow`.

#### Scenario: Workflow returns success
- **WHEN** the scan workflow finishes and returns true
- **THEN** `handle_scan` returns true
