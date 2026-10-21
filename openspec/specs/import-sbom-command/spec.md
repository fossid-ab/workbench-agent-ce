# import-sbom-command Specification

## Purpose
Validate a CycloneDX or SPDX file, create or reuse an SBOM scan, and import the prepared document. This is the collaboration surface for `handlers/import_sbom.py`.

## Requirements

### Requirement: Shared SBOM behavior
`import-sbom` MUST follow `report-validation-and-results` before any Workbench mutation, then `target-resolution-and-scan-reuse`, `preflight-and-status-waiting`, `upload-and-temporary-data`, and `handler-errors-and-redaction`.

#### Scenario: Valid CycloneDX import
- **WHEN** `import-sbom` receives a valid CycloneDX file and a new scan name
- **THEN** it validates first, creates an SBOM scan, uploads the original file, and waits for report import

### Requirement: Validation summary
After validation, the command SHALL print the format and version. CycloneDX output MUST include the component count and serial number when present. SPDX output MUST include document name, package count, and file count.

#### Scenario: SPDX validation
- **WHEN** a valid SPDX document is validated
- **THEN** the printed summary includes its document name, package count, and file count

### Requirement: Upload and start failures
The command SHALL upload the prepared path and then call `start_sbom_import`. A failure from either call MUST raise `WorkbenchAgentError`.

#### Scenario: Upload fails
- **WHEN** `upload_sbom_file` raises
- **THEN** the command raises `WorkbenchAgentError` and does not start the import

### Requirement: Import wait and result
The command SHALL wait on report-import status with `scan_number_of_tries` and a 3-second interval. Timeout and process errors MUST propagate. Other wait exceptions MUST raise `WorkbenchAgentError`. The handler MUST return true only after the wait completes and then print the import summary.

#### Scenario: Import completes
- **WHEN** the report-import wait returns successfully
- **THEN** the handler prints the import summary and returns true

### Requirement: Conversion cleanup
When preparation creates a temporary file, the command SHALL remove it in a `finally` block even if upload or import fails.

#### Scenario: Import fails after conversion
- **WHEN** SPDX conversion created a temporary file and the later import raises
- **THEN** the temporary file is still removed
