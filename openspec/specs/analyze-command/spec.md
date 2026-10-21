# analyze-command Specification

## Purpose
Run Toolbox dependency analysis, optionally knowledge-base scan first-party code into the same scan, and import the Toolbox dependency report. This is the collaboration surface for `handlers/analyze.py`.

## Requirements

### Requirement: Shared analyze behavior
`analyze` MUST follow `target-resolution-and-scan-reuse`, `preflight-and-status-waiting`, `upload-and-temporary-data`, `toolbox-runtime`, `toolbox-dependency-analysis`, `analyze-ecosystems-and-first-party`, `scan-execution-workflow`, and `handler-errors-and-redaction`. When `--blind-scan` is set it MUST also follow `toolbox-hash-generation`. Upload reuse rules apply because the first-party KB leg uses an upload scan.

#### Scenario: Full analysis
- **WHEN** `analyze` has a supported ecosystem and first-party files
- **THEN** it runs Toolbox, resolves one scan, scans first-party code, imports the dependency report, and prints one combined summary

### Requirement: Workbench dependency analysis is not used
`analyze` SHALL ignore `--run-dependency-analysis`. Before the KB workflow it MUST force both dependency-analysis flags off so managed dependencies come only from the Toolbox report import.

#### Scenario: Workbench DA flag is passed
- **WHEN** `analyze` is called with `--run-dependency-analysis`
- **THEN** the KB workflow does not start Workbench dependency analysis

### Requirement: First-party upload and blind branches
When a scan root exists, `--blind-scan` SHALL hash that staging directory and upload hashes. Otherwise the command MUST archive and upload the staging directory, then extract archives with the same failure rule as `scan`: `FAILED` or `CANCELLED` raises `ProcessError`. An existing scan MUST be cleared before either upload. A KB workflow result of false MUST stop the command before dependency import.

#### Scenario: Blind first-party scan
- **WHEN** first-party files exist and `--blind-scan` is set
- **THEN** source files are not archived for upload, instead hashes generated and uploaded 

#### Scenario: Extraction fails
- **WHEN** first-party archive extraction returns `FAILED`
- **THEN** `analyze` raises `ProcessError` and does not import the dependency report

### Requirement: Dependency report import
`analyze` SHALL upload `analyzer-result.json` and start an import-only dependency analysis. Upload or start failures MUST raise `WorkbenchAgentError`. `--no-wait` MUST return success without polling. Otherwise it MUST wait with `scan_number_of_tries` and a 3-second interval. Timeout and process errors MUST propagate.

#### Scenario: Import requested without waiting
- **WHEN** the KB leg succeeds and `--no-wait` is set
- **THEN** the import starts, the command does not poll, and the combined summary says the import was not awaited

### Requirement: Cleanup on every exit
`analyze` SHALL delete an owned first-party staging directory and the Toolbox output directory in a `finally` block. It MUST NOT delete the user-supplied project path.

#### Scenario: Command fails during import
- **WHEN** dependency import raises
- **THEN** owned staging and Toolbox output are still removed
