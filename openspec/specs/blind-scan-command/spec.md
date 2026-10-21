# blind-scan-command Specification

## Purpose
Run a knowledge-base scan from hashes so source code is not uploaded. This is the collaboration surface for `handlers/blind_scan.py`.

## Requirements

### Requirement: Shared blind-scan behavior
`blind-scan` MUST follow `target-resolution-and-scan-reuse`, `preflight-and-status-waiting`, `toolbox-runtime`, `toolbox-hash-generation`, `upload-and-temporary-data`, `scan-execution-workflow`, and `handler-errors-and-redaction`.

#### Scenario: Directory blind scan
- **WHEN** `blind-scan` receives a directory
- **THEN** it generates and validates hashes, uploads that hash file, and delegates to `execute_scan_workflow`

### Requirement: Input selection
A path that is a file ending in `.fossid` SHALL be treated as pre-generated hashes and MUST NOT invoke Toolbox hash generation. Every other path SHALL be hashed with Toolbox. Validation failure MUST stop the command before project resolution.

#### Scenario: Invalid pre-generated file
- **WHEN** the `.fossid` file is empty or not UTF-8
- **THEN** validation raises `ValidationError` and no project or scan is created

### Requirement: Existing content reset
For an existing scan, `blind-scan` SHALL try to remove all uploaded content before uploading hashes. A removal failure MUST be warned and MUST NOT stop the hash upload. A new scan MUST NOT be cleared. This command does not implement `--incremental-upload`.

#### Scenario: Existing scan is reused
- **WHEN** `blind-scan` resolves an existing upload scan
- **THEN** it attempts to clear existing content before uploading the hash file

### Requirement: Generated file cleanup
The command SHALL delete a Toolbox-generated hash file in a `finally` block. A user-supplied `.fossid` path MUST NOT be selected for cleanup.

#### Scenario: Upload fails after hash generation
- **WHEN** hash upload raises after Toolbox created the hash file
- **THEN** the generated file is still cleaned up and the user-supplied project path remains

### Requirement: Command success
`handle_blind_scan` SHALL return the boolean returned by `execute_scan_workflow`.

#### Scenario: Workflow returns success
- **WHEN** the scan workflow finishes and returns true
- **THEN** `handle_blind_scan` returns true
