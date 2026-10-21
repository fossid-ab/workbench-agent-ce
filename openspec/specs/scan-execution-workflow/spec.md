# scan-execution-workflow Specification

## Purpose
Start the Workbench knowledge-base scan and optional dependency analysis after a handler has prepared scan content, including identification reuse, waiting, one failed-file retry, cancellation handling, and the post-scan summary.

## Requirements

### Requirement: Single post-setup entry
`scan`, `scan-git`, `blind-scan`, and the first-party leg of `analyze` SHALL call `execute_scan_workflow` only after their own content preparation succeeds.

#### Scenario: Upload scan reaches execution
- **WHEN** `scan` finishes archive extraction
- **THEN** it calls `execute_scan_workflow` with the resolved scan code and collected durations

### Requirement: KB and dependency-analysis selection
The workflow SHALL run a KB scan by default. `--dependency-analysis-only` MUST skip the KB scan and run dependency analysis only. When both `--dependency-analysis-only` and `--run-dependency-analysis` are set, dependency-analysis-only mode MUST win. `--run-dependency-analysis` without the only flag MUST run both.

#### Scenario: Both dependency flags are set
- **WHEN** a scan command passes both dependency flags
- **THEN** the workflow starts dependency analysis only and does not start a KB scan

### Requirement: No-wait exit
When `--no-wait` is set, the workflow SHALL start the selected operation, print that it is not waiting, emit a summary with `show_summary` false, and return true. It MUST NOT poll for completion.

#### Scenario: KB scan requested without waiting
- **WHEN** a KB scan is started with `--no-wait`
- **THEN** the command returns success immediately and tells the user to use `show-results`

### Requirement: Identification reuse degrades safely
Before a KB scan, the workflow SHALL resolve `--reuse-any-identification`, `--reuse-my-identifications`, `--reuse-project-ids`, or `--reuse-scan-ids`. A lookup failure for a project or scan reuse source MUST log a warning and continue the scan with no reuse values. Conflicting reuse flags are resolved by the first match in that order.

#### Scenario: Reuse scan cannot be found
- **WHEN** `--reuse-scan-ids` names a scan that does not exist
- **THEN** the KB scan still starts with identification reuse unset

### Requirement: Failed KB retry
If a waited KB scan fails and the result is not a cancellation, the workflow SHALL retry once with failed files only. A second failure MUST be reported and MUST NOT raise solely because the retry failed. A cancelled result, including a failure payload whose text contains "cancel", MUST NOT be retried.

#### Scenario: First KB attempt fails
- **WHEN** the waited KB scan status is failed and its message is not a cancellation
- **THEN** the workflow starts one `scan_failed_files` retry and waits again

#### Scenario: User cancelled the scan
- **WHEN** the KB result status is `CANCELLED` or its message contains "cancel"
- **THEN** the workflow does not start the failed-file retry

### Requirement: Dependency analysis after KB
When dependency analysis was requested with a KB scan, a dependency-analysis wait error MUST be reported as a warning and MUST NOT discard the completed KB result. The summary SHALL record whether dependency analysis completed.

#### Scenario: Dependency analysis wait fails after KB
- **WHEN** the KB scan finishes and the dependency-analysis wait raises
- **THEN** the workflow prints a warning, marks dependency analysis incomplete, and still prints the summary

### Requirement: Summary ownership
The workflow SHALL call `print_scan_summary` unless the caller passes `emit_summary=False`. `analyze` MUST suppress this summary because it prints a combined summary after importing dependency results.

#### Scenario: Analyze owns the summary
- **WHEN** `analyze` runs the first-party KB scan
- **THEN** `execute_scan_workflow` does not print the scan summary
