# show-results-command Specification

## Purpose
Display selected results for an existing scan without creating or modifying Workbench data. This is the collaboration surface for `handlers/show_results.py`.

## Requirements

### Requirement: Read-only resolution
`show-results` MUST follow `target-resolution-and-scan-reuse` with creation disabled, `preflight-and-status-waiting`, `report-validation-and-results`, and `handler-errors-and-redaction`. At least one `--show-*` flag is required by CLI validation. Pre-flight MUST complete successfully before results are fetched.

#### Scenario: Existing scan
- **WHEN** `show-results` names an existing project and scan
- **THEN** it waits until relevant operations are idle and fetches results without creating either target

#### Scenario: Pre-flight does not complete
- **WHEN** the shared read pre-flight wait times out or raises an API or network error
- **THEN** the command does not fetch or display results

### Requirement: Scan identity
The command SHALL use scan information returned by resolution. If that information is absent, it MUST fetch scan information before displaying results. The project code from resolution MUST be passed to result fetching for project-level sections.

#### Scenario: Project policy section
- **WHEN** `--show-project-policy-warnings` is set
- **THEN** result fetching receives the resolved project code

### Requirement: Command success
`handle_show_results` SHALL return true after results are fetched and displayed. A save warning from result utilities MUST NOT change that success.

#### Scenario: Results displayed
- **WHEN** pre-flight completes and result fetching returns
- **THEN** the handler returns true
