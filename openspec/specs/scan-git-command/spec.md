# scan-git-command Specification

## Purpose
Clone a Git repository into a Workbench scan on the server, remove the `.git` directory, and run the shared scan workflow. This is the collaboration surface for `handlers/scan_git.py`.

## Requirements

### Requirement: Shared Git scan behavior
`scan-git` MUST follow `target-resolution-and-scan-reuse`, `preflight-and-status-waiting`, `scan-execution-workflow`, and `handler-errors-and-redaction`. Git target fields used at creation are part of target resolution.

#### Scenario: New Git scan
- **WHEN** `scan-git` names a new scan and a Git URL with a branch, tag, or commit
- **THEN** it creates the scan with that Git target, clones it, and delegates to `execute_scan_workflow`

### Requirement: Server-side clone
`scan-git` SHALL clone through `download_git_and_wait` using `scan_number_of_tries` and a 3-second interval. The clone duration MUST be recorded as `git_clone`. Any clone failure MUST raise `WorkbenchAgentError` and MUST NOT continue to scan execution.

#### Scenario: Clone fails
- **WHEN** the Git clone raises
- **THEN** the command raises `WorkbenchAgentError` and does not remove content or start a scan

### Requirement: Git metadata removal
After a successful clone, `scan-git` SHALL try to remove `.git/`. A removal failure MUST be printed as a warning and MUST NOT stop the scan.

#### Scenario: Metadata removal fails
- **WHEN** removing `.git/` raises
- **THEN** the command warns and still calls `execute_scan_workflow`

### Requirement: Command success
`handle_scan_git` SHALL return the boolean returned by `execute_scan_workflow`.

#### Scenario: Workflow returns success
- **WHEN** the scan workflow finishes and returns true
- **THEN** `handle_scan_git` returns true
