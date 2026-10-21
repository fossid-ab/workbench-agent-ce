# delete-scan-command Specification

## Purpose
Delete an existing scan after a permission check. This is the collaboration surface for `handlers/delete_scan.py`.

## Requirements

### Requirement: Lookup without creation
`delete-scan` MUST follow `target-resolution-and-scan-reuse` with creation disabled and `handler-errors-and-redaction`. It does not run a pre-flight idle check.

#### Scenario: Named scan exists
- **WHEN** `delete-scan` names an existing project and scan
- **THEN** it resolves their codes and does not create either target

### Requirement: Permission check
The command SHALL call `can_delete_scan` before deletion. A false result MUST raise `WorkbenchAgentError` with the fixed permission-denied message and MUST NOT start deletion.

#### Scenario: User cannot delete
- **WHEN** `can_delete_scan` returns false
- **THEN** deletion is not requested and the permission-denied error propagates

### Requirement: Deletion wait
Deletion SHALL pass `--delete-identifications` through as `delete_identifications`. The command MUST poll with `scan_number_of_tries` and a fixed 2-second interval, not `--scan-wait-time`. A result with `success` false MUST raise `WorkbenchAgentError` containing the server error message or status.

#### Scenario: Deletion job fails
- **WHEN** the deletion result has `success` false
- **THEN** the handler raises `WorkbenchAgentError` and does not print the success line

### Requirement: Success output
On success, the command SHALL print the scan name supplied by the user and the resolved scan code. When the server reports a duration, the command MUST print it to one decimal place. The handler MUST then return true.

#### Scenario: Deletion completes
- **WHEN** the deletion result has `success` true and a duration
- **THEN** the handler prints the scan name, code, and duration, then returns true
