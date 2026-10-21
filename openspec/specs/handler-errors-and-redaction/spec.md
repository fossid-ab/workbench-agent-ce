# handler-errors-and-redaction Specification

## Purpose
Give every command handler one error path and exit-code policy, and keep credentials out of the debug log.

## Requirements

### Requirement: Handler return and exception contract
Each handler SHALL return true for success. `evaluate-gates` MAY return false when a gate fails. `download-reports` SHALL return true when at least one report downloads. The handler wrapper MUST log exceptions, wrap unexpected exceptions as `WorkbenchAgentError`, and re-raise them. Handlers MUST NOT print the shared error panel themselves.

#### Scenario: Unexpected handler exception
- **WHEN** a wrapped handler raises `RuntimeError`
- **THEN** the wrapper logs it and re-raises `WorkbenchAgentError` for `main` to present

### Requirement: Process exit codes
`main` SHALL exit 0 when a handler returns true. It MUST exit 1 when `evaluate-gates` returns false, using the gates-failed message instead of the generic error message. Validation, configuration, and authentication errors MUST exit 2. Other handled command errors MUST exit 1. A non-gates success MUST print the generic success line. Gates success MUST print the gates-passed line.

#### Scenario: Gates fail
- **WHEN** `evaluate-gates` returns false
- **THEN** the process exits 1 and prints `Gates FAILED`

#### Scenario: Invalid CLI input
- **WHEN** parsing or validation raises `ValidationError`
- **THEN** the process exits 2 and prints the formatted error

### Requirement: Read-only missing-target text
`format_and_print_error` SHALL treat `show-results`, `evaluate-gates`, and `download-reports` as read-only. Project and scan not-found errors for those commands MUST say the requested target does not exist and MUST NOT suggest that the command could create it.

#### Scenario: Show-results misses a project
- **WHEN** `show-results` raises `ProjectNotFoundError`
- **THEN** the message says the project was not found and does not offer to create it

### Requirement: Credential redaction
Startup debug logging SHALL pass parsed arguments through `redact_cli_args_for_logging`. Attributes named `api_token`, `password`, or `token`, and names ending in `_token`, `_password`, `_secret`, or `_key`, MUST be replaced with `***REDACTED***`. `None` values MUST remain `None`.

#### Scenario: Token logged at debug
- **WHEN** the process starts with an API token
- **THEN** the debug argument dump contains `***REDACTED***` instead of the token

### Requirement: Sectioned terminal output
Command handlers SHALL use `print_section` for major phase headings. Section formatting MUST NOT change a command's success or failure result.

#### Scenario: Command starts
- **WHEN** any command handler begins
- **THEN** it prints a titled section naming that command
