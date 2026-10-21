# quick-scan-command Specification

## Purpose
Match one local file with the Workbench quick-scan operation without creating a project or scan. This is the collaboration surface for `handlers/quick_scan.py`.

## Requirements

### Requirement: No project resolution
`quick-scan` MUST NOT resolve, create, or modify a project or scan. It follows `handler-errors-and-redaction` for failures and terminal sections.

#### Scenario: File fingerprint
- **WHEN** `quick-scan` is given a readable file
- **THEN** it calls the quick-scan client and does not call project or scan resolution

### Requirement: Request contents
The command SHALL read the file in binary, base64-encode it, and send it with `--limit` and `--sensitivity`. File-read failures MUST propagate through the handler wrapper.

#### Scenario: Missing file
- **WHEN** the path cannot be opened
- **THEN** the handler wrapper logs the exception and the process exits through the shared error policy

### Requirement: Output format
Without `--raw`, an empty result SHALL print `No matches found.` A file match MUST name the artifact and author. A partial match MUST include the remote hit count, artifact, and author. Any other match type MUST print `Unknown match type.` A result without a component MUST print `No matches found.` With `--raw`, the command MUST print the JSON result with indentation 2 and MUST NOT use the human-readable formatter.

#### Scenario: Raw output
- **WHEN** `--raw` is set
- **THEN** stdout contains the JSON response and no human-readable match sentence

#### Scenario: Full-file match
- **WHEN** a result has type `file` and a component
- **THEN** the printed sentence says the entire file matched that artifact and author

### Requirement: Command success
A completed quick scan SHALL return true even when no matches are found.

#### Scenario: No matches
- **WHEN** the client returns an empty list
- **THEN** the command prints `No matches found.` and returns true
