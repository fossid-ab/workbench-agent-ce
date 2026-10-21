# Spec Delta

## MODIFIED Requirements

### Requirement: Read-only resolution
`show-results` MUST follow `target-resolution-and-scan-reuse` with creation disabled, `preflight-and-status-waiting`, `report-validation-and-results`, and `handler-errors-and-redaction`. At least one `--show-*` flag is required by CLI validation. Pre-flight MUST complete successfully before results are fetched.

#### Scenario: Existing scan
- **WHEN** `show-results` names an existing project and scan
- **THEN** it waits until relevant operations are idle and fetches results without creating either target

#### Scenario: Pre-flight does not complete
- **WHEN** the shared read pre-flight wait times out or raises an API or network error
- **THEN** the command does not fetch or display results
