# Spec Delta

## MODIFIED Requirements

### Requirement: Read-only gate setup
`evaluate-gates` MUST follow `target-resolution-and-scan-reuse` with creation disabled, `preflight-and-status-waiting`, and `handler-errors-and-redaction`. Pre-flight MUST wait until KB scan and dependency analysis are idle. A pre-flight failure returns false, as required by the pre-flight capability, without running gate checks.

#### Scenario: Existing scan is ready
- **WHEN** the scan exists and its pre-flight check completes
- **THEN** the command evaluates all three gates and does not create a project or scan

#### Scenario: Pre-flight wait fails
- **WHEN** the shared read pre-flight wait times out or raises an API or network error
- **THEN** the command returns false and does not evaluate pending files, policy, or vulnerabilities
