# Spec Delta

## MODIFIED Requirements

### Requirement: Read-only pre-flight failure
`show-results`, scan-scoped `download-reports`, and `evaluate-gates` SHALL wait for KB scan and dependency analysis to become idle before continuing. A pre-flight timeout, API error, or network error MUST abort the command so results, reports, or gates are not produced from an unverified scan. `show-results` and scan-scoped `download-reports` MUST propagate that failure to the handler error path. `evaluate-gates` MUST catch those errors, print a gate-evaluation failure, and return false without running gate checks.

#### Scenario: Show-results cannot verify completion
- **WHEN** a `show-results` status wait raises `ProcessTimeoutError`, `ApiError`, or `NetworkError`
- **THEN** the command does not fetch results

#### Scenario: Report generation starts after a status failure
- **WHEN** the KB or dependency-analysis wait raises during scan-scoped `download-reports`
- **THEN** the command does not generate or download reports

#### Scenario: Gates cannot confirm the scan is idle
- **WHEN** `evaluate_gates_pre_flight_check` raises `ProcessTimeoutError`
- **THEN** `evaluate-gates` returns false and does not query pending files, policy, or vulnerabilities
