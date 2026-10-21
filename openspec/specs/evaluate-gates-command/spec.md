# evaluate-gates-command Specification

## Purpose
Evaluate pending-file, license-policy, and vulnerability gates for an existing scan and return whether all gates passed. This is the collaboration surface for `handlers/evaluate_gates.py`.

## Requirements

### Requirement: Read-only gate setup
`evaluate-gates` MUST follow `target-resolution-and-scan-reuse` with creation disabled, `preflight-and-status-waiting`, and `handler-errors-and-redaction`. Pre-flight MUST wait until KB scan and dependency analysis are idle. A pre-flight failure returns false, as required by the pre-flight capability, without running gate checks.

#### Scenario: Existing scan is ready
- **WHEN** the scan exists and its pre-flight check completes
- **THEN** the command evaluates all three gates and does not create a project or scan

#### Scenario: Pre-flight wait fails
- **WHEN** the shared read pre-flight wait times out or raises an API or network error
- **THEN** the command returns false and does not evaluate pending files, policy, or vulnerabilities

### Requirement: Pending-file gate
The command SHALL count pending identification files. With `--fail-on-pending`, a count above zero or an API/network error MUST fail the gate. Without that flag, pending files or a check error MUST keep the gate passing while still reporting the count or error.

#### Scenario: Pending files fail the build
- **WHEN** pending files exist and `--fail-on-pending` is set
- **THEN** the pending gate fails and the overall result is false

#### Scenario: Pending files are informational
- **WHEN** pending files exist and `--fail-on-pending` is absent
- **THEN** the pending gate passes and the summary still shows the count

### Requirement: Policy gate
The command SHALL read `policy_warnings_total` from either the nested `data` object or the top-level payload, falling back to `total`. Non-dictionary payloads count as zero. With `--fail-on-policy`, a positive count or an API/network error MUST fail the gate. Without that flag, warnings or check errors MUST keep the gate passing.

#### Scenario: Policy warnings fail the build
- **WHEN** the warning count is positive and `--fail-on-policy` is set
- **THEN** the policy gate fails

### Requirement: Vulnerability gate
The command SHALL count vulnerabilities as `critical`, `high`, `medium`, `low`, or `other`, in that severity order. `--fail-on-vuln-severity` MUST fail the gate when any vulnerability at the named severity or higher has a count above zero. `other` MUST NOT satisfy a severity threshold. Without the flag, any vulnerability count MUST leave the gate passing. An API/network error MUST fail the gate only when the severity flag is set.

#### Scenario: High threshold
- **WHEN** a critical vulnerability exists and the threshold is `high`
- **THEN** the vulnerability gate fails

#### Scenario: Below threshold
- **WHEN** only low vulnerabilities exist and the threshold is `high`
- **THEN** the vulnerability gate passes

### Requirement: Overall result and next steps
The handler SHALL return true only when all three gates pass. It MUST print a summary showing enabled gates as passed or failed and disabled gates as counts. It MUST request Workbench links once. A link lookup failure MUST be ignored. Next-step links MUST appear for pending files when that gate fails or its count is positive, and for policy or vulnerabilities only when that gate fails.

#### Scenario: Only pending files need action
- **WHEN** pending files exist, policy and vulnerability gates pass, and links are available
- **THEN** next steps include the pending-files link and omit the policy and vulnerability links
