# Spec Delta

## REMOVED Requirements

### Requirement: No project resolution
**Reason**: `quick-scan` may now resolve a project, lookup-only, to evaluate its license policy.
**Migration**: Replaced by "Lookup-only project resolution" and "Optional project policy". Without project flags the command still performs no project or scan resolution.

## ADDED Requirements

### Requirement: Lookup-only project resolution
`quick-scan` MUST NOT create or modify a project or scan, and MUST NOT resolve a scan. Supplying both `--project-name` and `--project-code` MUST fail CLI validation. A project that cannot be found MUST fail the command through `handler-errors-and-redaction` without running the quick scan. The command follows `handler-errors-and-redaction` for failures and terminal sections.

#### Scenario: Project not found
- **WHEN** `--project-name` names a project that does not exist
- **THEN** the command fails, no project is created, and no quick scan is performed

### Requirement: Optional project policy
Without `--project-name` or `--project-code` the command SHALL NOT resolve a project or download a policy. With one of them it SHALL resolve the project lookup-only and download that project's license policy from Workbench once, before scanning.

#### Scenario: File fingerprint without a project
- **WHEN** `quick-scan` is given a readable file and no project flag
- **THEN** it calls the quick-scan client and does not resolve a project or download a policy

#### Scenario: Project supplied
- **WHEN** `--project-name` names an existing project
- **THEN** the policy is downloaded once before the quick scan runs

### Requirement: Policy rule classification
A policy rule that is not blocked SHALL classify its license as allowed. A blocked rule whose reason begins with "conditionally approved" or "approved with condition", ignoring case, SHALL classify it as conditional. Any other blocked rule SHALL classify it as prohibited. License id matching MUST be case-sensitive. A license with no rule is not covered.

#### Scenario: Conditional reason prefix
- **WHEN** a blocked rule's reason starts with "Conditionally approved"
- **THEN** the license is classified as conditional

### Requirement: License policy warnings
When a policy is loaded, the command SHALL evaluate every distinct license id from the component's primary license and its detected licenses. Within the match block it MUST print a warning naming the license, the project, and the rule reason for each prohibited or conditional license, and SHALL print a note for each license the policy does not cover. Allowed licenses MUST NOT produce a warning. Policy findings MUST NOT change the command result.

#### Scenario: Prohibited license
- **WHEN** a match's license is classified as prohibited
- **THEN** the match block contains a policy violation warning with the license id, project, and reason, and the command returns true

#### Scenario: Conditionally approved license
- **WHEN** a match's license is classified as conditional
- **THEN** the match block contains a conditional-approval warning instead of a violation

#### Scenario: Secondary detected license
- **WHEN** the primary license is allowed but another detected license id is prohibited
- **THEN** the match block contains a violation warning for the detected license

#### Scenario: License not in policy
- **WHEN** a match's license has no rule in the project policy
- **THEN** the match block notes that the license is not covered by the project policy

## MODIFIED Requirements

### Requirement: Output format
Without `--raw`, an empty result SHALL print `No matches found.` Otherwise the command SHALL print one block per result, preceded by a `Match N of M` header when there is more than one result. Each block MUST open with a line stating a full match for type `file`, or a partial match with the remote snippet hit count and local coverage percentage for type `partial`; any other type MUST state `Unknown match type.` A result without a component MUST print `No matches found.` for that block. The block SHALL then list, omitting any line whose field is absent: component name and version, supplier, primary license with any other distinct detected license ids, copyright statements, package URL, and matched remote file path. With `--raw`, the command MUST print the JSON result with indentation 2, MUST preserve non-ASCII characters, and MUST NOT use the human-readable formatter or print policy warnings.

#### Scenario: Raw output
- **WHEN** `--raw` is set
- **THEN** stdout contains the JSON response and no human-readable match block

#### Scenario: Full-file match
- **WHEN** a result has type `file` and a component
- **THEN** the block states the entire file matched and lists the component name and supplier

#### Scenario: Partial match block
- **WHEN** a result has type `partial`, a component, and snippet statistics
- **THEN** the block states a partial match with the hit count and coverage, and lists the component name and version, supplier, and license

#### Scenario: Missing copyright
- **WHEN** a component has no copyright statements
- **THEN** the block omits the copyright line
