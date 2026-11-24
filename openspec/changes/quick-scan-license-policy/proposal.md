# Proposal

## Why

`quick-scan` is used to check single files before commit, but its output is one sentence naming only the artifact and author. Developers cannot see the license, version, or copyright of the matched component, and cannot tell whether the match is acceptable under their project's license policy without opening Workbench.

## What Changes

- **BREAKING (output only)**: Replace the one-line match sentence with a structured block per match: match type (with snippet hits and local coverage for partial matches), component name and version, supplier, license (plus other detected license ids), copyright, package URL, and matched remote file. Lines whose fields are absent are omitted.
- Add optional `--project-name` / `--project` and `--project-code` to `quick-scan`. When given, the command resolves the project lookup-only (never creating it), downloads the project's license policy from Workbench once, and evaluates every distinct license id of each match against it.
- Print a policy warning in the match block when a license is prohibited or conditionally approved, and a short note when a license is not covered by the policy. Policy findings are informational: the command still succeeds.
- `--raw` keeps printing the API result unchanged, but no longer escapes non-ASCII characters.

## Capabilities

### New Capabilities

- (none)

### Modified Capabilities

- `quick-scan-command`: Structured output, optional lookup-only project resolution, and license policy warnings.

## Non-goals

- Reading or writing local policy files (`.fossid/policy.json`, `.fossidpolicy`). Policy comes only from Workbench.
- Category-level policy rules (Workbench project policies are license-level).
- Failing the command or changing the exit code on policy violations (no gate behavior).
- API/SDK or Workbench wire-schema changes; the existing quick-scan client and `PolicyService.download_project_policy_json` are reused.

## Impact

- `handlers/quick_scan.py` (formatter, project resolution, policy evaluation wiring)
- New `utilities/license_policy.py` (policy rule classification)
- `cli/parser.py` and `cli/validators.py` (new flags and mutual exclusion)
- Unit tests for the utility, handler, and CLI parsing
