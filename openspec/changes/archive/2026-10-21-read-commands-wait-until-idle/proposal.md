# Proposal

## Why

Scan-scoped read commands already wait when KB scan or dependency analysis is active, but `show-results` and `download-reports` swallow wait/status failures and continue with possibly incomplete data. That undercuts the purpose of pre-flight. Read commands should finish waiting for idle (or fail clearly) before producing results, reports, or gate outcomes.

## What Changes

- **BREAKING**: `show-results` and scan-scoped `download-reports` no longer warn-and-continue when a KB or dependency-analysis wait/status check times out or returns an API/network error. Those failures abort the command.
- Unify read-command pre-flight so `show-results`, scan-scoped `download-reports`, and `evaluate-gates` wait for KB scan and dependency analysis using `scan_number_of_tries` / `scan_wait_time`, then proceed only when idle.
- Keep `evaluate-gates` translating a pre-flight timeout/API/network failure into a failed command result (`false`) without running gate checks.
- Update `preflight-and-status-waiting` (and thin command-spec references) to remove the soft-continue read-only failure policy for show-results and download-reports.

## Capabilities

### New Capabilities

- (none)

### Modified Capabilities

- `preflight-and-status-waiting`: Replace soft-continue read-only failure for show-results and scan-scoped download-reports with wait-until-idle, fail-on-unverified-completion semantics shared with evaluate-gates wait behavior.
- `show-results-command`: Reference the stricter shared pre-flight failure policy (no incomplete-results continue).
- `download-reports-command`: Same for scan scope only; project scope remains without scan pre-flight for now.
- `evaluate-gates-command`: Clarify that pre-flight waits for idle before gates; failure still returns false without gate checks.

## Non-goals

- Project-scoped `download-reports` pre-flight across all project scans.
- Changing write-command pre-flight skip-on-unavailable-status behavior.
- API/SDK wire-contract changes.
- Infinite waits beyond `scan_number_of_tries` / `scan_wait_time`.

## Impact

- `utilities/pre_flight_checks.py` (`show_results_pre_flight_check`, `download_reports_pre_flight_check`; possibly shared helper with `evaluate_gates_pre_flight_check`)
- Handlers that call those checks (`show_results.py`, `download_reports.py`, `evaluate_gates.py`) only if error handling needs alignment
- Unit tests in `tests/unit/utilities/test_pre_flight_checks.py` and any handler coverage of soft-continue
