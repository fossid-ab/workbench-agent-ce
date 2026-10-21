# Design

## Context

See proposal.md for motivation. Today three read pre-flight helpers in `utilities/pre_flight_checks.py` diverge: `evaluate_gates_pre_flight_check` waits and propagates errors; `show_results_pre_flight_check` and `download_reports_pre_flight_check` catch broadly (including wait timeouts) and continue. Handlers call those helpers only; no API/SDK changes.

## Goals / Non-Goals

**Goals:**
- One shared wait path for the three read commands (KB + DA, same retry knobs).
- Abort before results/reports/gates when idle cannot be verified within the retry budget.
- Preserve evaluate-gates mapping of pre-flight failure to `return False`.

**Non-Goals:**
- Project-scoped multi-scan pre-flight.
- Changing write-command skip-on-unavailable-status behavior.
- New CLI flags for wait policy.

## Decisions

1. **Shared helper for read pre-flight**  
   Extract `_wait_for_kb_and_da(client, scan_code, params)` (or a public `read_command_pre_flight_check`) used by show-results, download-reports, and evaluate-gates. Keep the three named entry points as thin wrappers so handlers stay unchanged, or point handlers at one function—prefer one public function plus thin aliases if tests import the names.

2. **Error policy: propagate, don’t swallow**  
   Do not catch `ProcessTimeoutError`, `ApiError`, or `NetworkError` inside the shared wait. show-results / download-reports let `handler_error_wrapper` surface them. evaluate-gates keeps its existing `try/except` that prints and returns `false`.

3. **Unavailable status checks**  
   Match evaluate-gates for this change: do not soft-skip unknown status errors inside the read helper. If a status endpoint is unsupported, the command fails rather than continuing with unverified completion. Write-command skip behavior stays as-is.

4. **API boundary**  
   Continue calling only `client.status_check.check_scan_status` and `check_dependency_analysis_status` with `wait=True` and the existing retry parameters. No new client methods.

## Risks / Trade-offs

- [Older Workbench without status endpoints] → Read commands that previously soft-continued will now fail. Acceptable for correctness; document as **BREAKING** in the proposal.
- [Long-running scans] → Commands block up to `scan_number_of_tries * scan_wait_time` then fail. Users raise the knobs; no infinite wait.

## Migration Plan

Ship as a normal CE release note callout: scan-scoped read commands fail when pre-flight cannot confirm idle. No data migration. Rollback is reverting the utility/handler error-handling change.
