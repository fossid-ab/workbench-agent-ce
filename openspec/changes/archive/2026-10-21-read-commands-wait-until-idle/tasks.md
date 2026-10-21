# Tasks

## 1. Shared read pre-flight

- [x] 1.1 Extract a shared wait-for-KB-and-DA helper in `utilities/pre_flight_checks.py` and point `show_results_pre_flight_check`, `download_reports_pre_flight_check`, and `evaluate_gates_pre_flight_check` at it (propagate timeout/API/network errors; no soft-continue)
- [x] 1.2 Update `tests/unit/utilities/test_pre_flight_checks.py` so show-results and download-reports pre-flight raise on timeout/status failure, and evaluate-gates still propagates; verify with `pytest tests/unit/utilities/test_pre_flight_checks.py -q`

## 2. Handler alignment

- [x] 2.1 Confirm `show_results.py` and `download_reports.py` do not catch pre-flight failures (errors reach `handler_error_wrapper`); keep `evaluate_gates.py` mapping pre-flight failure to `return False`
- [x] 2.2 Add or adjust a unit/integration assertion that scan-scoped download-reports / show-results abort when pre-flight raises; verify with the focused pytest file(s) added or updated

## 3. Validation

- [x] 3.1 Run `npx openspec validate read-commands-wait-until-idle --type change --strict` and fix any issues

## Workflow follow-up

- Archive the change after review with `/opsx-archive` or the project archive flow.
