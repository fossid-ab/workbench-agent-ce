# Tasks

## 1. Policy classification

- [x] 1.1 Add `utilities/license_policy.py` with Workbench rule parsing and `classify` (allowed / conditional / prohibited / not covered)
- [x] 1.2 Unit tests in `tests/unit/utilities/test_license_policy.py` for blocked parsing, conditional reason prefixes, case-sensitive ids, and malformed rules

## 2. CLI

- [x] 2.1 Add `--project-name` / `--project` and `--project-code` to the `quick-scan` parser; reject both together in `_validate_quick_scan_command`
- [x] 2.2 Parser and validation tests for the new flags

## 3. Handler

- [x] 3.1 Replace the sentence formatter with the structured block formatter (omit absent fields, per-match header when more than one result)
- [x] 3.2 Resolve the project lookup-only and download its policy once before scanning; add policy warnings and not-covered notes per match
- [x] 3.3 Print `--raw` JSON with non-ASCII characters preserved
- [x] 3.4 Handler tests in `tests/unit/handlers/test_quick_scan_handler.py` using a captured two-result response: partial and full matches, missing copyright, prohibited and conditional warnings, not-covered note, project not found (no create, no scan), no project (no policy download), raw output

## 4. Validation

- [x] 4.1 Run `npx openspec validate quick-scan-license-policy --type change --strict` and the focused pytest files
