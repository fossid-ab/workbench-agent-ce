# Legacy CLI Compatibility — Implementation Plan

**Status:** Implemented

**Reference implementation:** [`workbench-agent/workbench-agent.py`](https://github.com/fossid-ab/workbench-agent/blob/main/workbench-agent.py)

**User-facing migration doc:** [[Legacy-Migration-Guide]] (wiki)

---

## Goal

Allow existing CI scripts that invoke the legacy agent (underscore flags, no subcommand, single flat pipeline) to run unchanged against **workbench-agent-ce** by:

1. Detecting legacy argv before argparse
2. Translating flags to CE subcommands and kebab-case options
3. Orchestrating **scan → show-results** in one process (matching legacy `main()`)

Modern CE invocations (explicit subcommands) must be unaffected.

---

## Out of scope

| Legacy feature | Decision |
|----------------|----------|
| `--target_path` | **Not supported.** Server-side scan path with no upload. Document in migration guide; fail with clear error if present. |
| `--chunked_upload` | **Dropped.** CE upload layer handles large files. Silently ignore. |
| Raw API JSON on stdout | CE prints summaries. Saved JSON uses structured keys (`kb_licenses`, `kb_matches`, …). Document difference; no raw-json compat mode in v1. |
| `log-agent.txt` | CE uses `workbench-agent-log.txt`. Document only. |

---

## Architecture

```
sys.argv
    │
    ▼
is_legacy_argv()? ──no──► parse_cmdline_args() ──► single handler
    │
   yes
    ▼
translate_legacy_argv() ──► LegacyPipeline
    │
    ├── scan_argv      (scan | blind-scan + translated flags)
    └── show_argv      (show-results + --show-* + --result-save-path)
    │
    ▼
main(): run scan handler → run show-results handler
```

### New modules

| File | Responsibility |
|------|----------------|
| `src/workbench_agent/cli/legacy_compat.py` | Detection, flag translation, ID reuse mapping, result-flag resolution, `path-result` normalization |
| `src/workbench_agent/cli/legacy_types.py` | `LegacyPipeline` dataclass (optional; can live in legacy_compat.py) |

### Modified modules

| File | Change |
|------|--------|
| `src/workbench_agent/cli/parser.py` | `parse_cmdline_args(argv: Optional[List[str]] = None)` |
| `src/workbench_agent/main.py` | Legacy pipeline orchestration before/instead of single dispatch |
| `tests/unit/cli/test_legacy_compat.py` | Translation matrix tests |
| `tests/unit/cli/test_legacy_orchestration.py` | Two-phase main() tests (mock handlers) |

---

## Legacy detection

Treat argv as **legacy** when **all** of:

1. First token after program name is **not** a known CE subcommand
2. First token is not `-h` / `--help` / `--version`
3. At least one **legacy marker** is present

**Known subcommands:** `scan`, `blind-scan`, `scan-git`, `analyze`, `show-results`, `evaluate-gates`, `download-reports`, `import-da`, `import-sbom`, `delete-scan`, `quick-scan`

**Legacy markers (any one):**

- `--api_url`
- `--project_code`
- `--scan_code`
- Any flag in `LEGACY_UNDERSCORE_FLAGS` (see mapping table below)

---

## Command routing

| Legacy condition | CE subcommand |
|------------------|---------------|
| `--blind_scan` | `blind-scan` |
| otherwise | `scan` |

Reject early:

- `--target_path` → `ValidationError` with migration hint
- `--run_only_dependency_analysis` + `--blind_scan` → same rule as CE (`dependency-analysis-only` + blind-scan)

---

## Flag mapping

### Connection & target

| Legacy | CE |
|--------|-----|
| `--api_url` | `--api-url` |
| `--api_user` | `--api-user` |
| `--api_token` | `--api-token` |
| `--project_code` | `--project-code` |
| `--scan_code` | `--scan-code` |
| `--path` | `--path` |

Legacy always uses codes for both project and scan. Map directly to CE `--project-code` / `--scan-code` (do **not** map to `--project-name` / `--scan-name`).

### Scan configuration

| Legacy | CE |
|--------|-----|
| `--limit` | `--limit` |
| `--sensitivity` | `--sensitivity` |
| `--recursively_extract_archives` | `--recursively-extract-archives` (see defaults) |
| `--jar_file_extraction` | `--jar-file-extraction` |
| `--run_dependency_analysis` | `--run-dependency-analysis` |
| `--run_only_dependency_analysis` | `--dependency-analysis-only` |
| `--auto_identification_detect_declaration` | `--autoid-file-licenses` |
| `--auto_identification_detect_copyright` | `--autoid-file-copyrights` |
| `--auto_identification_resolve_pending_ids` | `--autoid-pending-ids` |
| `--delta_only` | `--delta-scan` |
| `--no_advanced_match_scoring` | `--no-advanced-match-scoring` |
| `--match_filtering_threshold` | `--match-filtering-threshold` |
| `--use_projectscan` | `--use-projectscan` |
| `--scan_number_of_tries` | `--scan-number-of-tries` |
| `--scan_wait_time` | `--scan-wait-time` |
| `--log` | `--log` |

### Dropped (ignore)

| Legacy | Action |
|--------|--------|
| `--chunked_upload` | Omit |

### ID reuse (conditional)

Only when `--reuse_identifications` is present:

| `identification_reuse_type` | CE flag | Notes |
|----------------------------|---------|-------|
| `any` | `--reuse-any-identification` | |
| `only_me` | `--reuse-my-identifications` | |
| `specific_project` | `--reuse-project-ids` + value from `--specific_code` | |
| `specific_scan` | `--reuse-scan-ids` + value from `--specific_code` | |

When `--reuse_identifications` is **absent**, emit no reuse flags.

---

## Default normalization (critical)

Legacy and CE defaults differ. When translating legacy argv, **inject explicit CE flags** so behavior matches legacy:

| Setting | Legacy default | CE default | Translator action when legacy flag absent |
|---------|----------------|------------|---------------------------------------------|
| Archive recursion | **off** | **on** | Add `--no-recursively-extract-archives` |
| Log level | `ERROR` | `WARNING` | Add `--log ERROR` |
| Match filtering threshold | `-1` | server config | Add `--match-filtering-threshold -1` |

When legacy **explicitly** sets `--recursively_extract_archives`, emit `--recursively-extract-archives` (no `--no-…`).

---

## Result phase (show-results)

Legacy **always** fetches results after scan. Result mode is **mutually exclusive** (first match in legacy `main()`):

| Priority | Legacy flag | CE show-results flag |
|----------|-------------|----------------------|
| 1 | `--get_scan_identified_components` | `--show-components` |
| 2 | `--scans_get_policy_warnings_counter` | `--show-policy-warnings` |
| 3 | `--projects_get_policy_warnings_info` | `--show-project-policy-warnings` |
| 4 | `--scans_get_results` | `--show-matches` |
| 5 | *(default)* | `--show-licenses` |

Build `show-results` argv with:

- Same connection + target flags (`--project-code`, `--scan-code`, …)
- Same monitoring flags (`--scan-number-of-tries`, `--scan-wait-time`)
- Exactly **one** `--show-*` from table above
- `--result-save-path` when `--path-result` present (see below)

Scan-phase argv must **not** include result flags or `--path-result`.

---

## `--path-result` normalization

Legacy `save_results()` behavior → CE `--result-save-path`:

| Legacy `--path-result` | CE `--result-save-path` |
|------------------------|---------------------------|
| Directory path | `{dir}/wb_results.json` |
| File path ending in `.json` | Use as-is |
| File path without `.json` | Replace extension with `.json` (legacy behavior) |
| Non-existent path treated as directory | `{path}/wb_results.json` (legacy fallback) |

Implement in `normalize_result_save_path(path_result: str) -> str`.

---

## `main()` orchestration

```python
def main() -> int:
    pipeline = build_legacy_pipeline(sys.argv)
    if pipeline is None:
        return run_single_command(parse_cmdline_args())

    exit_code = run_single_command(parse_cmdline_args(pipeline.scan_argv))
    if exit_code != 0:
        return exit_code

    if pipeline.show_argv is not None:
        return run_single_command(parse_cmdline_args(pipeline.show_argv))
    return exit_code
```

Extract `run_single_command(args)` from current handler dispatch (client init, handler call, exit code logic) to avoid duplication.

**Note:** Legacy runs show-results even when scan-only DA path (`run_only_dependency_analysis`) — still fetches licenses (or alternate result flag) at end. Replicate that.

---

## Implementation tasks (order)

### Phase 1 — Translation core

- [x] **1.1** Add `legacy_compat.py` with `is_legacy_argv()`, `LEGACY_FLAG_MAP`, `translate_legacy_argv()`
- [x] **1.2** Implement ID reuse mapping (`translate_reuse_flags()`)
- [x] **1.3** Implement result-flag resolution (`resolve_legacy_result_flags()` → single `--show-*`)
- [x] **1.4** Implement default normalization (`apply_legacy_defaults()`)
- [x] **1.5** Implement `normalize_result_save_path()`
- [x] **1.6** Reject `--target_path` with actionable error

### Phase 2 — Wiring

- [x] **2.1** `parse_cmdline_args(argv=None)` — pass through to `parser.parse_args(argv)`
- [x] **2.2** `build_legacy_pipeline(argv) -> Optional[LegacyPipeline]`
- [x] **2.3** Refactor `main.py` for two-phase legacy run
- [x] **2.4** Export/test via `workbench-agent` entrypoint unchanged

### Phase 3 — Tests

- [x] **3.1** Translation matrix: one test per legacy flag rename
- [x] **3.2** ID reuse: 4 type × with/without master flag
- [x] **3.3** Result flags: priority order + default licenses
- [x] **3.4** Default normalization: no `--recursively_extract_archives` → `--no-recursively-extract-archives`
- [x] **3.5** `path-result` directory/file/nonexistent cases
- [x] **3.6** `--target_path` rejection
- [x] **3.7** Orchestration: mock handlers called in order with expected argv
- [x] **3.8** Modern argv unchanged (regression: existing `test_argument_parsing.py`)

### Phase 4 — Documentation

- [x] **4.1** Wiki [[Legacy-Migration-Guide]] (mapping tables + examples)
- [x] **4.2** Link from [[Core-Concepts]]
- [x] **4.3** Add to wiki `_Sidebar.md` under Advanced Topics
- [x] **4.4** Note in [[show-results]] that legacy result flags route there

---

## Test examples (golden argv)

### Basic scan + default licenses

**Legacy:**
```bash
workbench-agent \
  --api_url https://wb/api.php --api_user u --api_token t \
  --project_code PRJ --scan_code SCN --path ./src
```

**Translated scan argv:**
```bash
workbench-agent scan \
  --api-url ... --project-code PRJ --scan-code SCN --path ./src \
  --no-recursively-extract-archives --log ERROR \
  --match-filtering-threshold -1
```

**Translated show argv:**
```bash
workbench-agent show-results \
  --api-url ... --project-code PRJ --scan-code SCN \
  --show-licenses --log ERROR
```

### Blind scan + matches + save

**Legacy:** `... --blind_scan --scans_get_results --path-result /tmp/out/`

**Scan:** `blind-scan ...`  
**Show:** `show-results ... --show-matches --result-save-path /tmp/out/wb_results.json`

### Project policy warnings

**Legacy:** `... --projects_get_policy_warnings_info`

**Show:** `show-results ... --show-project-policy-warnings`

---

## Acceptance criteria

1. All golden argv tests pass without network
2. Existing CE unit tests unchanged (no regressions)
3. Legacy marker detection does not trigger on modern `workbench-agent scan ...`
4. Two-phase run executes scan then show-results with matching project/scan codes
5. Migration guide published with explicit “unsupported” section for `--target_path`

---

## CE prerequisites (done)

- [x] `--project-code` / `--scan-code`
- [x] `--use-projectscan`
- [x] `--show-matches` (`scans.get_results`)
- [x] `--show-project-policy-warnings` (`projects.get_policy_warnings_info`)
- [x] All other `--show-*` flags on `show-results`
- [x] `show-results` wiki guide
