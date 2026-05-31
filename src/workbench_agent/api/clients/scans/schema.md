# Scans API (`group: scans`)

Workbench scan lifecycle, execution, Git, reports, and notice extract.  
This client wraps the `scans` group; orchestration lives in `api/services/`.

## Common request fields

| Field | Used by |
|-------|---------|
| `scan_code` | Most actions |
| `process_id` | `check_status` (async delete/report) |
| `type` | `check_status` (process type), `notice_extract_*` (extract type) |

## Actions (client methods)

| Action | Method |
|--------|--------|
| `list_scans` | `list_scans` |
| `get_information` | `get_information` |
| `get_folder_metrics` | `get_scan_folder_metrics` |
| `get_scan_identified_components` | `get_scan_identified_components` |
| `get_scan_identified_licenses` | `get_scan_identified_licenses` |
| `get_dependency_analysis_results` | `get_dependency_analysis_results` |
| `add_dependency_analysis_results` | `add_dependency_analysis_results` |
| `update_dependency_analysis_results` | `update_dependency_analysis_results` |
| `remove_dependency_analysis_results` | `remove_dependency_analysis_results` |
| `get_pending_files` | `get_pending_files` |
| `get_policy_warnings_counter` | `get_policy_warnings_counter` |
| `create` | `create` |
| `update` | `update` |
| `delete` | `delete` (raw; use `ScanDeletionService` for orchestration) |
| `download_content_from_git` | `download_content_from_git` |
| `check_status_download_content_from_git` | `check_status_download_content_from_git` |
| `remove_uploaded_content` | `remove_uploaded_content` |
| `extract_archives` | `extract_archives` |
| `run` | `run` |
| `run_dependency_analysis` | `run_dependency_analysis` |
| `check_status` | `check_status` |
| `generate_report` | `generate_report` |
| `notice_extract_run` | `notice_extract_run` |
| `notice_extract_download` | `notice_extract_download` |
| `import_report` | `import_report` |

## Response notes

- `list_scans`: `data` is often a **map** `{id: scan_details}`; client returns a **list** with `id` injected.
- `get_scan_identified_components`: `data` map → list of values; empty may be **`false`**
  (see [`quirks.md`](quirks.md)).
- `get_pending_files`: map of file id → path; errors may return `{}` (logged, not raised).

## `get_pending_files`

### Request (`data`)

| Field | API | Client param |
|-------|-----|--------------|
| `scan_code` | **R** | `scan_code` |

Payload shape: `group: scans`, `action: get_pending_files`.

### Response `data`

| Shape | Notes |
|-------|-------|
| `{file_id: relative_path}` | Map keyed by scan file id (string); **values** are relative paths for `files_and_folders` APIs |
| `[]` | Empty list → client returns `{}` |
| absent | Success without `data` → client returns `{}` |

Use **values** (e.g. `OpenFastPath/src/ofp_subr_hash.c`), not keys (file ids), when calling
`get_identification`, `get_fossid_results`, and other file-scoped actions.

See **`quirks.md` § get_pending_files`** and live fixtures in `tests/api/conftest.py`
(`pending_files`, `pending_paths`).

## `get_dependency_analysis_results`

### Request (`data`)

| Field | API | Client param |
|-------|-----|--------------|
| `scan_code` | **R** | `scan_code` |

Payload shape: `group: scans`, `action: get_dependency_analysis_results`.

### Response `data`

| Shape | Notes |
|-------|-------|
| List of dependency objects | Each row describes an imported dependency (name, version, package id, scopes, …) |
| absent / not run | Client returns **`[]`** (see `quirks.md`) |

Use **Dependency Analysis Test Scan** for live tests when KB was skipped and only DA
was run. See `tests/api/conftest.py` (`dependency_analysis_test_scan_code`).

## `add_dependency_analysis_results`

### Request (`data`)

| Field | API | Client param |
|-------|-----|--------------|
| `scan_code` | **R** | `scan_code` |
| `component_name` | **R** | `component_name` |
| `component_version` | **R** | `component_version` |
| `package_id` | **R** | `package_id` |
| `projects_and_scopes` | O | `projects_and_scopes` (JSON string) |
| `detailed_dependency_info` | O | `detailed_dependency_info` (JSON string) |
| `include_in_report` | O | `include_in_report` → `"0"` / `"1"` |

### Response `data`

Same shape as `update_dependency_analysis_results` (operation id
`scans_add_dependency_analysis_results`).

## `update_dependency_analysis_results`

### Request (`data`)

| Field | API | Client param |
|-------|-----|--------------|
| `scan_code` | **R** | `scan_code` |
| `component_name` | **R** | `component_name` |
| `component_version` | **R** | `component_version` |
| `package_id` | O | `package_id` |
| `projects_and_scopes` | O | `projects_and_scopes` (JSON string) |
| `detailed_dependency_info` | O | `detailed_dependency_info` (JSON string) |
| `include_in_report` | O | `include_in_report` → `"0"` / `"1"` |

### Response `data`

| Field | Type | Notes |
|-------|------|-------|
| `scan_id` | int | Scan row id |
| `component_id` | int | Updated dependency component id |
| `package_id` | string | Package id (e.g. PURL) |
| `projects_and_scopes` | string / null | JSON blob |
| `detailed_dependency_info` | string / null | JSON blob |
| `include_in_report` | bool | Report inclusion flag |
| `updated` | string | Timestamp |

## `remove_dependency_analysis_results`

### Request (`data`)

| Field | API | Client param |
|-------|-----|--------------|
| `scan_code` | **R** | `scan_code` |
| `component_name` | **R** | `component_name` |
| `component_version` | **R** | `component_version` |

### Response `data`

Boolean **`true`** on success.

## Other response notes

- `check_status`: `data` may be dict, string, or bool (`DELETE_SCAN` finished → normalized dict).
- `generate_report` / `notice_extract_download`: may return `_raw_response` for downloads.
