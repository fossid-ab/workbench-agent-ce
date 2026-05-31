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
- `check_status`: `data` may be dict, string, or bool (`DELETE_SCAN` finished → normalized dict).
- `generate_report` / `notice_extract_download`: may return `_raw_response` for downloads.
