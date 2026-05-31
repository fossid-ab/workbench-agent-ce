# Scans API quirks (Workbench 2026.1+)

Field reference: [`schema.md`](schema.md).  
Unit coverage: `tests/api/clients/scans/test_scans_client.py`.

## Not found

| Signal | Client behavior |
|--------|-----------------|
| `Scan not found`, `row_not_found` in `error` | `ScanNotFoundError` when `BaseAPI` returns JSON with `status: "0"` to the client |
| `get_information`, `get_folder_metrics`, `get_pending_files` (2026.1) | `status: "0"` + `row_not_found` → **`BaseAPI` raises `ApiError`** before client mapping |
| `get_scan_identified_*`, `get_policy_warnings_counter` | Often `ScanNotFoundError` via client when error text matches |
| `check_status` with `scan_code=None` | Same markers → `ScanNotFoundError` with process context |

### Live test timing

Invalid ``scan_code`` requests on several scan actions can take **1–3 minutes each**
(server-side). Live tests use one session probe for ``row_not_found`` instead of
hitting every endpoint. ``BaseAPI._send_request`` defaults to a **1800s** HTTP
timeout; scans live tests cap this via ``WORKBENCH_LIVE_API_TIMEOUT`` (default 120s).

## `list_scans`

- Success `data` is usually a **dict** keyed by numeric id strings, not a list.
- Empty list `data` → `[]`.

## `get_pending_files`

Entry point for **auditor / identification workflows** on a scan with pending work.
Call once per scan, then pass each returned **path** to `files_and_folders` read and write
APIs (`get_identification`, `get_fossid_results`, `get_matched_lines`, mutations, etc.).

| Topic | Observed (2026.1 live) |
|-------|---------------------------|
| Request | `scan_code` only (see `schema.md`) |
| Success `data` | **`{file_id: relative_path}`** — e.g. `{"1830925": "Android-Bluetooth/Foo.java"}` |
| Path values | Relative paths within the scan tree; use **values**, not numeric keys, for file APIs |
| Empty scan | `{}` or `data: []` → client returns `{}` |
| API failure | Returns **`{}`** and logs (does not raise) |
| Not found | Invalid `scan_code` may raise via `BaseAPI` (`row_not_found`) — see table above |

Live tests on **Unidentified Test Scan** resolve paths via
`workbench_client.scans.get_pending_files` in `tests/api/conftest.py` (`pending_files`,
`pending_paths`, `pending_path`, and derived fixtures such as `snippet_file_path`).

## `get_dependency_analysis_results`

Dependency list for scans where **Dependency Analysis** was run (with or without KB).
On **Dependency Analysis Test Scan** (DA-only, KB skipped), expect a non-empty list and
**no** KB identified components from `get_scan_identified_components`.

| Topic | Observed (2026.1 live) |
|-------|---------------------------|
| Request | `scan_code` only |
| Success `data` | **List** of dependency dicts |
| Not run | Error text `Dependency analysis has not been run` → client returns **`[]`** |
| Row fields | `name`, `version`, `component_id`, `package_id`, `supplier_name`, `is_direct_dependency`, `is_transitive_dependency`, … |
| `package_id` | Package URL style id (e.g. `Maven:aopalliance:aopalliance:1.0`) |

Live fixtures: `dependency_analysis_test_scan_code`, `scan_has_da_results` in
`tests/api/conftest.py`. Tests: `TestScansLiveDependencyAnalysis` in
`tests/api/clients/scans/test_scans_live.py`.

## `add_dependency_analysis_results`

Adds a dependency row to DA results. Response shape matches update (operation id
`scans_add_dependency_analysis_results`).

| Topic | Observed / client behavior |
|-------|----------------------------|
| `package_id` | **Required** on add (PURL-style id; must refer to a resolvable package) |
| Catalog prerequisite | Component must exist in catalog — use **`ComponentService.resolve`** |

Prefer **`DependencyService.add_dependency`**, which resolves the catalog row
automatically. Live add/remove tests: `tests/api/services/dependency/`.

## `update_dependency_analysis_results`

Updates a single dependency analysis row (report inclusion, scope JSON, etc.).

| Topic | Observed / client behavior |
|-------|----------------------------|
| `include_in_report` | Send `"0"` / `"1"` strings; response `data.include_in_report` is **boolean** |
| Optional JSON fields | Pass pre-serialized JSON strings for `projects_and_scopes` / `detailed_dependency_info` |
| `package_id` | Optional disambiguator when multiple rows share name/version |

## `remove_dependency_analysis_results`

Removes a dependency row from DA results. Success `data` is boolean **`true`**
(operation id `scans_remove_dependency_analysis_results`).

## `get_scan_identified_components`

- Spec success `data` is usually a **map** `{id: component_details}`; client returns
  `list(data.values())`.
- On Workbench 2026.1, when there are **no** identified components, `data` may be boolean
  **`false`** (not `{}`) with `status: "1"` and `message: "Success"`.
- Client treats non-dict `data` as empty → **`[]`**.

## `remove_uploaded_content`

- Invalid `filename` → parsing error `filename_is_not_valid` → returns **`True`** (treat as already gone).

## `check_status`

- `DELETE_SCAN` when finished: `data` may be boolean **`true`** → normalized to `progress_state: FINISHED`.
- Git status (`check_status_download_content_from_git`): `data` may be a **string** (`NOT FINISHED`, etc.) → wrapped as `{"data": "..."}`.

## `delete`

- Returns raw JSON; use **`ScanDeletionService`** for polling and not-found handling.

## Services vs client

Prefer **`ScanOperationsService`**, **`ReportService`**, **`ScanDeletionService`**, **`ScanContentService`**, **`DependencyService`** for validation and workflows; `ScansClient` is the thin API layer.
