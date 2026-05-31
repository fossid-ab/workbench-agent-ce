# Scans API quirks (Workbench 2026.1+)

Field reference: [`schema.md`](schema.md).  
Unit coverage: `tests/api/clients/scans/test_scans_client.py`.

## Not found

| Signal | Client behavior |
|--------|-----------------|
| `Scan not found`, `row_not_found` in `error` | `ScanNotFoundError` when `BaseAPI` returns JSON with `status: "0"` to the client |
| `get_information`, `get_folder_metrics`, `get_pending_files` (2026.1 cs-demo) | `status: "0"` + `row_not_found` → **`BaseAPI` raises `ApiError`** before client mapping |
| `get_scan_identified_*`, `get_policy_warnings_counter` | Often `ScanNotFoundError` via client when error text matches |
| `check_status` with `scan_code=None` | Same markers → `ScanNotFoundError` with process context |

### Live test timing (cs-demo)

Invalid ``scan_code`` requests on several scan actions can take **1–3 minutes each**
(server-side). Live tests use one session probe for ``row_not_found`` instead of
hitting every endpoint. ``BaseAPI._send_request`` defaults to a **1800s** HTTP
timeout; scans live tests cap this via ``WORKBENCH_LIVE_API_TIMEOUT`` (default 120s).

## `list_scans`

- Success `data` is usually a **dict** keyed by numeric id strings, not a list.
- Empty list `data` → `[]`.

## `get_pending_files`

- On API failure, returns **`{}`** and logs (does not raise).

## `get_dependency_analysis_results`

- `Dependency analysis has not been run` → **`[]`** (not an error).

## `get_scan_identified_components`

- Spec success `data` is usually a **map** `{id: component_details}`; client returns
  `list(data.values())`.
- On 2026.1 cs-demo, when there are **no** identified components, `data` may be boolean
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

Prefer **`ScanOperationsService`**, **`ReportService`**, **`ScanDeletionService`**, **`ScanContentService`** for validation and workflows; `ScansClient` is the thin API layer.
