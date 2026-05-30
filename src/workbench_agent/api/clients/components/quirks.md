# Components API quirks (Workbench 2026.1)

Full field lists: [`schema.md`](schema.md) (from `components-api.txt`).  
Validated on cs-demo / `tests/api/clients/components/`.

## Spec vs observed behavior

| Area | Official spec | Observed (2026.1) |
|------|---------------|-------------------|
| `get_information` missing component | Not documented | `status: "1"`, `data: null` — no `ApiError` |
| `list_components` + `count_results` | `{count_results: int}` | May be bare numeric **string** (e.g. `"25481"`) |
| `get_usage.data.list` | Typed as object in spec | **Array** of usage rows in live responses |
| `get_usage.data.records_total` | Not in spec | Present on 2026.1 (see fixtures) |
| `create` response names | Plain strings in sample | `component_name` / `component_version` may be **base64** |
| `count_results` wire type | `list_components`: string; `list_by_usage`: integer | Client matches each action’s spec type |

## `get_information`

- Use `errors.is_missing_component_information()` to detect success + null.
- With version omitted, `data` is a **list**; with version, a **single dict**.

## `list_components`

- `order_by`: `version`, `name`, `license_name`, `license_identifier`, `created`, `updated`.
- `direction`: `ASC` or `DESC`.

## `get_usage`

- Pass `component_id` for typical usage queries.
- `order_by`: `scan_name`, `scan_code`, `scan_created`; `direction`: `asc` / `desc`.

## Errors (`status: "0"`)

- ``BaseAPI`` returns ``status: "0"`` for all ``components`` actions so the client
  can prefix ``Failed to …`` (live-validated).
- **Exception:** missing component on ``get_information`` → ``status: "1"``,
  ``data: null`` (not an ``ApiError``).
- ``delete`` / ``get_usage_count`` not-found: error text contains ``not found``.
