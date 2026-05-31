# API clients layout

Domain clients live here. Newer clients use a **package per domain**:

```
clients/<domain>/
  __init__.py    # public export (e.g. ComponentsClient)
  client.py      # HTTP methods
  errors.py      # error mapping, path rules, response helpers
  schema.md      # request/response fields
  quirks.md      # spec vs live behavior (2026.1+)
```

**Contracts and JSON fixtures** stay in `tests/api/support/` — not duplicated under `src/`.

## Packaged clients

| Package | Notes |
|---------|--------|
| `components/` | Catalog CRUD; `get_information` may return `null` without error |
| `files_and_folders/` | Path base64 via `errors.path_for_action`; plain path for `remove_component_identification` |
| `projects/` | Not-found mapping; `get_all_scans` → `[]` for unknown project |
| `users/` | Permission list normalization; parsing-error shape for unknown user |
| `scans/` | List/map normalization; `check_status` / Git status wrapping; pending files soft-fail |
| `uploads/` | Raw HTTP upload transport (scan target, DA, SBOM) |

| Legacy flat modules (`download_api.py`, …) remain until migrated.

Import from the package root or the domain subpackage:

```python
from workbench_agent.api.clients import ComponentsClient
from workbench_agent.api.clients.projects import ProjectsClient
```
