# Files and folders API quirks (Workbench 2026.1)

Full field lists: [`schema.md`](schema.md) (from `files-and-folders-api.txt`).  
Validated on cs-demo / `tests/api/clients/files_and_folders/`.

## Spec vs observed behavior

| Area | Official spec | Observed / client behavior |
|------|---------------|----------------------------|
| `path` encoding | base64 for most actions | **`remove_component_identification`**: plain relative path |
| `remove_component_identification` path | “Relative path” (no base64 called out) | Plain path required on 2026.1 live server |
| Read responses `message` | Often present on `get_*` | Client returns **only `data`** for read methods |
| `get_file_comments` empty | Array in samples | `data: null` → client normalizes to `[]` |
| `is_directory` | Required (`0`/`1`) | Client defaults to `"0"` when omitted |
| `preserve_existing_identifications` | Default `1` | Client default `True` → `"1"` |

## Paths

- Encoding rules: `errors.path_for_action` / `PLAIN_PATH_ACTIONS`.
- Pending file paths: `scans.get_pending_files` returns `{file_id: path}` — use **values**, not keys.

## Write responses

- Mutations with `include_message=True` return `{"data", "message"}`.
- Many writes return `data: null` on success (see contract `write_null_data`).

## `add_license_identification`

- `identification_on` must be exactly `'file'` or `'snippet'`.

## Errors (`status: "0"`)

- ``BaseAPI`` returns ``status: "0"`` for all ``files_and_folders`` actions so the
  client prefixes ``Failed to …`` (live-validated).
- Typical missing file: `The provided file path does not exist`.
- Missing catalog component: ``Component not found`` on ``set_identification_component``.
