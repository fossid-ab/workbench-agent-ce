# Files and folders API schema reference

Source: `files-and-folders-api.txt` in the repo root.  
Client: `FilesAndFoldersClient` in `client.py`.  
Auth fields (`username`, `key`) are added by `BaseAPI`.

Legend: **R** = required in API `data`, **O** = optional.  
Path encoding: see `errors.path_for_action` and `quirks.md`.

## Actions overview

| Action | Client method | Path encoding |
|--------|---------------|---------------|
| `get_folder_content` | `get_folder_content()` | base64 |
| `get_folder_content_metrics` | `get_folder_content_metrics()` | base64 |
| `get_folder_components_ranking` | `get_folder_components_ranking()` | base64 |
| `get_folder_extensions_ranking` | `get_folder_extensions_ranking()` | base64 |
| `get_identification` | `get_identification()` | base64 |
| `set_identification_copyright` | `set_identification_copyright()` | base64 |
| `add_license_identification` | `add_license_identification()` | base64 |
| `set_identification_component` | `set_identification_component()` | base64 |
| `get_fossid_results` | `get_fossid_results()` | base64 |
| `get_matched_lines` | `get_matched_lines()` | base64 |
| `add_file_comment` | `add_file_comment()` | base64 |
| `get_file_comments` | `get_file_comments()` | base64 |
| `edit_file_comment` | `edit_file_comment()` | — (no path) |
| `delete_file_comment` | `delete_file_comment()` | — |
| `mark_as_identified` | `mark_as_identified()` | base64 |
| `unmark_as_identified` | `unmark_as_identified()` | base64 |
| `change_distribution_status` | `change_distribution_status()` | base64 |
| `remove_component_identification` | `remove_component_identification()` | **plain** |

---

## `get_folder_content_metrics`

### Request (`data`)

| Field | API | Client param | Default |
|-------|-----|--------------|---------|
| `scan_code` | **R** | `scan_code` | |
| `path` | **R** | `path` | `"."` (scan root) |

### Response `data`

| Field | Spec type | Notes |
|-------|-----------|-------|
| `total` | int | Files in folder scope |
| `pending_identification` | int | Pending ID count |
| `identified_files` | int | Marked identified |
| `without_matches` | int | No KB matches |

Top-level `message` is present on success but not returned by the client
(read methods return `data` only — see `quirks.md`).

See **`quirks.md` § get_folder_content_metrics`**.

---

## `get_folder_content`

### Request (`data`)

| Field | API | Client param | Default |
|-------|-----|--------------|---------|
| `scan_code` | **R** | `scan_code` | |
| `path` | **R** | `path` | `"."` (scan root) |
| `show_all` | **R** | `show_all` | `True` → `"1"` |
| `source_code_only` | **R** | `source_code_only` | `False` → `"0"` |

### Response `data`

| Shape | Spec | Observed (2026.1 cs-demo) |
|-------|------|-----------------------------|
| Array of nodes | Yes | Directories: `id`, `text`, `is_directory`, `children`. Files: `id`, `text`, `is_directory`, `icon`. |

See **`quirks.md` § get_folder_content`**.

---

## `get_folder_components_ranking`

### Request (`data`)

| Field | API | Client param | Default |
|-------|-----|--------------|---------|
| `scan_code` | **R** | `scan_code` | |
| `path` | **R** | `path` | `"."` (scan root) |

### Response `data`

| Shape | Spec | Observed (2026.1 cs-demo) |
|-------|------|-----------------------------|
| Array of ranking rows | Yes | Sorted by ``amount`` descending |
| `false` | Yes | Returned when ``path`` is a **file**, not a folder |

Row fields: `rownum`, `artifact`, `version`, `amount_per_artifact_version`,
`amount`, `cpe`, `artifact_license`, `category`, `author`, `fcrid`.

See **`quirks.md` § get_folder_components_ranking`**.

---

## `get_folder_extensions_ranking`

### Request (`data`)

| Field | API | Client param | Default |
|-------|-----|--------------|---------|
| `scan_code` | **R** | `scan_code` | |
| `path` | **R** | `path` | `"."` (scan root) |
| `current_view` | O | `current_view` | omitted (server default) |

``current_view`` values: ``show_all``, ``all_items``, ``pending_items``,
``mark_as_identified``, ``without_matches``.

### Response `data`

| Shape | Spec | Observed (2026.1 cs-demo) |
|-------|------|-----------------------------|
| Array of extension rows | Yes | Sorted by ``amount`` descending |
| `false` | — | File path, or some views with no matching files |

Row fields: `id`, `file_extension`, `amount`.

See **`quirks.md` § get_folder_extensions_ranking`**.

---

## `get_identification`

### Request (`data`)

| Field | API | Client param |
|-------|-----|--------------|
| `scan_code` | **R** | `scan_code` |
| `path` | **R** | `path` | Spec: base64 relative path; client encodes |

### Response

| Field | Spec | Client return |
|-------|------|---------------|
| `data` | `component_identification`, `licenses`, `copyright`, … | Returned as dict |
| `message` | O | **Not returned** by client (only `data`) — see `quirks.md` |

Observed `data` shapes (2026.1 cs-demo): see **`quirks.md` § get_identification`**
— `component_identification` may be `[]` or a dict; `licenses` may be `false`
or a dict; distribution is `component_identification.is_distributed`.

---

## `set_identification_copyright`

### Request (`data`)

| Field | API | Client param | Default |
|-------|-----|--------------|---------|
| `scan_code` | **R** | `scan_code` | |
| `path` | **R** | `path` | base64; empty path + `is_directory=1` → root (per spec) |
| `is_directory` | **R** | `is_directory` | Client default `"0"` if omitted |
| `copyright` | **R** | `copyright` | |

### Response

| Field | Client return |
|-------|---------------|
| `data`, `message` | `{"data", "message"}` |

---

## `add_license_identification`

### Request (`data`)

| Field | API | Client param |
|-------|-----|--------------|
| `scan_code` | **R** | `scan_code` |
| `path` | **R** | `path` |
| `license_identifier` | **R** | `license_identifier` |
| `identification_on` | **R** | `identification_on` | `'file'` or `'snippet'` |
| `is_directory` | **R** | `is_directory` | Client default `"0"` |

### Response `data`

| Field | Spec |
|-------|------|
| `identification_id` | int |

---

## `set_identification_component`

### Request (`data`)

| Field | API | Client param | Default |
|-------|-----|--------------|---------|
| `scan_code` | **R** | `scan_code` | |
| `path` | **R** | `path` | |
| `is_directory` | **R** | `is_directory` | Client default `"0"` |
| `component_name` | **R** | `component_name` | |
| `component_version` | **R** | `component_version` | |
| `supplier_name` | O | `supplier_name` | |
| `preserve_existing_identifications` | O | `preserve_existing_identifications` | Spec default **1**; client default **True** → `"1"` |

---

## `get_fossid_results`

### Request (`data`)

| Field | API | Client param |
|-------|-----|--------------|
| `scan_code` | **R** | `scan_code` |
| `path` | **R** | `path` |

### Response `data`

| Field | Spec |
|-------|------|
| Map of match id → match object | Max 10 items |

Match objects include `match_type` (`partial`, `full`, …), `author`, `artifact`,
`version`, `artifact_license`, `file_license`, `client_result_id` (as `id`), etc.
See **`quirks.md` § get_fossid_results`** for agent mapping notes.

---

## `get_matched_lines`

### Request (`data`)

| Field | API | Client param |
|-------|-----|--------------|
| `scan_code` | **R** | `scan_code` |
| `path` | **R** | `path` |
| `client_result_id` | **R** | `client_result_id` | From `get_fossid_results` |

### Response `data`

| Field | Spec |
|-------|------|
| `local_file` | line id map (may be an empty list on 2026.1 — see quirks) |
| `mirror_file` | line id map |

See **`quirks.md` § get_matched_lines`** — prefer `mirror_file` when `local_file`
is empty.

---

## `add_file_comment`

### Request (`data`)

| Field | API | Client param | Default |
|-------|-----|--------------|---------|
| `scan_code` | **R** | `scan_code` | |
| `path` | **R** | `path` | |
| `comment` | **R** | `comment` | |
| `is_important` | O | `is_important` | `"0"` |
| `include_in_report` | O | `include_in_report` | `"0"` |

---

## `get_file_comments`

### Request (`data`)

| Field | API | Client param |
|-------|-----|--------------|
| `scan_code` | **R** | `scan_code` |
| `path` | **R** | `path` |

### Response `data`

| Shape | Spec | Quirk |
|-------|------|-------|
| Array of comment objects | Yes | `null` → client returns `[]` |

---

## `edit_file_comment`

### Request (`data`)

| Field | API | Client param |
|-------|-----|--------------|
| `scan_code` | **R** | `scan_code` |
| `comment_id` | **R** | `comment_id` | Client coerces to str |
| `comment` | O | `comment` |
| `is_important` | O | `is_important` |
| `include_in_report` | O | `include_in_report` |

---

## `delete_file_comment`

### Request (`data`)

| Field | API | Client param |
|-------|-----|--------------|
| `scan_code` | **R** | `scan_code` |
| `comment_id` | **R** | `comment_id` |

---

## `mark_as_identified` / `unmark_as_identified`

### Request (`data`)

| Field | API | Client param | Default |
|-------|-----|--------------|---------|
| `scan_code` | **R** | `scan_code` | |
| `path` | **R** | `path` | |
| `is_directory` | **R** | `is_directory` | Client default `"0"` |

---

## `change_distribution_status`

### Request (`data`)

| Field | API | Client param |
|-------|-----|--------------|
| `scan_code` | **R** | `scan_code` |
| `path` | **R** | `path` | Spec says folder path; works for files in practice |

---

## `remove_component_identification`

### Request (`data`)

| Field | API | Client param | Notes |
|-------|-----|--------------|-------|
| `scan_code` | **R** | `scan_code` | |
| `path` | **R** | `path` | Spec: **plain** path (not base64) — quirk vs other actions |
| `component_name` | O | `component_name` | Omit = remove all components |
| `component_version` | O | `component_version` | Omit = all versions |

### Response `data`

| Type | Spec |
|------|------|
| `boolean` | |
