# Files and folders API schema reference

Source: `files-and-folders-api.txt` in the repo root.  
Client: `FilesAndFoldersClient` in `client.py`.  
Auth fields (`username`, `key`) are added by `BaseAPI`.

Legend: **R** = required in API `data`, **O** = optional.  
Path encoding: see `errors.path_for_action` and `quirks.md`.

## Actions overview

| Action | Client method | Path encoding |
|--------|---------------|---------------|
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

All 14 spec actions are implemented — **no missing actions**.

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
| `local_file` | line id map |
| `mirror_file` | line id map |

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
