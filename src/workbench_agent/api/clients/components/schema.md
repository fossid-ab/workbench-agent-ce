# Components API schema reference

Source: `components-api.txt` in the repo root.  
Client: `ComponentsClient` in `client.py`.  
Auth fields (`username`, `key`) are added by `BaseAPI` — not listed below.

Legend: **R** = required in API `data`, **O** = optional.

## Actions overview

| Action | Client method | Implemented |
|--------|---------------|-------------|
| `list_components` | `list_components()` | Yes |
| `list_by_usage` | `list_by_usage()` | Yes |
| `get_information` | `get_information()` | Yes |
| `create` | `create()` | Yes |
| `update` | `update()` | Yes |
| `delete` | `delete()` | Yes |
| `get_usage` | `get_usage()` | Yes |
| `get_usage_count` | `get_usage_count()` | Yes |

---

## `list_components`

### Request (`data`)

| Field | API | Client param | Notes |
|-------|-----|--------------|-------|
| `name` | O | `name` | MySQL pattern filter |
| `count_results` | O | `count_results` | Spec: string `"0"`/`"1"`. Client accepts bool/int/str → `"0"`/`"1"` |
| `records_per_page` | O | `records_per_page` | Spec: string. Client coerces to str |
| `page` | O | `page` | Spec: string. Client coerces to str |
| `order_by` | O | `order_by` | `version`, `name`, `license_name`, `license_identifier`, `created`, `updated` (default `name`) |
| `direction` | O | `direction` | `ASC` or `DESC` (default `DESC`) |

### Response `data` (one of)

| Shape | Spec | Quirk (2026.1) |
|-------|------|----------------|
| `{count_results: int}` | Yes | May also be bare numeric **string** (e.g. `"25481"`) — see `quirks.md` |
| `null` | Yes | |
| `[{id, name, version, …}]` | Yes | List items include license/vuln fields per spec |

---

## `list_by_usage`

### Request (`data`)

| Field | API | Client param | Notes |
|-------|-----|--------------|-------|
| `page` | O | `page` | Spec: **integer** (default 1) |
| `records_per_page` | O | `records_per_page` | integer |
| `search_value` | O | `search_value` | Partial name match |
| `usage_equal_or_above` | O | `usage_equal_or_above` | integer, e.g. `1` = at least one usage |
| `order_by` | O | `order_by` | e.g. `name`, `version`, `created` |
| `direction` | O | `direction` | `ASC` / `DESC` |
| `count_results` | O | `count_results` | Spec: **integer** `0`/`1`. Client sends int (not string like `list_components`) |

### Response `data`

| Field | Spec | Notes |
|-------|------|-------|
| `total_count` | int | |
| `page` | int | |
| `next_page` | bool | |
| `previous_page` | bool | |
| `list` | array | Component usage rows (see spec for item fields) |

---

## `get_information`

### Request (`data`)

| Field | API | Client param |
|-------|-----|--------------|
| `component_name` | **R** | `component_name` |
| `component_version` | O | `component_version` | Omit to list all versions for the name |

### Response `data`

| Shape | Spec | Quirk (2026.1) |
|-------|------|----------------|
| Single object | Yes | When `component_version` provided |
| Array of objects | Yes | When version omitted |
| `null` | **Not in spec** | Missing component returns `status: "1"`, `data: null` — no exception |

---

## `create`

### Request (`data`)

| Field | API | Client param |
|-------|-----|--------------|
| `name` | **R** | `name` |
| `version` | **R** | `version` |
| `license_identifier` | **R** | `license_identifier` |
| `cpe` | O | `cpe` |
| `package_size` | O | `package_size` |
| `package_size_binary` | O | `package_size_binary` |
| `commits_nro` | O | `commits_nro` |
| `contributors_nro` | O | `contributors_nro` |
| `releases_nro` | O | `releases_nro` |
| `bugs_nro` | O | `bugs_nro` |
| `fixed_bugs_nro` | O | `fixed_bugs_nro` |
| `community_size` | O | `community_size` |
| `purl` | O | `purl` |
| `url` | O | `url` |
| `supplier_url` | O | `supplier_url` |
| `community_url` | O | `community_url` |
| `download_url` | O | `download_url` |
| `download_url_binary` | O | `download_url_binary` |
| `package_md5` | O | `package_md5` |
| `package_sha1` | O | `package_sha1` |
| `comment` | O | `comment` |
| `description` | O | `description` |
| `repository_download_path_binary` | O | `repository_download_path_binary` |
| `copyright` | O | `copyright` |
| `attribution_acknowledgement` | O | `attribution_acknowledgement` |
| `warranty_liability_exclusions` | O | `warranty_liability_exclusions` |
| `known_bugs` | O | `known_bugs` |
| `known_vulnerabilities` | O | `known_vulnerabilities` |
| `change_log` | O | `change_log` |
| `platform` | O | `platform` |
| `programming_language` | O | `programming_language` |
| `binary_md5` | O | `binary_md5` |
| `binary_sha1` | O | `binary_sha1` |
| `sup_com_name` | O | `sup_com_name` |
| `sha256` | O | `sha256` |
| `binary_sha256` | O | `binary_sha256` |
| `release_date` | O | `release_date` |
| `built_date` | O | `built_date` |
| `community_status` | O | `community_status` |

All optional create fields from the spec are exposed on `create()` — **no gaps**.

### Response

| Field | Spec | Client return |
|-------|------|---------------|
| `data.component_id` | int | In `result["data"]` |
| `data.component_name` | string | May be base64 on some servers |
| `data.component_version` | string | May be base64 |
| `data.component_license` | string | |
| `message` | string | In `result["message"]` when present |

---

## `update`

### Request (`data`)

| Field | API | Client param |
|-------|-----|--------------|
| `name` | **R** | `name` | Exact name of the component to update |
| `version` | **R** | `version` | Exact version of the component to update |
| `license_identifier` | O | `license_identifier` | Declared SPDX/catalog license (`components.license_id`) |
| `new_name` | O | `new_name` | |
| `new_version` | O | `new_version` | |
| `cpe` | O | `cpe` | |
| `package_size` | O | `package_size` | |
| `package_size_binary` | O | `package_size_binary` | |
| `commits_nro` | O | `commits_nro` | |
| `contributors_nro` | O | `contributors_nro` | |
| `releases_nro` | O | `releases_nro` | |
| `bugs_nro` | O | `bugs_nro` | |
| `fixed_bugs_nro` | O | `fixed_bugs_nro` | |
| `community_size` | O | `community_size` | |
| `purl` | O | `purl` | |
| `url` | O | `url` | |
| `supplier_url` | O | `supplier_url` | |
| `community_url` | O | `community_url` | |
| `download_url` | O | `download_url` | |
| `download_url_binary` | O | `download_url_binary` | |
| `package_md5` | O | `package_md5` | |
| `package_sha1` | O | `package_sha1` | |
| `comment` | O | `comment` | |
| `description` | O | `description` | |
| `repository_download_path_binary` | O | `repository_download_path_binary` | |
| `copyright` | O | `copyright` | |
| `attribution_acknowledgement` | O | `attribution_acknowledgement` | |
| `warranty_liability_exclusions` | O | `warranty_liability_exclusions` | |
| `known_bugs` | O | `known_bugs` | |
| `known_vulnerabilities` | O | `known_vulnerabilities` | |
| `change_log` | O | `change_log` | |
| `platform` | O | `platform` | |
| `programming_language` | O | `programming_language` | |
| `binary_md5` | O | `binary_md5` | |
| `binary_sha1` | O | `binary_sha1` | |
| `sup_com_name` | O | `sup_com_name` | |
| `sha256` | O | `sha256` | |
| `binary_sha256` | O | `binary_sha256` | |
| `release_date` | O | `release_date` | |
| `built_date` | O | `built_date` | |
| `community_status` | O | `community_status` | |

All optional update fields from the spec are exposed on `update()` — **no gaps**.

### Response

| Field | Spec | Client return |
|-------|------|---------------|
| `data.component_id` | int | In `result["data"]` |
| `message` | string | In `result["message"]` when present |

---

## `delete`

### Request (`data`)

| Field | API | Client param |
|-------|-----|--------------|
| `name` | **R** | `name` |
| `version` | **R** | `version` |

### Response `data`

| Type | Spec |
|------|------|
| `boolean` | Success flag |

---

## `get_usage`

### Request (`data`)

| Field | API | Client param | Notes |
|-------|-----|--------------|-------|
| `from_api` | O | `from_api` | Spec: int, default 0; set 1 for API-origin usage |
| `component_id` | O | `component_id` | Typically required for meaningful results |
| `project_id` | O | `project_id` | |
| `page` | O | `page` | |
| `records_per_page` | O | `records_per_page` | Default 10 per spec |
| `direction` | O | `direction` | `asc` / `desc` (default `desc`) |
| `order_by` | O | `order_by` | `scan_name`, `scan_code`, `scan_created` |
| `search_value` | O | `search_value` | Scan code or name |

### Response `data`

| Field | Spec | Quirk (2026.1) |
|-------|------|----------------|
| `page` | int | |
| `records_per_page` | int | |
| `list` | array | Spec text shows object type; live API returns **array** of usage rows |
| `records_total` | **Not in spec** | Present on 2026.1 — see fixtures |

---

## `get_usage_count`

### Request (`data`)

| Field | API | Client param |
|-------|-----|--------------|
| `id` | O | `component_id` | Client maps to API field `id` |

### Response `data`

| Field | Spec |
|-------|------|
| `identifications_usage_count` | int |
| `dependency_usage_count` | int |
