# Projects API schema reference

Derived from Workbench API docs, live fixtures (`tests/api/support/fixtures/2026.1.0/`),
live probes (`tests/api/clients/projects/test_projects_operations_live.py`), and
`ProjectsClient` implementation.  
Auth fields (`username`, `key`) are added by `BaseAPI`.

See [`quirks.md`](quirks.md) for cs-demo / 2026.1 error text variants.

Legend: **R** = required in API `data`, **O** = optional.

## Actions overview

| Action | Client method | Implemented |
|--------|---------------|-------------|
| `list_projects` | `list_projects()` | Yes |
| `get_information` | `get_information()` | Yes |
| `get_all_scans` | `get_all_scans()` | Yes |
| `create` | `create()` | Yes |
| `update` | `update()` | Yes |
| `generate_report` | `generate_report()` | Yes |
| `check_status` | `check_status()` | Yes |

---

## `list_projects`

### Request (`data`)

Empty object `{}`.

### Response `data`

| Field (per item) | Notes |
|------------------|-------|
| `id`, `project_code`, `project_name` | Contract-required |
| `creator`, `created`, `updated`, `scans`, `warnings` | Often strings on 2026.1 |
| `limit_date`, `product_code`, `product_name`, `description`, `comment` | |
| `is_archived`, `jira_project_key`, `policy_rules`, `is_member` | |

---

## `get_information`

### Request (`data`)

| Field | API | Client param |
|-------|-----|--------------|
| `project_code` | **R** | `project_code` |

### Response `data`

Project detail dict (`id`, `project_code`, `project_name`, `owner_email`, …).

---

## `get_all_scans`

### Request (`data`)

| Field | API | Client param |
|-------|-----|--------------|
| `project_code` | **R** | `project_code` |

### Response `data`

Array of scan objects (`id`, `code`, `name`, …). Unknown project → client returns `[]`.

---

## `create`

### Request (`data`)

| Field | API | Client param |
|-------|-----|--------------|
| `project_name` | **R** | `project_name` |
| `product_code` | O | `product_code` |
| `product_name` | O | `product_name` |
| `description` | O | `description` |
| `comment` | O | `comment` |
| `limit_date` | O | `limit_date` |
| `jira_project_key` | O | `jira_project_key` |

### Response `data`

| Field | Notes |
|-------|-------|
| `project_code` | Auto-generated; returned as string |

---

## `update`

### Request (`data`)

| Field | API | Client param |
|-------|-----|--------------|
| `project_code` | **R** | `project_code` |
| `project_name` | **R** | `project_name` |
| `product_code` | O | `product_code` |
| `product_name` | O | `product_name` |
| `description` | O | `description` |
| `comment` | O | `comment` |
| `limit_date` | O | `limit_date` |
| `jira_project_key` | O | `jira_project_key` |
| `new_project_owner` | O | `new_project_owner` |

### Response `data`

| Field | Notes |
|-------|-------|
| `project_id` | Returned as int by client |

---

## `generate_report`

### Request (`data`)

Caller-defined. Typical keys (via `ReportService`):

| Field | Notes |
|-------|-------|
| `project_code` | **R** (effective) |
| `report_type` | e.g. `xlsx`, `spdx`, `cyclone_dx` |
| `async` | `"1"` for async project reports |
| `selection_type`, `selection_view`, `disclaimer` | O |
| `include_vex`, `report_content_type`, `include_dep_det_info` | O |

Client forwards `payload_data` unchanged.

### Response `data`

| Field | Notes |
|-------|-------|
| `process_queue_id` | int via client |

---

## `check_status`

### Request (`data`)

| Field | API | Client param |
|-------|-----|--------------|
| `process_id` | **R** | `process_id` (sent as string) |
| `type` | **R** | `process_type` |

### Response `data`

Status dict (e.g. `status`, `progress`).
