# Vulnerabilities API (`group: vulnerabilities`)

CVE lookup, scan vulnerability listing, and VEX (vulnerability exploitability)
statements. Client: `VulnerabilitiesClient` in `client.py`.

## Actions (client methods)

| Action | Method |
|--------|--------|
| `list_vulnerabilities` | `list_vulnerabilities` |
| `get_information` | `get_information` |
| `vulnerability_exploitability_create` | `create_vulnerability_exploitability` |
| `vulnerability_exploitability_update` | `update_vulnerability_exploitability` |
| `import_vulnerability_exploitability_from_scan` | `import_vulnerability_exploitability_from_scan` |

## Prerequisites

CVE listing requires **identified components** and/or **dependency analysis**
results on the scan. Use **Identified Test Scan** or **Dependency Analysis Test
Scan** for live tests.

## `list_vulnerabilities`

### Request (`data`)

| Field | API | Client param | Notes |
|-------|-----|--------------|-------|
| `project_code` | O | `project_code` | List vulnerabilities for a project |
| `scan_code` | O | `scan_code` | List vulnerabilities for a scan |
| `records_per_page` | O | `records_per_page` | Default **100**; coerced to string |
| `page` | O | `page` | Coerced to string |
| `search_value` | O | `search_value` | CVE, component CPE, PURL, or `name,version` (partial match OK) |
| `count_results` | O | `count_results` | `"1"` → count only |

Provide **`scan_code` or `project_code`** (API validates).

### Response `data`

| Shape | When |
|-------|------|
| `{count_results: int}` | `count_results=1` |
| `{list: [...], ...}` | One page of rows |

The client returns ``data`` as-is. Automatic pagination lives in
``VulnerabilityService`` (`list_scan_vulnerabilities`,
``list_project_vulnerabilities``) via ``fetch_all_vulnerability_rows``.

### Service helpers

| Method | Purpose |
|--------|---------|
| `VulnerabilityService.list_scan_vulnerabilities` | All rows for a scan |
| `VulnerabilityService.list_project_vulnerabilities` | All rows for a project |
| `VulnerabilityService.count_scan_vulnerabilities` | Count for a scan |
| `VulnerabilityService.count_project_vulnerabilities` | Count for a project |
| `VulnerabilityService.create_vex` / `update_vex` | VEX write/update |

CLI summaries use ``vulnerability_helpers.summarize_vulnerability_rows`` directly.

## `get_information`

### Request (`data`)

| Field | API | Client param |
|-------|-----|--------------|
| `cve` | **R** | `cve` |

### Response `data`

| Field | Type | Notes |
|-------|------|-------|
| `cve` | list | KB CVE rows (severity, cvss, cpes, …) |
| `component_vulnerability_in_scans` | list | VEX rows tied to scans/components |

## `vulnerability_exploitability_create`

### Request (`data`)

| Field | API | Client param |
|-------|-----|--------------|
| `scan_code` | **R** | `scan_code` |
| `component_id` | **R** | `component_id` |
| `cve` | **R** | `cve` |
| `vuln_exp_status` | O | `vuln_exp_status` |
| `vuln_exp_justification` | O | `vuln_exp_justification` |
| `vuln_exp_response` | O | `vuln_exp_response` |
| `vuln_exp_details` | O | `vuln_exp_details` |

### Response `data`

| Field | Type |
|-------|------|
| `id` | int (VEX row id) |

## `vulnerability_exploitability_update`

### Request (`data`)

| Field | API | Client param |
|-------|-----|--------------|
| `vuln_exp_id` | **R** | `vuln_exp_id` |
| `vuln_exp_status` | O | `vuln_exp_status` |
| `vuln_exp_justification` | O | `vuln_exp_justification` |
| `vuln_exp_response` | O | `vuln_exp_response` |
| `vuln_exp_details` | O | `vuln_exp_details` |

### Response `data`

`null` on success; `message` carries confirmation text.

## `import_vulnerability_exploitability_from_scan`

### Request (`data`)

| Field | API | Client param |
|-------|-----|--------------|
| `scan_code_from` | **R** | `scan_code_from` |
| `scan_code_to` | **R** | `scan_code_to` |
| `override_vex` | O | `override_vex` → `"0"` / `"1"` |

### Response `data`

List (often empty); `message` describes import counts.
