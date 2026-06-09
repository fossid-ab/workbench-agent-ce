# Vulnerabilities API (`group: vulnerabilities`)

CVE lookup, scan vulnerability listing, and VEX (vulnerability exploitability)
interactions. Client: `VulnerabilitiesClient` in `client.py`.

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

## VEX (CycloneDX)

Workbench VEX (Vulnerability Exploitability eXchange) statements follow the
[CycloneDX 1.7](https://cyclonedx.org/docs/1.7/json/) vulnerability
`analysis` object. Workbench uses its own wire field names on the API; values
are the CycloneDX enum strings (snake_case).

**Spec reference:** [analysis.state](https://cyclonedx.org/docs/1.7/json/#vulnerabilities_items_analysis_state),
[analysis.justification](https://cyclonedx.org/docs/1.7/json/#vulnerabilities_items_analysis_justification),
[analysis.response](https://cyclonedx.org/docs/1.7/json/#vulnerabilities_items_analysis_response),
[analysis.detail](https://cyclonedx.org/docs/1.7/json/#vulnerabilities_items_analysis_detail).

### Wire ↔ CycloneDX ↔ service mapping

| Workbench API field | CycloneDX `analysis` | `VulnerabilityService` param | Notes |
|---------------------|----------------------|------------------------------|-------|
| `vuln_exp_status` | `state` | `status` | Impact analysis state |
| `vuln_exp_justification` | `justification` | `justification` | Required when `state` is `not_affected` |
| `vuln_exp_response` | `response` (array in BOM) | `response` | Workbench accepts **one** string per write |
| `vuln_exp_details` | `detail` | `details` | Free-text explanation |

Create/update via **`VulnerabilitiesClient.create_vulnerability_exploitability`**
/ **`update_vulnerability_exploitability`**, or
**`VulnerabilityService.create_vex`** / **`update_vex`** (friendly param names).

### Accepted `vuln_exp_status` (`analysis.state`)

| Value | Meaning |
|-------|---------|
| `resolved` | Vulnerability remediated |
| `resolved_with_pedigree` | Remediated with verifiable pedigree evidence |
| `exploitable` | May be directly or indirectly exploitable |
| `in_triage` | Under investigation |
| `false_positive` | Not specific to this component/service |
| `not_affected` | Component/service not affected (**provide `justification`**) |

Live-validated on Workbench 2026.1: `not_affected`, `exploitable` (via updates).

### Accepted `vuln_exp_justification` (`analysis.justification`)

Use when asserting **`not_affected`** (CycloneDX requires justification for that
state):

| Value | Meaning |
|-------|---------|
| `code_not_present` | Vulnerable code removed or tree-shaken |
| `code_not_reachable` | Vulnerable code not invoked at runtime |
| `requires_configuration` | Exploitability depends on a config option |
| `requires_dependency` | Exploitability depends on a missing dependency |
| `requires_environment` | Exploitability depends on a missing environment |
| `protected_by_compiler` | Compiler flags prevent exploitation |
| `protected_at_runtime` | Runtime protections prevent exploitation |
| `protected_at_perimeter` | Network/logical/physical perimeter blocks attacks |
| `protected_by_mitigating_control` | Other controls reduce likelihood/impact |

Live-validated: `code_not_reachable`.

### Accepted `vuln_exp_response` (`analysis.response`)

CycloneDX allows multiple responses in a BOM; Workbench writes **one per API
call**. Strongly encouraged when `state` is `exploitable`.

| Value | Meaning |
|-------|---------|
| `can_not_fix` | Cannot fix |
| `will_not_fix` | Will not fix |
| `update` | Update to a different release |
| `rollback` | Revert to a previous release |
| `workaround_available` | Workaround exists |

Live-validated: `will_not_fix`.

### `vuln_exp_details` (`analysis.detail`)

Optional free-text string describing impact, assessment method, or why the
component is not affected. Maps to CycloneDX `detail`.

### Reading VEX (validation / inspection)

Agents can inspect existing VEX from two API surfaces:

**1. `list_vulnerabilities` rows** (scan/project list)

When a component/CVE pair has VEX, list rows may include (among CVE metadata):

| Field | Type | Notes |
|-------|------|-------|
| `cve` | string | CVE id |
| `component_id` | int | Catalog component id |
| `vuln_exp_id` | int | VEX row id — use for **`update_vex`** / **`vuln_exp_id`** |
| `vuln_exp_status` | string | CycloneDX `analysis.state` |
| `vuln_exp_justification` | string | CycloneDX `analysis.justification` |
| `vuln_exp_response` | string | CycloneDX `analysis.response` value |
| `vuln_exp_details` | string | CycloneDX `analysis.detail` |

Prefer **`VulnerabilityService.list_scan_vulnerabilities`** for all rows.
Match on `cve` + `component_id`; when `vuln_exp_id` is present, VEX exists.

**2. `get_information` → `component_vulnerability_in_scans`**

Per-CVE VEX rows across scans. Each object typically includes:

| Field | Type | Notes |
|-------|------|-------|
| `id` | int | VEX row id (same role as `vuln_exp_id` on updates) |
| `cve` | string | CVE id |
| `component_id` | int | Catalog component id |
| `code` | string | Scan code the VEX applies to |
| `vuln_exp_status` | string | When set |
| `vuln_exp_justification` | string | When set |
| `vuln_exp_response` | string | When set |
| `vuln_exp_details` | string | When set |

Use **`get_information(cve)`** to review KB metadata (`cve` list) and all scan
VEX rows for that CVE in one call.

### Agent checklist (write)

1. Obtain `component_id` and `cve` from **`list_scan_vulnerabilities`**.
2. Check for existing VEX via `vuln_exp_id` on the list row or
   **`get_information`**.
3. **Create:** `scan_code`, `component_id`, `cve`, plus VEX fields. When
   `status` is `not_affected`, always set `justification`.
4. **Update:** `vuln_exp_id` (from create `data.id`, list `vuln_exp_id`, or
   get_information `id`); pass only fields to change.
5. Use CycloneDX enum strings exactly — Workbench validates against the VEX
   vocabulary, not arbitrary prose in status/justification/response fields.

Example (service):

```python
client.vulnerability.create_vex(
    scan_code,
    component_id=1909,
    cve="CVE-2021-20089",
    status="not_affected",
    justification="code_not_reachable",
    response="will_not_fix",
    details="Static analysis: vulnerable path not reachable in our build.",
)
```

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
``VulnerabilityService.list_scan_vulnerabilities`` /
``list_project_vulnerabilities``.

### Service helpers

| Method | Purpose |
|--------|---------|
| `VulnerabilityService.list_scan_vulnerabilities` | All rows for a scan |
| `VulnerabilityService.list_project_vulnerabilities` | All rows for a project |
| `VulnerabilityService.count_scan_vulnerabilities` | Count for a scan |
| `VulnerabilityService.count_project_vulnerabilities` | Count for a project |
| `VulnerabilityService.create_vex` / `update_vex` | VEX write/update |

## `get_information`

### Request (`data`)

| Field | API | Client param |
|-------|-----|--------------|
| `cve` | **R** | `cve` |

### Response `data`

| Field | Type | Notes |
|-------|------|-------|
| `cve` | list | KB CVE rows (severity, cvss, cpes, …) |
| `component_vulnerability_in_scans` | list | VEX rows tied to scans/components — see [VEX (CycloneDX)](#vex-cyclonedx) |

## `vulnerability_exploitability_create`

### Request (`data`)

| Field | API | Client param |
|-------|-----|--------------|
| `scan_code` | **R** | `scan_code` |
| `component_id` | **R** | `component_id` |
| `cve` | **R** | `cve` |
| `vuln_exp_status` | O | `vuln_exp_status` | CycloneDX `analysis.state` — see [VEX](#vex-cyclonedx) |
| `vuln_exp_justification` | O | `vuln_exp_justification` | CycloneDX `analysis.justification` |
| `vuln_exp_response` | O | `vuln_exp_response` | CycloneDX `analysis.response` |
| `vuln_exp_details` | O | `vuln_exp_details` | CycloneDX `analysis.detail` |

### Response `data`

| Field | Type |
|-------|------|
| `id` | int (VEX row id) |

## `vulnerability_exploitability_update`

### Request (`data`)

| Field | API | Client param |
|-------|-----|--------------|
| `vuln_exp_id` | **R** | `vuln_exp_id` |
| `vuln_exp_status` | O | `vuln_exp_status` | CycloneDX `analysis.state` — see [VEX](#vex-cyclonedx) |
| `vuln_exp_justification` | O | `vuln_exp_justification` | CycloneDX `analysis.justification` |
| `vuln_exp_response` | O | `vuln_exp_response` | CycloneDX `analysis.response` |
| `vuln_exp_details` | O | `vuln_exp_details` | CycloneDX `analysis.detail` |

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
