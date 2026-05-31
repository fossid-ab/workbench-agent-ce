# Vulnerabilities API quirks (Workbench 2026.1+)

Field reference: [`schema.md`](schema.md).  
Unit coverage: `tests/api/clients/vulnerabilities/test_vulnerabilities_client.py`.

## Prerequisites

| Topic | Observed |
|-------|----------|
| `list_vulnerabilities` | Requires identified components and/or DA results on the scan |
| Live fixtures | `identified_test_scan_code`, `dependency_analysis_test_scan_code`, `scan_has_vulnerabilities` |

## `list_vulnerabilities`

- Client performs **one API call** and returns response ``data`` as-is
  (count dict or paginated ``{list: [...]}``).
- **Automatic pagination** is in ``VulnerabilityService`` (`list_scan_vulnerabilities`,
  ``list_project_vulnerabilities``) via ``fetch_all_vulnerability_rows``.
- Scope: pass ``scan_code`` **or** ``project_code`` (API validates).
- ``search_value`` filters server-side: CVE id, CPE, PURL, or
  ``component_name,component_version``. Partial values accepted.
- ``VulnerabilityService.get_component_vulnerabilities`` uses ``search_value``
  when name+version, PURL, or CPE is known; ``component_id`` alone falls back
  to client-side filtering of the full scan list.

## `get_information`

- Returns both KB CVE metadata (`data.cve`) and scan VEX rows
  (`data.component_vulnerability_in_scans`).
- Use a CVE id from ``list_scan_vulnerabilities`` for live probes.

## VEX mutations

- Create returns `data.id` (VEX row id) for subsequent updates.
- Update success `data` may be **`null`**; rely on `message`.
- Import copies VEX between scans with matching components; `override_vex`
  defaults to `"0"`.

Live mutation tests: `test_vulnerabilities_operations_live.py` with
`WORKBENCH_ALLOW_MUTATIONS=1`.
