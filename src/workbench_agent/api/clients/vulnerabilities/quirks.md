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
- Count-only responses return ``{"count_results": <int>}`` (live-validated on
  2026.1; read ``data["count_results"]`` directly).
Automatic pagination is in ``VulnerabilityService`` (private ``_fetch_all_rows``).
- Scope: pass ``scan_code`` **or** ``project_code`` (API validates).
- ``search_value`` is supported by the raw client for API completeness; the
  service lists full scan/project results without search filters.

## `get_information`

- Returns both KB CVE metadata (`data.cve`) and scan VEX rows
  (`data.component_vulnerability_in_scans`).
- Use a CVE id from ``list_scan_vulnerabilities`` for live probes.

## VEX mutations

- Create returns `data.id` (VEX row id) for subsequent updates.
- Update success `data` may be **`null`**; rely on `message`.
- Import copies VEX between scans with matching components; `override_vex`
  defaults to `"0"`.
- VEX field vocabulary (status, justification, response) follows **CycloneDX
  1.7** — see [`schema.md` § VEX (CycloneDX)](schema.md#vex-cyclonedx).
- Workbench sends **`vuln_exp_response`** as a single string per write; CycloneDX
  BOMs model `response` as an array.

Live mutation tests: `test_vulnerabilities_operations_live.py` with
`WORKBENCH_ALLOW_MUTATIONS=1`.
