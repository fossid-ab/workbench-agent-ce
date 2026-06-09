# Projects API quirks (Workbench 2026.1)

Field reference: [`schema.md`](schema.md).  
Validated via live tests in `tests/api/clients/projects/`.

## Spec vs observed behavior

| Area | Typical spec / docs | Observed (2026.1) |
|------|---------------------|-------------------|
| Project not found message | ``Project code does not exist`` | ``Project does not exist``; also ``Handler.Projects.*.project_does_not_exist`` on ``update`` / ``generate_report`` |
| ``create`` / ``update`` date errors | Parsing request JSON | ``BaseAPI`` returns ``status: "0"`` so client can map (not raised in ``BaseAPI``) |
| ``generate_report`` empty project | — | May error with ``project_does_not_have_scans`` (project needs scans) |
| ``get_all_scans`` missing project | Unclear | ``status: "0"`` → client returns ``[]`` (not ``ProjectNotFoundError``) |
| ``get_information`` missing project | Error | ``status: "0"`` → ``ProjectNotFoundError`` |
| ``list_projects`` numeric fields | integers | Many values are JSON **strings** (e.g. ``"723"``, ``"0"``) |
| ``list_projects`` bad ``data`` type | — | Non-list ``data`` → ``[]`` + warning (no exception) |
| ``BaseAPI`` status ``0`` | Raises | **Bypassed** for all ``projects`` group actions above so the client maps errors |

## Error markers

``helpers.is_project_not_found()`` matches:

- ``Project does not exist``
- ``Project code does not exist``
- ``row_not_found``

## ``create`` / ``update``

- Invalid ``limit_date`` → ``RequestData.Base.issues_while_parsing_request`` with
  ``not_valid_date_string``.
- ``update`` may return ``mandatory_field_missing`` for omitted required API fields.

## ``generate_report``

- Payload is caller-built (see ``ReportService.build_project_report_payload``).
- Client passes ``data`` through unchanged.

## ``get_policy_warnings_info``

- ``type`` wire values: ``identifications`` (default), ``dependencies``, ``all``.
- ``scans_list`` may be ``null`` when there are no affected scans.
- List items use ``scan_id``, ``scan_name``, ``scan_code`` (2026.1 live).
- Empty result sets may return ``null`` for all three top-level fields (not ``0`` / ``[]``).
- Missing project → ``ProjectNotFoundError`` (same markers as ``get_information``).
- Scan-level detail (per-rule rows) is ``scans.get_policy_warnings_info`` — Test Project
  policies flag one **license category** and one **specific license**; both can fire on
  Identified Test Scan (see ``scans`` quirks).
