# Identification service live test coverage

Validated on cs-demo **Test Project** / **Test Scan** via
`tests/api/services/identification/`.

| Operation | Unit | Live read | Live write |
|-----------|------|-----------|------------|
| Scan metrics / pending files | — | Yes | — |
| `get_identification` / summarize | Yes | Yes | — |
| `get_matches` | Yes | Yes | — |
| `get_matched_content` | Yes | Yes | — |
| `ensure_component` / from match | Yes | Yes* | Yes* |
| `identify_component_to_file` | Yes | — | Yes* |
| `add_file_license_to_file` | Yes | — | Yes* |
| `identify_snippet_in_file` | Yes | — | Yes* |
| `mark_as_identified` / unmark | Yes | — | Yes* |
| `set_distribution_status` | Yes | — | Yes* |

\* `WORKBENCH_ALLOW_MUTATIONS=1`

Requires `WORKBENCH_URL`, `WORKBENCH_USER`, and `WORKBENCH_TOKEN` (see
[`tests/api/README.md`](../../README.md)).

```bash
pytest tests/api/services/identification/test_identification_operations_live.py -v
WORKBENCH_ALLOW_MUTATIONS=1 pytest tests/api/services/identification/ -v
```

Quirks discovered during these runs are documented in
[`files_and_folders/quirks.md`](../../../src/workbench_agent/api/clients/files_and_folders/quirks.md).
