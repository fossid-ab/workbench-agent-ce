# Files and folders API test coverage

| Action | Unit | Live | Errors live | Operations live | Auditor workflow |
|--------|------|------|-------------|-----------------|------------------|
| `get_folder_content` | Yes | Yes | — | — | Yes |
| `get_folder_content_metrics` | Yes | Yes | — | — | Yes |
| `get_folder_components_ranking` | Yes | Yes | — | — | Yes |
| `get_folder_extensions_ranking` | Yes | Yes | — | — | Yes |
| `get_identification` | Yes | Yes | Yes | Yes | Yes |
| `get_fossid_results` | Yes | Yes | — | — | Yes |
| `get_matched_lines` | Yes | Yes | Yes | — | Yes |
| `get_file_comments` | Yes | Yes | — | Yes | Yes |
| `add_license_identification` | Yes | Yes* | Yes | Yes* | Yes |
| `set_identification_copyright` | Yes | Yes* | — | — | Yes |
| `set_identification_component` | Yes | Yes* | Yes | Yes | Yes |
| `remove_component_identification` | Yes | Yes* | Yes | Yes* | Yes |
| `add_file_comment` | Yes | Yes* | — | — | Yes |
| `edit_file_comment` | Yes | Yes* | — | — | Yes |
| `delete_file_comment` | Yes | Yes* | — | — | Yes |
| `mark_as_identified` | Yes | Yes* | — | — | Yes |
| `unmark_as_identified` | Yes | Yes* | — | — | Yes |
| `change_distribution_status` | Yes | Yes* | — | — | Yes |

\* `WORKBENCH_ALLOW_MUTATIONS=1`

## Auditor workflow (canonical live suite)

`test_files_and_folders_auditor_workflow_live.py` runs every client method in
auditor order:

1. **Discovery** — pending files, folder content, extension/component rankings
2. **Investigation** — identification, FossID matches, matched lines, comments
3. **Mutations** — license, copyright, component, distribution, comments,
   mark/unmark identified (each verified by re-reading `get_identification`)

Requires `WORKBENCH_URL`, `WORKBENCH_USER`, and `WORKBENCH_TOKEN` (see
[`tests/api/README.md`](../../README.md)).

```bash
# Read-only discovery + investigation
pytest tests/api/clients/files_and_folders/test_files_and_folders_auditor_workflow_live.py -k Phase1 -v

# Full auditor flow including writes
WORKBENCH_ALLOW_MUTATIONS=1 pytest tests/api/clients/files_and_folders/test_files_and_folders_auditor_workflow_live.py -v

# All files_and_folders live tests
pytest tests/api/clients/files_and_folders -m requires_workbench
```

## Other live suites

```bash
WORKBENCH_ALLOW_MUTATIONS=1 pytest tests/api/clients/files_and_folders/test_files_and_folders_operations_live.py -v
```
