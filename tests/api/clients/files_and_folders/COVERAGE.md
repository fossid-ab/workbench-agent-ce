# Files and folders API test coverage

| Action | Unit | Live | Errors live | Operations live |
|--------|------|------|-------------|-----------------|
| `get_identification` | Yes | Yes | Yes | Yes |
| `get_fossid_results` | Yes | Yes | — | — |
| `get_matched_lines` | Yes | Yes | Yes | — |
| `get_file_comments` | Yes | Yes | — | Yes |
| `add_license_identification` | Yes | Yes* | Yes | Yes* |
| `set_identification_copyright` | Yes | Yes* | — | — |
| `set_identification_component` | Yes | Yes* | Yes | Yes |
| `remove_component_identification` | Yes | Yes* | Yes | Yes* |
| Other writes | Yes | Yes* | — | — |

\* `WORKBENCH_ALLOW_MUTATIONS=1`

```bash
set -a && source .env-cs && set +a
pytest tests/api/clients/files_and_folders -m requires_workbench
WORKBENCH_ALLOW_MUTATIONS=1 pytest tests/api/clients/files_and_folders/test_files_and_folders_operations_live.py -v
```
