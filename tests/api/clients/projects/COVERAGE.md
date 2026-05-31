# Projects API test coverage

Stability target: **Workbench 2026.1** + Test Project / Test Scan (live).

| Action | Unit | Payload | Fixture | Live | Errors unit | Errors live |
|--------|------|---------|---------|------|-------------|-------------|
| `list_projects` | Yes | Yes | Yes | Yes | Yes | — |
| `get_information` | Yes | Yes | Yes | Yes | Yes | Yes |
| `get_all_scans` | Yes | Yes | Yes | Yes | Yes | Yes |
| `create` | Yes | Yes | — | Yes* | Yes | Yes |
| `update` | Yes | Yes | — | Yes* | Yes | Yes |
| `generate_report` | Yes | pass-through | — | Yes* | Yes | Yes |
| `check_status` | Yes | Yes | — | Yes* | Yes | — |

\* `test_projects_operations_live.py` (requires `WORKBENCH_ALLOW_MUTATIONS=1`)

## CI tiers

```bash
# PR (required)
pytest tests/api/clients/projects -m "not requires_workbench"

# Release / nightly (recommended for “stable”)
pytest tests/api/clients/projects -m requires_workbench
```

## Recording fixtures after upgrade

```bash
WORKBENCH_RECORD_CONTRACTS=1 pytest tests/api/clients/projects -m requires_workbench
```

Full operation matrix (creates ephemeral projects):

```bash
WORKBENCH_ALLOW_MUTATIONS=1 pytest tests/api/clients/projects/test_projects_operations_live.py -v
```
