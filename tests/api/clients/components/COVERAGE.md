# Components API test coverage

| Action | Unit | Payload | Fixture | Live | Errors live | Operations live |
|--------|------|---------|---------|------|-------------|-----------------|
| `list_components` | Yes | — | Yes | Yes | — | Yes |
| `list_by_usage` | Yes | — | — | Yes | — | Yes |
| `get_information` | Yes | — | — | Yes | Yes | Yes |
| `create` | Yes | — | — | Yes* | Yes | Yes* |
| `delete` | Yes | — | — | Yes* | Yes | Yes* |
| `get_usage` | Yes | — | Yes | Yes | — | Yes* |
| `get_usage_count` | Yes | — | — | Yes | Yes | — |

\* Mutations: `WORKBENCH_ALLOW_MUTATIONS=1`

```bash
set -a && source .env-cs && set +a
pytest tests/api/clients/components -m requires_workbench
WORKBENCH_ALLOW_MUTATIONS=1 pytest tests/api/clients/components/test_components_operations_live.py -v
```
