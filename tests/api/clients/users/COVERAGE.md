# Users API test coverage

| Action | Unit | Payload | Fixture | Live | Errors unit | Errors live |
|--------|------|---------|---------|------|-------------|-------------|
| `get_information` | Yes | Yes | Yes | Yes | Yes | Yes |
| `get_user_permissions_list` | Yes | Yes | Yes | Yes | — | Yes |

## CI tiers

```bash
pytest tests/api/clients/users -m "not requires_workbench"
pytest tests/api/clients/users -m requires_workbench   # needs .env-cs
```

Full probes:

```bash
pytest tests/api/clients/users/test_users_operations_live.py -m requires_workbench -v
```
