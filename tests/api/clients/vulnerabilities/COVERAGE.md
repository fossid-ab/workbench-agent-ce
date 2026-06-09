# Vulnerabilities client coverage

| Operation | Unit | Live read | Live write |
|-----------|------|-----------|------------|
| `list_vulnerabilities` | Yes | Yes | — |
| `get_information` | Yes | Yes | — |
| `create_vulnerability_exploitability` | Yes | Yes* | Yes* |
| `update_vulnerability_exploitability` | Yes | Yes* | Yes* |
| `import_vulnerability_exploitability_from_scan` | Yes | Yes* | — |

\* Requires `scan_has_vulnerabilities` and `WORKBENCH_ALLOW_MUTATIONS=1` for writes.

```bash
pytest tests/api/clients/vulnerabilities/test_vulnerabilities_client.py -v
pytest tests/api/clients/vulnerabilities/test_vulnerabilities_live.py -m requires_workbench -v
WORKBENCH_ALLOW_MUTATIONS=1 pytest tests/api/clients/vulnerabilities/ -m requires_workbench -v
```

See [`quirks.md`](../../../../src/workbench_agent/api/clients/vulnerabilities/quirks.md).
