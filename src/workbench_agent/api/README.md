# Workbench API layer (`workbench_agent.api`)

HTTP access to FossID Workbench is organized in three layers. The goal is a
**machine-readable SDK** that CLIs, agents, and MCP servers can consume without
baking in human formatting.

```
┌─────────────────────────────────────────────────────────────┐
│  Consumers (CLI, agents, MCP, scripts)                       │
│  Human output → workbench_agent.utilities/ (outside this tree)│
└────────────────────────────┬────────────────────────────────┘
                             │
┌────────────────────────────▼────────────────────────────────┐
│  WorkbenchClient — wires clients + services                  │
└────────────────────────────┬────────────────────────────────┘
                             │
         ┌───────────────────┴───────────────────┐
         │                                       │
┌────────▼─────────┐                 ┌───────────▼──────────┐
│  Services        │                 │  Clients             │
│  Business logic  │──uses──────────▶│  Raw HTTP / API ops  │
│  dicts & lists   │                 │  dicts & lists       │
└────────┬─────────┘                 └───────────┬──────────┘
         │                                       │
         └───────────────────┬───────────────────┘
                             │
                  ┌──────────▼──────────┐
                  │  api/utils helpers  │
                  │  Pure transforms    │
                  │  (no HTTP, no I/O)  │
                  └─────────────────────┘
```

## Clients

**Own:** one Workbench API **group** per domain (`projects`, `scans`,
`vulnerabilities`, …).

**Responsibilities:**

- Build request payloads (`group`, `action`, `data`)
- Call `BaseAPI._send_request`
- Map failures to `ApiError` (see each package’s `errors.py`)
- Normalize wire shapes where useful (pagination flattening, flag `"0"`/`"1"`,
  optional field coercion)

**Do not:** encode multi-step workflows, CLI messages, or `print()`.

Packaged layout and domain notes: [`clients/README.md`](clients/README.md).
Field reference: `clients/<domain>/schema.md` and `quirks.md`.

```python
from workbench_agent.api import WorkbenchClient

wb = WorkbenchClient(url, user, token)
rows = wb.vulnerability.list_scan_vulnerabilities(scan_code)

# VEX
wb.vulnerability.create_vex(
    scan_code, component_id=1909, cve="CVE-2021-20089",
    status="not_affected", justification="code_not_reachable",
)
```

## Services

**Own:** **business workflows** that combine one or more clients (and sometimes
helpers).

**Responsibilities:**

- Orchestrate reads/writes across domains (e.g. identify a file → resolve catalog
  row → write identification)
- Expose agent-friendly operations with stable, documented return shapes
- Return **structured data only** — `dict`, `list`, `bool`, `int`, etc.

**Do not:** call `print()` or format strings for terminal display. Logging via
`logger.debug` / `logger.info` is fine.

```python
summary = summarize_vulnerability_rows(vulnerabilities)  # helpers
components = get_vulnerable_components_from_rows(vulnerabilities)
```

| Service | Role |
|---------|------|
| `component_catalog` | Catalog find / resolve / update |
| `identification` | File + scan identification read/write |
| `dependencies` | Dependency analysis read/write |
| `vulnerability` | `list_scan_vulnerabilities` / `list_project_vulnerabilities`, VEX create/update |
| `results` | Aggregate scan reads for `--show-*` (delegates to domain services) |
| `resolver`, `scan_operations`, `reports`, … | Higher-level scan/project workflows |

Prefer **services** in application and agent code. Reach for **clients** when
you need direct access to a single API action, contract tests, or a method not
yet wrapped by a service.

## Helpers (`api/utils/`)

Small **pure functions** shared by services: row parsing, filtering, aggregation
(`vulnerability_helpers`, `dependency_helpers`, …).

- No HTTP, no logging side effects required
- Same structured types as services
- Unit-tested without mocking Workbench

Keep helpers free of business orchestration; services call helpers + clients.

## Human-readable output (outside `api/`)

Terminal formatting lives in **`workbench_agent.utilities/`**, not in clients or
services. Example: `utilities/vulnerability_display.py` turns service dicts into
`print()` output for the CLI.

When this tree is extracted as **`workbench-sdk`**, the SDK should stay
machine-readable; CE (or an MCP server) owns display.

## Machine-readable contract

| Layer | Returns | Avoid |
|-------|---------|--------|
| Client | API `data` shapes (normalized), typed primitives | `print`, prose summaries |
| Service | Domain dicts/lists documented on the method | `print`, HTML, markdown meant for users |
| Helper | Derived dicts/lists from in-memory rows | I/O |
| Utility | *(none — formats and prints)* | — |

API messages in response bodies (e.g. VEX `"message": "…"`) are passed through
as fields; services do not rewrite them into CLI text.

## Tests

| Layer | Tests |
|-------|--------|
| Clients | `tests/api/clients/<domain>/` — mocked HTTP, live contract tests |
| Services | `tests/api/services/<domain>/` — mocked clients |
| Helpers | `tests/api/utils/test_*_helpers.py` |
| Contracts | `tests/api/support/` — versioned fixtures, `assert_contract` |

See [`tests/api/README.md`](../../../tests/api/README.md).

## Migration notes

- Older **flat** client modules (`*_api.py`) are being replaced by packaged
  `clients/<domain>/`.
- Some **legacy services** still emit CLI `print()` during long-running
  workflows (`resolver`, `status_check`, parts of `results.fetch_results`).
  New service code should not add prints; migrate callers to utilities when
  touching those paths.

## Related docs

- [`SDK_DISTRIBUTION_STRATEGY.md`](SDK_DISTRIBUTION_STRATEGY.md) — extracting this tree as `workbench-sdk`
- [`clients/README.md`](clients/README.md) — per-domain client packages
