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
│  WorkbenchClient + BaseAPI — transport & wiring              │
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

## Transport (`base_api.py`)

``BaseAPI`` owns the shared HTTP session, auth injection, and ``_send_request``.
Domain clients receive a ``BaseAPI`` instance from ``WorkbenchClient`` and call
``_send_request`` with their ``group`` / ``action`` payloads.

``WorkbenchClient.get_workbench_config()`` calls ``internal.getConfig`` once
(cached) for server version and settings — there is no separate internal client.

## Clients

**Own:** one Workbench API **group** per domain (or a dedicated transport for uploads).

**Responsibilities:**

- Build request payloads (`group`, `action`, `data`)
- Call `BaseAPI._send_request` (or raw HTTP for uploads)
- Map failures to `ApiError` (see each package’s `helpers.py`)
- Normalize wire shapes where useful (pagination flattening, flag `"0"`/`"1"`,
  optional field coercion)

**Do not:** encode multi-step workflows, CLI messages, or `print()`.

Packaged layout and domain notes: [`clients/README.md`](clients/README.md).
Field reference: `clients/<domain>/schema.md` and `quirks.md`.

| `WorkbenchClient` attribute | Class | API group / transport |
|------------------------------|-------|------------------------|
| `projects` | `ProjectsClient` | `projects` |
| `scans` | `ScansClient` | `scans` |
| `uploads` | `UploadsClient` | raw HTTP upload to `api.php` |
| `downloads` | `DownloadClient` | `download` |
| `vulnerabilities` | `VulnerabilitiesClient` | `vulnerabilities` |
| `quick_scan` | `QuickScanClient` | `quick_scan` |
| `users` | `UsersClient` | `users` |
| `components` | `ComponentsClient` | `components` |
| `files_and_folders` | `FilesAndFoldersClient` | `files_and_folders` |

Legacy flat modules (`download_api.py`, `quickscan_api.py`, …) remain until
migrated to packaged `clients/<domain>/` layouts.

```python
from workbench_agent.api import WorkbenchClient

wb = WorkbenchClient(url, user, token)
rows = wb.vulnerability.list_scan_vulnerabilities(scan_code)

# Direct client access
info = wb.components.get_information("openssl", "1.1.1")
perms = wb.users.get_user_permissions_list(searched_username=wb.api_user)

# VEX (via service; uses VulnerabilitiesClient under the hood)
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
vulns = wb.vulnerability.list_scan_vulnerabilities(scan_code)
links = wb.links.get_workbench_links(scan_code)
warnings = wb.policy.get_policy_warnings(scan_code)
catalog = wb.component_catalog.resolve("abbrev", "1.1.1", "ISC")
```

| `WorkbenchClient` attribute | Class | Role |
|------------------------------|-------|------|
| `component_catalog` | `ComponentService` | Catalog find / resolve / update |
| `identification` | `IdentificationService` | File + scan identification read/write |
| `dependencies` | `DependencyService` | Dependency analysis read/write |
| `vulnerability` | `VulnerabilityService` | Paginated CVE listing; VEX create/update |
| `policy` | `PolicyService` | Scan counters; scan/project policy warnings; `download_project_policy_json` |
| `links` | `LinksService` | Version-aware Workbench UI deep links (not an API group) |
| `scan_content` | `ScanContentService` | Scan file directory: upload (target/DA/SBOM), extract, remove, Git |
| `scan_operations` | `ScanOperationsService` | Process scan files: KB scan, DA run/import, SBOM import |
| `scan_deletion` | `ScanDeletionService` | Queue scan delete and wait until complete |
| `resolver` | `ResolverService` | Resolve project/scan names to codes; create if needed |
| `reports` | `ReportService` | Report generation, validation, waiting, download |
| `status_check` | `StatusCheckService` | Poll async operation status (Git, scan, reports, delete, …) |
| `user_permissions` | `UserPermissionsService` | Permissions for the configured API user |
| `quick_scan_service` | `QuickScanService` | Single-file quick scan wrapper over `quick_scan` client |

Prefer **services** in application and agent code. Reach for **clients** when
you need direct access to a single API action, contract tests, or a method not
yet wrapped by a service.

## Helpers (`api/utils/`)

Optional shared pure functions when logic is reused across multiple services.
Most domain logic lives on the service itself; CLI formatting lives under
``workbench_agent.utilities/``.

## Human-readable output (outside `api/`)

Terminal formatting lives in **`workbench_agent.utilities/`**, not in clients or
services. Example: `utilities/vulnerability_display.py` summarizes and prints CVE rows
for the CLI (not part of the SDK service layer).

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
| Transport | `tests/api/test_base_api.py` |
| Utils | `tests/api/utils/` |
| Contracts | `tests/api/support/` — versioned fixtures, `assert_contract` |

See [`tests/api/README.md`](../../../tests/api/README.md).

## Migration notes

- Older **flat** client modules (`*_api.py`) are being replaced by packaged
  `clients/<domain>/`.
- Some **legacy services** still emit CLI `print()` during long-running
  workflows (`resolver`, `status_check`). New service code should not add
  prints; `--show-*` orchestration lives in `workbench_agent.utilities`.

## Related docs

- [`SDK_DISTRIBUTION_STRATEGY.md`](SDK_DISTRIBUTION_STRATEGY.md) — extracting this tree as `workbench-sdk`
- [`clients/README.md`](clients/README.md) — per-domain client packages
