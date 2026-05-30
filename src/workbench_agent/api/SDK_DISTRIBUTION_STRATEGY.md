# SDK Distribution Strategy

This document describes how the Workbench HTTP client layer under `src/workbench_agent/api/` could be published as a separate Python package (working name: **`workbench-sdk`**), and how the **Workbench Agent CE** CLI would depend on it. It is updated to match the repository as of the last revision of this file.

## Architecture Overview

**Today (monorepo):** the CE CLI and the API client live in one installable distribution, `workbench-agent` (see root `pyproject.toml`). There is **no** separate `workbench-sdk` on PyPI yet; imports use `workbench_agent.api`.

**Target (two packages):** the CLI consumes a published SDK that owns all Workbench REST usage.

```
┌─────────────────────────────────────────────────────────┐
│  Workbench Agent CE CLI (distribution: workbench-agent)   │
│  - Version: semantic (e.g. 0.8.x) — product / CE cadence  │
│  - Depends on: workbench-sdk>=… (once split)             │
│  - Owns: cli/, handlers/, utilities/, main, Docker      │
└───────────────────┬─────────────────────────────────────┘
                    │ pip dependency
                    ↓
┌─────────────────────────────────────────────────────────┐
│  Workbench SDK (distribution: workbench-sdk)            │
│  - Owns: HTTP client, services, API exceptions           │
│  - Versioning: see “Versioning” below (not 1:1 with CE)  │
│  - Code path today: src/workbench_agent/api/             │
│  - Code path target: src/workbench_sdk/ (or similar)    │
└───────────────────┬─────────────────────────────────────┘
                    │ HTTPS
                    ↓
┌─────────────────────────────────────────────────────────┐
│  FossID Workbench Server                                 │
│  - Compatibility: enforced in WorkbenchClient init       │
│    (minimum server version constant in code today)       │
└─────────────────────────────────────────────────────────┘
```

## Versioning (current code vs future policy)

**Current behavior**

- The **CE package** version is the semver in root `pyproject.toml` (e.g. `0.8.0`). It is **not** the same numbering scheme as FossID Workbench server releases.
- `WorkbenchClient` performs a **minimum Workbench server version** check using a constant in `workbench_client.py` (`MINIMUM_VERSION`, currently `24.3.0`), via `internal.get_config()` and `packaging.version`.
- There is **no** `workbench-sdk` entry in `dependencies` today; the strategy sections below describe a **future** split.

**Future options (choose explicitly when extracting)**

1. **SDK semver independent of Workbench** (e.g. `workbench-sdk` 1.0.0, 1.1.0) and document supported Workbench ranges in release notes + keep `MINIMUM_VERSION` (and optionally a maximum) in code.
2. **SDK version tracks Workbench** (e.g. `24.3.0`) — only works if release cadence and breaking-change policy align with Workbench; CE would still use its own semver.

## Current repository layout (monorepo)

```
workbench-agent-ce/
├── pyproject.toml                 # Single [project] name = workbench-agent
├── src/workbench_agent/
│   ├── api/                       # ← Candidate SDK surface (see boundary audit)
│   │   ├── __init__.py            # Public exports: WorkbenchClient, exceptions
│   │   ├── exceptions.py
│   │   ├── workbench_client.py
│   │   ├── clients/
│   │   ├── services/
│   │   ├── helpers/
│   │   └── utils/                 # e.g. process_waiter, report_definitions
│   ├── cli/
│   ├── handlers/                  # Many imports from workbench_agent.api
│   ├── utilities/                 # Several imports from workbench_agent.api
│   ├── exceptions.py            # CLI-level errors (WorkbenchAgentError, …)
│   └── main.py
└── tests/                         # API tests under tests/api/ (SDK-ready layout)
```

## Boundary audit (prerequisite for extraction)

### Inward boundary (good)

- Under `src/workbench_agent/api/`, **no** imports from `workbench_agent.cli`, `workbench_agent.handlers`, or `workbench_agent.utilities`.
- The API layer is the right place for REST clients, orchestration services, and `WorkbenchClient`.

### Outward boundary (must fix before a clean SDK wheel)

The API package **does** import application-level exceptions from `workbench_agent.exceptions` in several modules, for example:

- `FileSystemError` — `upload_api.py`, `upload_service.py`, `report_service.py`
- `ValidationError` — `download_api.py`, `report_service.py`

`WorkbenchAgentError` and subclasses live outside `api/` today. For a standalone `workbench-sdk` wheel, either:

- **Move** shared types into the SDK (e.g. `workbench_sdk.errors` with thin subclasses), and have the CLI re-export or wrap them, or  
- **Define** SDK-local I/O/validation exceptions and map them at the CLI boundary.

Until one of these is done, the claim “SDK has no dependencies on non-SDK code” is **false**.

### Minor coupling

- `WorkbenchClient` uses `logging.getLogger("workbench-agent")`. For a separate package, rename to something like `workbench-sdk` for log filtering.

### Consumers outside `api/`

Many modules import `workbench_agent.api` (handlers, `main.py`, utilities, tests, integration `conftest`). A rename to `workbench_sdk` implies a **repo-wide import and docstring reference** update, plus moving or duplicating tests that belong to the SDK package.

## Future layout (two distributions)

### SDK repository / package

```
workbench-sdk/
├── pyproject.toml
│   [project]
│   name = "workbench-sdk"
│   version = "…"                    # Policy: see “Versioning”
│   dependencies = [
│       "requests",
│       "packaging>=21.0",
│   ]
├── src/workbench_sdk/
│   ├── __init__.py
│   ├── exceptions.py
│   ├── workbench_client.py
│   ├── clients/
│   ├── services/
│   ├── helpers/
│   └── utils/
└── README.md
```

### CE CLI repository (or same monorepo with two packages)

```
workbench-agent-ce/
├── pyproject.toml
│   dependencies = [
│       "workbench-sdk>=…",
│       "spdx-tools>=0.8.5",
│       "cyclonedx-python-lib[validation]>=7.0.0",
│       …
│   ]
├── src/workbench_agent/
│   ├── cli/
│   ├── handlers/                  # from workbench_sdk import WorkbenchClient
│   ├── utilities/
│   └── main.py
```

## What it would take to separate the layer (effort summary)

Rough phases for planning (ordering matters):

1. **Decouple exceptions** — Remove `from workbench_agent.exceptions import …` from `api/` (small, blocking).
2. **Mechanical rename** — `workbench_agent.api` → `workbench_sdk` (or keep `workbench_agent.api` as a thin re-export shim for one release — optional migration path).
3. **Split packaging** — Second `pyproject.toml` (second package in monorepo *or* new repo), setuptools package discovery, optional `[tool.setuptools.packages.find]` boundaries.
4. **Wire CE to SDK** — Add `workbench-sdk` dependency; delete or shrink in-tree `api/`; run full test suite.
5. **Tests** — Move `tests/api/` with the SDK or keep in CE with `workbench-sdk` as dev dependency; update `tests/integration` fixtures that patch `workbench_agent.api…`.
6. **Release engineering** — PyPI (or private index) for `workbench-sdk`, version policy, changelog, and aligning `MINIMUM_VERSION` with documented supported Workbench versions.
7. **Docs** — Public SDK README, exception hierarchy, compatibility guarantees.

CI (GitHub Actions), Docker, and GHCR publishing for CE remain separate from SDK publication unless you add a dedicated SDK workflow.

## Implementation steps

### Phase 1: Prepare SDK for extraction (in progress)

- [x] SDK-oriented exceptions in `api/exceptions.py` and exports from `api/__init__.py`
- [x] `WorkbenchClient` with domain clients/services and Workbench version compatibility check
- [ ] **Remove dependency on `workbench_agent.exceptions` from `api/`** (blocking for a clean split)
- [ ] Optional: add a second package in the **same** repo (e.g. `packages/workbench-sdk/pyproject.toml`) to prove `pip install -e ./packages/workbench-sdk` without publishing

### Phase 2: Test SDK independence

- [ ] `pip install` SDK alone in a clean venv; `from workbench_sdk import WorkbenchClient` (after rename)
- [ ] Static check: no imports from `workbench_agent` outside the new SDK root (ruff/mypy path constraints or a simple grep in CI)

### Phase 3: Extract SDK (repository choice)

- [ ] New repository **or** monorepo multi-package — team decision
- [ ] Move/rename tree; publish `workbench-sdk` to PyPI (name availability / trademark — verify org-wide)

### Phase 4: Update CE to depend on external SDK

- [ ] Root `pyproject.toml`: add `workbench-sdk>=…`
- [ ] Replace imports across handlers, utilities, `main.py`, tests
- [ ] Remove in-tree `api/` (or keep compatibility shim for one major CE version)

## Benefits (unchanged intent)

### For SDK consumers

```python
from workbench_sdk import WorkbenchClient
from workbench_sdk.exceptions import ApiError

client = WorkbenchClient(url, user, token)
```

### For CLI users

- CE version can move on its own cadence once the SDK is a versioned dependency.
- Pinning `workbench-sdk` in enterprise environments becomes possible.

### For maintainers

- Clear ownership: REST contract and server compatibility in SDK; UX and orchestration in CLI.

## Example: version evolution (illustrative)

After a split, a plausible timeline (numbers are examples only):

```
CE 0.8.x ships with workbench-sdk 1.2.x (supports Workbench >= 24.3)
CE 0.9.x bumps to workbench-sdk 1.3.x when new API surface is required
```

Exact coupling should follow the policy chosen under “Versioning”.

## Checklist before claiming “SDK ready for extraction”

- [ ] No imports from `workbench_agent.exceptions` (or any non-SDK module) inside the SDK tree
- [ ] Logger names / package metadata aligned with distribution name
- [ ] Tests and docs run with SDK installed as the only source of `WorkbenchClient`
- [ ] Published artifact on an index you control; CE declares compatible range

---

This architecture follows common Python practice: a thin application package depends on a library package with a explicit version range, and the library owns the remote API contract.
