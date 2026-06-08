# SDK Distribution Strategy — remaining work

The HTTP client layer under `src/workbench_agent/api/` is structured as an
extractable SDK surface. **Extraction has not happened yet** — CE still ships
as a single `workbench-agent` distribution with in-tree `api/`. This document
lists what is left before publishing **`workbench-sdk`** and wiring CE to it.

## Prerequisites (done)

These blockers for a clean split are already satisfied in the monorepo:

- `api/` does not import `cli/`, `handlers/`, or `utilities/`
- Shared SDK errors (`ValidationError`, `FileSystemError`, API hierarchy) live in
  `api/exceptions.py`; `workbench_agent.exceptions` re-exports for CLI compat
- No runtime `print()` in `api/` (logging only)
- CE orchestration, terminal output, and compatibility policy live in
  `utilities/` and `handlers/`

## Target architecture

```
┌─────────────────────────────────────────────────────────┐
│  Workbench Agent CE (workbench-agent)                   │
│  cli/, handlers/, utilities/, main, Docker              │
│  depends on: workbench-sdk>=…                           │
└───────────────────┬─────────────────────────────────────┘
                    │ pip
                    ↓
┌─────────────────────────────────────────────────────────┐
│  Workbench SDK (workbench-sdk)                          │
│  src/workbench_sdk/  ← move from workbench_agent/api/ │
│  WorkbenchClient, clients/, services/, utils/           │
└───────────────────┬─────────────────────────────────────┘
                    │ HTTPS
                    ↓
              FossID Workbench Server
```

## Decisions needed before extraction

1. **Versioning policy** — SDK semver independent of Workbench (recommended) vs
   tracking Workbench server releases. CE keeps its own semver either way.
   `MINIMUM_VERSION` in `workbench_client.py` documents supported server floor.
2. **Repository layout** — new repo vs monorepo with two `pyproject.toml` packages.
3. **PyPI name** — confirm `workbench-sdk` availability / org trademark policy.
4. **Migration shim** — optional one-release re-export
   `workbench_agent.api` → `workbench_sdk` for downstream importers.

## Remaining work

### 1. Package split and rename

- [ ] Create `workbench-sdk` package (`src/workbench_sdk/` or
      `packages/workbench-sdk/`)
- [ ] Mechanical rename: `workbench_agent.api` → `workbench_sdk` imports
- [ ] Second `pyproject.toml` with `requests`, `packaging>=21.0` only
- [ ] Optional: prove `pip install -e ./packages/workbench-sdk` in the monorepo
      before publishing

### 2. SDK polish (small, pre-publish)

- [ ] Rename logger from `workbench-agent` to `workbench-sdk` (or configurable)
- [ ] Migrate legacy flat clients (`download_api.py`, `quickscan_api.py`) into
      packaged `clients/<domain>/` layouts (optional but cleaner artifact)
- [ ] Public SDK README: install, `WorkbenchClient` quick start, exception
      hierarchy, supported Workbench version range

### 3. Wire CE to the SDK

- [ ] Add `workbench-sdk>=…` to root `pyproject.toml`
- [ ] Update imports in `handlers/`, `utilities/`, `main.py`, and tests
- [ ] Remove in-tree `api/` (or keep thin compatibility shim for one CE release)
- [ ] Full test suite green with SDK installed as the only source of
      `WorkbenchClient`

### 4. Tests

- [ ] Move `tests/api/` with the SDK **or** keep in CE with `workbench-sdk` as
      dev dependency — pick one ownership model
- [ ] Update `tests/integration` fixtures that patch `workbench_agent.api…`
- [ ] CI guard: no imports from `workbench_agent` inside the SDK tree
      (grep/ruff path constraint)

### 5. Release engineering

- [ ] Publish `workbench-sdk` to PyPI (or private index)
- [ ] Changelog and documented Workbench compatibility per SDK release
- [ ] Optional dedicated GitHub Actions workflow for SDK (CE Docker/GHCR stays
      separate unless you want unified releases)

## Extraction checklist

All must pass before calling the SDK “extracted”:

- [ ] `pip install workbench-sdk` in a clean venv →
      `from workbench_sdk import WorkbenchClient` works
- [ ] SDK tree has zero imports from `workbench_agent` (except a deliberate shim)
- [ ] Logger names and package metadata match distribution name
- [ ] CE declares a compatible `workbench-sdk` range and does not duplicate
      `api/` source
- [ ] Published artifact on an index you control

## Related docs

- [`README.md`](README.md) — layer boundaries and machine-readable contract
- [`clients/README.md`](clients/README.md) — per-domain client layout
