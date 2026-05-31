# API tests (`tests/api/`)

Self-contained test suite for `workbench_agent.api`. Layout mirrors the SDK
package so this tree can move with `src/workbench_agent/api/` when the SDK is
extracted.

## Layout

```
tests/api/
  README.md
  conftest.py                 # Credentials, Test Scan, pending paths, mutations
  test_workbench_client.py
  support/
    contract.py               # assert_contract (version-aware)
    contract_specs.py         # Base contracts (all versions)
    contracts/2026.1.0.json   # Per-version contract overrides
    fixtures/2026.1.0/*.json  # Recorded responses for unit smoke tests
    error_assertions.py
    version_contracts.py
  clients/<name>/             # Mirrors api/clients/
  services/<name>/            # Mirrors api/services/
  helpers/, utils/
```

### Test file patterns

| Pattern | Purpose |
|---------|---------|
| `test_<name>_client.py` | Mocked HTTP |
| `test_<name>_errors_unit.py` | Mocked API failures |
| `test_<name>_fixture_smoke.py` | Unit tests driven by `fixtures/<version>/` |
| `test_<name>_live.py` | Real Workbench success + contracts |
| `test_<name>_errors_live.py` | Real Workbench invalid inputs |

Packaged clients document fields in
`src/workbench_agent/api/clients/<domain>/schema.md` and quirks in `quirks.md`.
Coverage matrices live in `tests/api/clients/<domain>/COVERAGE.md` — see
[`clients/README.md`](../../src/workbench_agent/api/clients/README.md).

## Workbench version normalization

`internal.getConfig()` returns a raw string such as `2026.1.0#25559481630`.
The SDK normalizes to **`2026.1.0`** via
`workbench_agent.api.utils.version.normalize_workbench_version` (same logic as
`WorkbenchClient`).

- Live fixture `workbench_version` → normalized (`2026.1.0`)
- Live fixture `workbench_version_raw` → raw from getConfig
- Contracts: [`support/contracts/2026.1.0.json`](support/contracts/2026.1.0.json)
- Fixtures: [`support/fixtures/2026.1.0/`](support/fixtures/2026.1.0/)

Add a new JSON file when supporting another Workbench release.

## Path encoding utility

`workbench_agent.api.utils.path_encoding.encode_path` / `decode_path` — tested
in [`utils/test_path_encoding.py`](utils/test_path_encoding.py). Used by
`FilesAndFoldersClient` (except `remove_component_identification`).

## Prerequisites (live tests)

Live tests read credentials from **environment variables only** — the same
``WORKBENCH_*`` names used in GitHub Actions secrets.

```bash
export WORKBENCH_URL="https://your-workbench-server.com/api.php"
export WORKBENCH_USER="your_username"
export WORKBENCH_TOKEN="your_api_token"
```

Default PR CI should use:

```bash
pytest tests/api -m "not requires_workbench"
```

### Test Project / Test Scan

The Scan on includes:

- **Files with Snippets** — partial matches (`snippet_file_path` fixture)
- **OpenFastPath/** — shared component, folder ops (`openfastpath_dir` fixture)

```bash
export WORKBENCH_TEST_PROJECT_NAME="Test Project"
export WORKBENCH_TEST_SCAN_NAME="Test Scan"
export WORKBENCH_TEST_SCAN_CODE="..."              # optional
export WORKBENCH_TEST_SNIPPET_FILE_PATH="..."      # optional override
export WORKBENCH_TEST_OPENFASTPATH_DIR="OpenFastPath"
```

## Running tests

```bash
pytest tests/api -m "not requires_workbench"     # unit + fixture smoke (CI)
pytest tests/api -m requires_workbench           # live (needs server)
WORKBENCH_ALLOW_MUTATIONS=1 pytest tests/api/clients/files_and_folders -m requires_workbench
```

Full live error/operation validation (components, files_and_folders, users):

```bash
WORKBENCH_ALLOW_MUTATIONS=1 pytest \
  tests/api/clients/components/test_components_operations_live.py \
  tests/api/clients/files_and_folders/test_files_and_folders_operations_live.py \
  tests/api/clients/users/test_users_operations_live.py \
  -v
```

Record new responses after upgrades:

```bash
WORKBENCH_RECORD_CONTRACTS=1 pytest tests/api/clients/components -m requires_workbench
```

## SDK extraction

Move `src/workbench_agent/api/` and **`tests/api/`** together into the SDK package.
