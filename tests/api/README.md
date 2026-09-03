# API tests (`tests/api/`)

Test suite for `workbench_agent.api`. Layout mirrors the SDK so this tree can move with `src/workbench_agent/api/` when the SDK is extracted.

## Layout

```
tests/api/
  README.md
  conftest.py                 # Credentials, dual test scans, pending paths, mutations
  test_workbench_client.py
  test_base_api.py
  support/
    contract.py               # assert_contract (version-aware)
    contract_specs.py         # Base contracts (all versions)
    contracts/2026.1.0.json   # Per-version contract overrides
    fixtures/2026.1.0/*.json  # Recorded responses for unit smoke tests
    error_assertions.py
    version_contracts.py
  clients/<name>/             # Mirrors api/clients/
  services/<name>/            # Mirrors api/services/
  utils/
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

`WorkbenchClient.get_workbench_config()` (`internal.getConfig`) returns a raw
version string such as `2026.1.0#25559481630`.
The SDK normalizes to **`2026.1.0`** via
`workbench_agent.api.utils.version.normalize_workbench_version` (same logic as
`WorkbenchClient`).

- Live fixture `workbench_version` → normalized (`2026.1.0`)
- Live fixture `workbench_version_raw` → raw from getConfig
- Contracts: [`support/contracts/2026.1.0.json`](support/contracts/2026.1.0.json)
- Fixtures: [`support/fixtures/2026.1.0/`](support/fixtures/2026.1.0/)

Add a new JSON file when supporting another Workbench release.

## Path encoding

`FilesAndFoldersClient.encode_path` / `decode_path` (implemented in
`clients/files_and_folders/helpers.py`) — tested in
[`clients/files_and_folders/test_path_encoding.py`](clients/files_and_folders/test_path_encoding.py).
Most actions base64-encode paths; `remove_component_identification` sends plain paths.

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

### Test Project / Test Scans

Live tests target project **`SDK-TEST-DND`** with four scans:

| Scan | Use |
|------|-----|
| **UNIDENTIFIED** | Pending files, mutations, auditor workflow |
| **IDENTIFIED** | Stable identified components, licenses, read-only ID state |
| **IDENTIFIED-WITH-DA** | Dependency Analysis results (`get_dependency_analysis_results`) |
| **UNIDENTIFIED-WITH-DA** | Pending identification plus DA (e.g. vulnerability fallback) |

**Policy tests** (`clients/scans/`, `clients/projects/`, `services/policy/`): project
policies should include at least one **license-category** rule and one **license** rule;
both can appear in `scans.get_policy_warnings_info` on **IDENTIFIED**.

**Vulnerability / VEX tests** (`clients/vulnerabilities/`, `services/vulnerability/`):
CVE listing requires identified components and/or DA results. Live tests use
`scan_has_vulnerabilities` (probes **IDENTIFIED**, then **IDENTIFIED-WITH-DA**, then
**UNIDENTIFIED-WITH-DA**). Prefer `workbench.vulnerability` for agent workflows;
`workbench.vulnerabilities` remains the raw client. Mutations need
`WORKBENCH_ALLOW_MUTATIONS=1`.


### Unidentified scan: auditor workflow

1. **`scans.get_pending_files(scan_code)`** — returns `{file_id: relative_path}`.
2. Use **path values** (not file-id keys) for file-scoped APIs:
   - `files_and_folders.get_identification`
   - `files_and_folders.get_fossid_results` / `get_matched_lines`
   - identification writes (license, component, mark identified, …)
3. Optional folder context: `get_folder_content` / rankings under a top-level folder.

Fixtures: `pending_files`, `pending_paths`, `pending_path` (session-scoped from step 1).

```bash
export WORKBENCH_TEST_PROJECT_NAME="SDK-TEST-DND"
export WORKBENCH_TEST_UNIDENTIFIED_SCAN_NAME="UNIDENTIFIED"              # default
export WORKBENCH_TEST_IDENTIFIED_SCAN_NAME="IDENTIFIED"                  # default
export WORKBENCH_TEST_IDENTIFIED_WITH_DA_SCAN_NAME="IDENTIFIED-WITH-DA"  # default
export WORKBENCH_TEST_UNIDENTIFIED_WITH_DA_SCAN_NAME="UNIDENTIFIED-WITH-DA"  # default
export WORKBENCH_TEST_SCAN_NAME="UNIDENTIFIED"                           # alias for unidentified
export WORKBENCH_TEST_SCAN_CODE="..."                                    # unidentified override
export WORKBENCH_TEST_UNIDENTIFIED_SCAN_CODE="..."                       # optional
export WORKBENCH_TEST_IDENTIFIED_SCAN_CODE="..."                         # optional
export WORKBENCH_TEST_IDENTIFIED_WITH_DA_SCAN_CODE="..."                 # optional
export WORKBENCH_TEST_UNIDENTIFIED_WITH_DA_SCAN_CODE="..."               # optional
export WORKBENCH_TEST_DA_SCAN_NAME="IDENTIFIED-WITH-DA"                  # legacy alias
export WORKBENCH_TEST_DA_SCAN_CODE="..."                                 # legacy alias
export WORKBENCH_TEST_SNIPPET_FILE_PATH="..."                            # optional override
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
