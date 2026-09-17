# Functional Tests

Production-grade end-to-end functional tests using pytest. These tests execute `workbench-agent` commands against a real Workbench server.

## Prerequisites

### Required Environment Variables

```bash
export WORKBENCH_URL="https://your-workbench-server.com/api.php"
export WORKBENCH_USER="your_username"
export WORKBENCH_TOKEN="your_api_token"
```

### Python Dependencies

Install test dependencies:

```bash
pip install -e ".[test]"
```

This installs:
- `pytest` - Test framework
- `pytest-xdist` - Parallel test execution
- `pytest-mock` - Mocking support

## Running Tests

### Basic Usage

```bash
# Run all functional tests
pytest -v -m functional

# Run with live output (see print statements)
pytest -v -s -m functional

# Run specific test file
pytest -v tests/functional/test_scan_workflow.py

# Run specific test
pytest -v tests/functional/test_scan_workflow.py::TestScanWorkflow::test_scan_workflow
```

### Parallel Execution

Run tests in parallel for faster execution and load testing:

```bash
# Run with 4 parallel workers
pytest -v -m functional -n 4

# Run with auto-detected number of CPUs
pytest -v -m functional -n auto

# Run with parallel and live output
pytest -v -s -m functional -n 4
```

### Selective Execution

```bash
# Run only tests that don't require toolbox
pytest -v -m "functional and not requires_toolbox"

# Run only import tests
pytest -v -k "import"

# Run only scan tests (scan and scan-git)
pytest -v -k "scan"

# Exclude slow tests
pytest -v -m "functional and not slow"
```

### Debugging

```bash
# Drop into debugger on failure
pytest -v -m functional --pdb

# Show full diff on assertion failures
pytest -v -m functional --tb=long

# Stop on first failure
pytest -v -m functional -x

# Show detailed reasons for skipped tests
pytest -v -m functional -rs

# Very verbose output (inline skip reasons)
pytest -vv -m functional
```

## Test Structure

Each test file validates a complete end-to-end workflow:

### `test_scan_workflow.py`
**Workflow:** scan → show-results → evaluate-gates → download-reports
- Creates temporary source directory
- Performs scan with dependency analysis
- Validates all follow-up commands

### `test_scan_git_workflow.py`
**Workflow:** scan-git → show-results → evaluate-gates → download-reports
- Scans the workbench-agent GitHub repository
- Uses shallow clone (depth=1) for speed
- Validates all follow-up commands

### `test_blind_scan_workflow.py`
**Workflow:** blind-scan → show-results → evaluate-gates → download-reports → delete-scan
- Copies `tests/fixtures/signatures` to `signatures.fossid` under the temp source directory (the repo stores the fixture without a `.fossid` extension so other tooling is not confused by a stray hash file in `fixtures/`)
- Runs `blind-scan` with `--path` pointing at that file so Workbench receives pre-generated hashes and **fossid-toolbox is not required**
- Validates all follow-up commands

### `test_import_da_workflow.py`
**Workflow:** import-da → show-results → evaluate-gates → download-reports
- Uses fixture file: `tests/fixtures/analyzer-result.json`
- Imports dependency analysis results
- Validates all follow-up commands

### `test_import_sbom_workflow.py`
**Workflow:** import-sbom → show-results → evaluate-gates → download-reports
- Uses fixture file: `tests/fixtures/cyclonedx-bom.json`
- Imports SBOM in CycloneDX format
- Validates all follow-up commands

### `test_legacy_workflow.py`
**Workflow:** legacy (no-subcommand) scan → show-results → delete-scan
- Uses underscore flags (`--project_code`, `--scan_code`, `--api_url`, …)
- Covers default licenses, `--scans_get_results`, blind scan, DA-only, result-flag modes, kitchen-sink scan flags + `--path-result`, identification reuse, and rejected `--target_path`
- Display text may differ from the original agent; API behavior should match CE `scan` / `blind-scan` + `show-results`

## Fixtures

Shared test fixtures are defined in `conftest.py`:

- **`workbench_config`**: Validates and provides Workbench credentials
- **`temp_source_dir`**: Creates temporary source directory with sample files
- **`temp_reports_dir`**: Creates temporary directory for downloaded reports
- **`unique_scan_name`**: Generates unique scan names using process ID
- **`unique_scan_code`**: Generates unique alphanumeric scan codes for legacy CLI tests
- **`project_name`**: Standard project name for all tests
- **`project_code`**: Resolves the functional test project's internal Workbench code
- **`fixtures_dir`**: Path to test fixture files

## Best Practices

### For Development

1. **Run tests individually during development:**
   ```bash
   pytest -v -s tests/functional/test_scan_workflow.py
   ```

2. **Use `-s` flag to see progress output:**
   ```bash
   pytest -v -s -m functional
   ```

3. **Run in parallel for quick validation:**
   ```bash
   pytest -v -m functional -n 4
   ```

### For CI/CD

1. **Always use parallel execution:**
   ```bash
   pytest -v -m functional -n auto
   ```

2. **Generate coverage and XML reports:**
   ```bash
   pytest -v -m functional --cov=src --junit-xml=results.xml
   ```

3. **Skip tests that require special dependencies:**
   ```bash
   pytest -v -m "functional and not requires_toolbox"
   ```

## Troubleshooting

### Tests Skip with "Missing environment variables"

Ensure all required environment variables are set:
```bash
echo $WORKBENCH_URL
echo $WORKBENCH_USER
echo $WORKBENCH_TOKEN
```

### Tests fail with "workbench-agent command not found"

Install workbench-agent:
```bash
pip install -e .
```

### Parallel tests hang or fail

Reduce parallelism:
```bash
pytest -v -m functional -n 2
```

Or run sequentially:
```bash
pytest -v -m functional
```