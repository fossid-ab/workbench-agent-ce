# Functional Tests

Production-grade end-to-end functional tests using pytest. These tests execute actual `workbench-agent` CLI commands against a real Workbench server to validate complete workflows.

## Prerequisites

### Required Environment Variables

```bash
export WORKBENCH_URL="https://your-workbench-server.com/api.php"
export WORKBENCH_USER="your_username"
export WORKBENCH_TOKEN="your_api_token"
```

### Optional Dependencies

- **fossid-toolbox**: Required for `test_blind_scan_workflow.py`
  - Must be installed and available on PATH
  - Tests will be skipped if not found

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
**Workflow:** blind-scan → show-results → evaluate-gates → download-reports
- Requires fossid-toolbox installed
- Creates temporary source directory
- Performs blind scan with dependency analysis
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

## CI/CD Integration

### GitHub Actions Example

```yaml
name: Functional Tests

on: [push, pull_request]

jobs:
  functional-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - uses: actions/setup-python@v4
        with:
          python-version: '3.9'
      
      - name: Install dependencies
        run: |
          pip install -e ".[test]"
      
      - name: Run functional tests
        env:
          WORKBENCH_URL: ${{ secrets.WORKBENCH_URL }}
          WORKBENCH_USER: ${{ secrets.WORKBENCH_USER }}
          WORKBENCH_TOKEN: ${{ secrets.WORKBENCH_TOKEN }}
        run: |
          pytest -v -m "functional and not requires_toolbox" -n 4
      
      - name: Run blind-scan tests (if toolbox available)
        if: ${{ env.TOOLBOX_INSTALLED }}
        run: |
          pytest -v -m "functional and requires_toolbox"
```

### JUnit XML Output

Generate JUnit XML for CI tools:

```bash
pytest -v -m functional --junit-xml=test-results.xml
```

## Fixtures

Shared test fixtures are defined in `conftest.py`:

- **`workbench_config`**: Validates and provides Workbench credentials
- **`temp_source_dir`**: Creates temporary source directory with sample files
- **`temp_reports_dir`**: Creates temporary directory for downloaded reports
- **`unique_scan_name`**: Generates unique scan names using process ID
- **`project_name`**: Standard project name for all tests
- **`fixtures_dir`**: Path to test fixture files
- **`fossid_toolbox_path`**: Validates and provides toolbox path

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

### blind-scan tests skip with "fossid-toolbox not found"

Install fossid-toolbox and ensure it's on your PATH:
```bash
which fossid-toolbox
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

## Comparison with Bash Scripts

These pytest tests replace the bash scripts in `tests/scripts/functional_tests/`:

| **Aspect** | **Bash Scripts** | **pytest Tests** |
|------------|-----------------|------------------|
| **Framework** | Custom bash | Industry-standard pytest |
| **Parallel** | Custom logic with issues | Built-in with pytest-xdist |
| **Debugging** | Echo statements | pytest debugger, detailed assertions |
| **CI Integration** | Basic exit codes | JUnit XML, coverage reports |
| **Maintenance** | Shell scripting complexity | Python, easy to understand |
| **Fixtures** | Manual setup/teardown | pytest fixtures with auto-cleanup |
| **Error Messages** | Basic | Detailed with full context |

The bash scripts can be kept as a backup or removed once pytest tests are validated.

