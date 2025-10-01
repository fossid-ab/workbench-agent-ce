# Functional Tests

This directory contains end-to-end functional tests for the workbench-agent commands.

## Prerequisites

Before running the functional tests, you need to set up the following environment variables:

```bash
export WORKBENCH_URL='https://your-workbench-instance.com/api.php'
export WORKBENCH_USER='your-username'
export WORKBENCH_TOKEN='your-api-token'
```

## Running Tests

### Using the Test Runner Script

The easiest way to run tests is using the provided runner script:

```bash
# Check if environment variables are set correctly
python tests/functional/run_functional_tests.py check-env

# Run individual tests
python tests/functional/run_functional_tests.py scan
python tests/functional/run_functional_tests.py scan-git
python tests/functional/run_functional_tests.py import-da
python tests/functional/run_functional_tests.py import-sbom

# Run all tests
python tests/functional/run_functional_tests.py all
```

### Running Tests Directly

You can also run the individual test scripts directly:

```bash
python tests/functional/test_scan_functional.py
python tests/functional/test_scan_git_functional.py
python tests/functional/test_import_da_functional.py
python tests/functional/test_import_sbom_functional.py
```

## Test Descriptions

### `test_scan_functional.py`
- Creates a temporary directory with test files
- Runs `scan` command with dependency analysis
- Tests: scan → show-results → evaluate-gates → download-reports

### `test_scan_git_functional.py`
- Uses the `octocat/Hello-World` GitHub repository
- Runs `scan-git` command with dependency analysis
- Tests: scan-git → show-results → evaluate-gates → download-reports

### `test_import_da_functional.py`
- Uses the `analyzer-result.json` test fixture
- Runs `import-da` command
- Tests: import-da → show-results → evaluate-gates → download-reports

### `test_import_sbom_functional.py`
- Uses both SPDX and CycloneDX test fixtures
- Runs `import-sbom` command for both formats
- Tests: import-sbom → show-results → evaluate-gates → download-reports

## Notes

- Each test run generates unique project and scan names using timestamps
- Tests are designed to be independent and can be run in any order
- All tests follow the same workflow pattern as the GitHub Actions dogfood workflow
- Tests will clean up after themselves (temporary files, etc.)
