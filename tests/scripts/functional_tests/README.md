# Functional Test Scripts

Bash scripts that run actual `workbench-agent` commands with DEBUG logging enabled. These scripts test the complete CLI workflows end-to-end against a real Workbench server.

## Prerequisites

1. **Environment Variables**: Set the following environment variables:
   ```bash
   export WORKBENCH_URL="https://your-workbench-server.com/api.php"
   export WORKBENCH_USER="your_username"
   export WORKBENCH_TOKEN="your_api_token"
   ```

2. **Optional**: For blind-scan tests, ensure `fossid-toolbox` is installed and available on your PATH.

## Usage

### Run All Tests

```bash
# Sequential execution (default)
./scripts/functional_tests/run_all_tests.sh

# Parallel execution
./scripts/functional_tests/run_all_tests.sh --parallel

# Parallel execution with custom concurrency
./scripts/functional_tests/run_all_tests.sh --parallel --max-parallel=8
```

### Run Individual Test Scripts

```bash
# Scan tests (sequential)
./scripts/functional_tests/run_scan_tests.sh

# Scan tests (parallel)
./scripts/functional_tests/run_scan_tests.sh --parallel --max-parallel=4

# Scan tests with debug output
./scripts/functional_tests/run_scan_tests.sh --debug

# Scan tests (parallel with debug)
./scripts/functional_tests/run_scan_tests.sh --parallel --max-parallel=4 --debug

# Scan-git tests
./scripts/functional_tests/run_scan_git_tests.sh

# Blind-scan tests (requires fossid-toolbox)
./scripts/functional_tests/run_blind_scan_tests.sh

# Import-DA tests
./scripts/functional_tests/run_import_da_tests.sh

# Import-SBOM tests
./scripts/functional_tests/run_import_sbom_tests.sh
```

### Parallel Stress Test

Run multiple test suites concurrently to stress-test the Workbench server:

```bash
# Default: 8 concurrent operations, 1 iteration per test suite
./scripts/functional_tests/run_parallel_stress_test.sh

# Custom concurrency and iterations
./scripts/functional_tests/run_parallel_stress_test.sh --max-parallel=16 --iterations=3

# Stress test with debug logging
./scripts/functional_tests/run_parallel_stress_test.sh --max-parallel=16 --iterations=3 --debug
```

This will:
- Run all test suites multiple times in parallel
- Stress-test the Workbench server with concurrent operations
- Generate detailed logs for debugging
- Provide a comprehensive summary

## Test Scripts

### `run_scan_tests.sh`
Tests for the `scan` command:
- Basic scan with directory
- Scan with ZIP file
- Scan with AutoID
- Scan with dependency analysis
- Scan with all display options

### `run_scan_git_tests.sh`
Tests for the `scan-git` command:
- Basic scan-git with branch
- Scan-git with dependency analysis
- Scan-git with delta scan
- Scan-git with AutoID

### `run_blind_scan_tests.sh`
Tests for the `blind-scan` command:
- Basic blind-scan
- Blind-scan with AutoID
- Blind-scan with dependency analysis
- *Requires fossid-toolbox*

### `run_import_da_tests.sh`
Tests for the `import-da` command:
- Basic DA import
- DA import with results display
- Multiple DA file imports

### `run_import_sbom_tests.sh`
Tests for the `import-sbom` command:
- CycloneDX JSON import
- SPDX RDF import
- SBOM import with results display

## Features

- **Optional DEBUG Logging**: Use `--debug` flag to enable `--log DEBUG` for detailed output
- **Real Commands**: Tests run actual `workbench-agent` CLI commands
- **Color Output**: Color-coded test results (green for pass, red for fail)
- **Test Summary**: Each script provides a summary of passed/failed tests
- **Error Handling**: Scripts exit with appropriate exit codes
- **Parallel Execution**: Support for running tests in parallel to stress-test the server
- **Controlled Concurrency**: Limit the number of concurrent operations to avoid overwhelming the server

## Debugging

When a test fails, check:

1. **Debug Log**: Run tests with `--debug` flag to enable detailed logging written to `workbench-agent-log.txt`
2. **Console Output**: All command output is displayed in the console
3. **Workbench Server**: Check your Workbench server for created projects/scans
4. **Environment Variables**: Ensure all required environment variables are set

## Notes

- Tests create real projects and scans on your Workbench server
- Some tests may take several minutes to complete (waiting for scans to finish)
- Tests use temporary directories/files that are cleaned up automatically
- If a test fails, the script will continue with remaining tests (unless using `set -e`)

## Customizing Tests

You can easily modify the test scripts to:
- Change project/scan names
- Add additional test cases
- Modify command arguments
- Use different test data

Each script follows a simple pattern:
1. Setup (create test files/directories)
2. Run tests using the `run_test` function
3. Display summary

