# Functional Test Scripts

Bash scripts that test end-to-end workflows for `workbench-agent` commands. Each test script executes a complete workflow: initial scan/import → show-results → evaluate-gates → download-reports, demonstrating how commands can be stacked in real-world scenarios.

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

Run all test suites sequentially or in parallel:

```bash
# Sequential execution (default)
./scripts/functional_tests/run_all_tests.sh

# Parallel execution (runs test suites concurrently)
./scripts/functional_tests/run_all_tests.sh --parallel

# Parallel execution with custom concurrency
./scripts/functional_tests/run_all_tests.sh --parallel --max-parallel=3

# With debug logging
./scripts/functional_tests/run_all_tests.sh --parallel --debug
```

### Run Individual Test Scripts

Each test script runs a complete end-to-end workflow for its respective handler:

```bash
# Scan workflow
./scripts/functional_tests/run_scan_tests.sh

# Scan-git workflow
./scripts/functional_tests/run_scan_git_tests.sh

# Blind-scan workflow (requires fossid-toolbox)
./scripts/functional_tests/run_blind_scan_tests.sh

# Import-DA workflow
./scripts/functional_tests/run_import_da_tests.sh

# Import-SBOM workflow
./scripts/functional_tests/run_import_sbom_tests.sh

# Run with debug logging
./scripts/functional_tests/run_scan_tests.sh --debug
```

### Parallel Stress Test

Run multiple test suites concurrently to stress-test the Workbench server and validate waiting logic:

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
- Test concurrent end-to-end workflows
- Validate the waiting logic in handlers when multiple scans are running
- Stress-test the Workbench server with concurrent operations
- Generate detailed logs for debugging
- Provide a comprehensive summary

## Test Scripts

Each test script executes a complete 5-step workflow to validate end-to-end command stacking:

### `run_scan_tests.sh`
**Workflow:** scan → show-results → evaluate-gates → download-reports
1. Performs a scan with dependency analysis
2. Displays results with all show options
3. Evaluates quality gates
4. Downloads project-level reports
5. Downloads scan-level reports

### `run_scan_git_tests.sh`
**Workflow:** scan-git → show-results → evaluate-gates → download-reports
1. Performs a Git repository scan with dependency analysis
2. Displays results with all show options
3. Evaluates quality gates
4. Downloads project-level reports
5. Downloads scan-level reports

### `run_blind_scan_tests.sh`
**Workflow:** blind-scan → show-results → evaluate-gates → download-reports
1. Performs a blind scan with dependency analysis (*requires fossid-toolbox*)
2. Displays results with all show options
3. Evaluates quality gates
4. Downloads project-level reports
5. Downloads scan-level reports

### `run_import_da_tests.sh`
**Workflow:** import-da → show-results → evaluate-gates → download-reports
1. Imports dependency analysis results
2. Displays results with all show options
3. Evaluates quality gates
4. Downloads project-level reports
5. Downloads scan-level reports

### `run_import_sbom_tests.sh`
**Workflow:** import-sbom → show-results → evaluate-gates → download-reports
1. Imports SBOM (CycloneDX format)
2. Displays results with all show options
3. Evaluates quality gates
4. Downloads project-level reports
5. Downloads scan-level reports

## Features

- **End-to-End Workflows**: Each test validates a complete user workflow with command stacking
- **Project/Scan Reuse**: Same project and scan are used across all workflow steps
- **Dual Report Scope**: Tests both project-level and scan-level report downloads
- **Optional DEBUG Logging**: Use `--debug` flag to enable `--log DEBUG` for detailed output
- **Real Commands**: Tests run actual `workbench-agent` CLI commands against a live Workbench server
- **Color Output**: Color-coded test results (green for pass, red for fail)
- **Test Summary**: Each script provides a summary of passed/failed tests
- **Error Handling**: Scripts exit with appropriate exit codes
- **Parallel Test Suites**: Run multiple test suites in parallel to load-test Workbench server
- **Controlled Concurrency**: Limit the number of concurrent test suites to avoid overwhelming the server

## Debugging

When a workflow step fails, check:

1. **Debug Log**: Run tests with `--debug` flag to enable detailed logging written to `workbench-agent-log.txt`
2. **Console Output**: All command output is displayed in the console
3. **Workbench Server**: Check your Workbench server for created projects/scans
4. **Workflow State**: Check which step failed - later steps depend on earlier ones succeeding
5. **Project/Scan Names**: Each test uses a unique scan name (with PID suffix) but shared project name
6. **Environment Variables**: Ensure all required environment variables are set
7. **Dependencies**: For blind-scan tests, ensure `fossid-toolbox` is installed and accessible

## Notes

- Tests create real projects and scans on your Workbench server
- Each test suite reuses the same project/scan across all workflow steps
- Some tests may take several minutes to complete (waiting for scans to finish)
- Tests use temporary directories/files that are cleaned up automatically
- Reports are downloaded to temporary directories and cleaned up after tests
- If a workflow step fails, subsequent steps will still be attempted
- Parallel execution runs different test suites concurrently (not individual steps within a workflow)

## Customizing Tests

You can easily modify the test scripts to:
- Change project/scan names (via `PROJECT_NAME` and `SCAN_NAME` constants)
- Add additional workflow steps
- Modify command arguments
- Use different test data
- Test different report formats

Each script follows a consistent pattern:
1. Setup (create test files/directories, define constants)
2. Step 1: Run initial operation (scan/import)
3. Step 2: Show results with all display options
4. Step 3: Evaluate quality gates
5. Step 4: Download project-level reports
6. Step 5: Download scan-level reports
7. Display summary

