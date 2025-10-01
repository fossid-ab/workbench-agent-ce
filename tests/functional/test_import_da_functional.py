#!/usr/bin/env python3
"""
Functional test for the import-da command.

This test performs an end-to-end workflow:
1. Run import-da command with analyzer result file
2. Show results
3. Evaluate gates
4. Download reports

The test uses environment variables for credentials:
- WORKBENCH_URL: API Endpoint URL
- WORKBENCH_USER: Workbench Username
- WORKBENCH_TOKEN: Workbench API Token
"""

import os
import subprocess
import sys
import time
from pathlib import Path


def run_command(cmd, description):
    """Run a command and return success status."""
    print(f"\n--- {description} ---")
    print(f"Running: {' '.join(cmd)}")
    
    try:
        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
        print(f"✓ {description} completed successfully")
        if result.stdout:
            print("STDOUT:", result.stdout)
        return True
    except subprocess.CalledProcessError as e:
        print(f"✗ {description} failed with exit code {e.returncode}")
        print("STDERR:", e.stderr)
        if e.stdout:
            print("STDOUT:", e.stdout)
        return False


def main():
    """Main test function."""
    print("Starting functional test for import-da command...")
    
    # Check required environment variables
    required_env_vars = ["WORKBENCH_URL", "WORKBENCH_USER", "WORKBENCH_TOKEN"]
    missing_vars = [var for var in required_env_vars if not os.getenv(var)]
    if missing_vars:
        print(f"Error: Missing required environment variables: {', '.join(missing_vars)}")
        sys.exit(1)
    
    # Use the test fixture analyzer result file
    test_fixtures_dir = Path(__file__).parent.parent / "fixtures"
    analyzer_result_file = test_fixtures_dir / "analyzer-result.json"
    
    if not analyzer_result_file.exists():
        print(f"Error: Test fixture file not found: {analyzer_result_file}")
        sys.exit(1)
    
    print(f"Using analyzer result file: {analyzer_result_file}")
    
    # Generate unique project and scan names
    timestamp = int(time.time())
    project_name = f"FunctionalTest-ImportDA-{timestamp}"
    scan_name = f"import-da-test-{timestamp}"
    
    # Base command arguments (without the command)
    base_args = [
        "workbench-agent",
    ]
    
    # Step 1: Run import-da command
    import_da_cmd = base_args + [
        "import-da",
        "--project-name", project_name,
        "--scan-name", scan_name,
        "--path", str(analyzer_result_file)
    ]
    
    if not run_command(import_da_cmd, "Import-DA Command"):
        return False
    
    # Step 2: Show results
    show_cmd = base_args + [
        "show-results",
        "--project-name", project_name,
        "--scan-name", scan_name,
        "--show-licenses",
        "--show-components", 
        "--show-dependencies",
        "--show-scan-metrics",
        "--show-vulnerabilities"
    ]
    
    if not run_command(show_cmd, "Show Results"):
        return False
    
    # Step 3: Evaluate gates
    gates_cmd = base_args + [
        "evaluate-gates",
        "--project-name", project_name,
        "--scan-name", scan_name,
        "--fail-on-pending",
        "--fail-on-policy"
    ]
    
    if not run_command(gates_cmd, "Evaluate Gates"):
        return False
    
    # Step 4: Download reports
    download_cmd = base_args + [
        "download-reports",
        "--project-name", project_name,
        "--scan-name", scan_name,
        "--report-scope", "project",
        "--report-type", "xlsx,spdx"
    ]
    
    if not run_command(download_cmd, "Download Reports"):
        return False
    
    print("\n✓ All import-da functional tests passed!")
    return True


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)

