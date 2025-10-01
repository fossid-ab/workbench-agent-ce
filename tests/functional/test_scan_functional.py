#!/usr/bin/env python3
"""
Functional test for the scan command.

This test performs an end-to-end workflow:
1. Run scan command with dependency analysis
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
import tempfile
import shutil
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


def create_test_directory():
    """Create a temporary directory with some test files."""
    test_dir = tempfile.mkdtemp(prefix="workbench-test-scan-")
    
    # Create some test files
    (Path(test_dir) / "test.py").write_text("""
import requests
import json

def hello_world():
    print("Hello, World!")
    return "success"

if __name__ == "__main__":
    hello_world()
""")
    
    (Path(test_dir) / "requirements.txt").write_text("""
requests>=2.25.0
json5>=0.9.0
""")
    
    (Path(test_dir) / "README.md").write_text("""
# Test Project
This is a test project for workbench-agent functional testing.
""")
    
    return test_dir


def main():
    """Main test function."""
    print("Starting functional test for scan command...")
    
    # Check required environment variables
    required_env_vars = ["WORKBENCH_URL", "WORKBENCH_USER", "WORKBENCH_TOKEN"]
    missing_vars = [var for var in required_env_vars if not os.getenv(var)]
    if missing_vars:
        print(f"Error: Missing required environment variables: {', '.join(missing_vars)}")
        sys.exit(1)
    
    # Create test directory
    test_dir = create_test_directory()
    print(f"Created test directory: {test_dir}")
    
    try:
        # Generate unique project and scan names
        import time
        timestamp = int(time.time())
        project_name = f"FunctionalTest-Scan-{timestamp}"
        scan_name = f"scan-test-{timestamp}"
        
        # Base command arguments (without the command)
        base_args = [
            "workbench-agent",
        ]
        
        # Step 1: Run scan command
        scan_cmd = base_args + [
            "scan",
            "--project-name", project_name,
            "--scan-name", scan_name,
            "--path", test_dir,
            "--run-dependency-analysis",
            "--autoid-file-licenses",
            "--autoid-file-copyrights",
            "--no-wait"
        ]
        
        if not run_command(scan_cmd, "Scan Command"):
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
        
        print("\n✓ All scan functional tests passed!")
        return True
        
    finally:
        # Cleanup
        shutil.rmtree(test_dir, ignore_errors=True)
        print(f"Cleaned up test directory: {test_dir}")


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)

