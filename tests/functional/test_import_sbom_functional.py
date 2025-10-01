#!/usr/bin/env python3
"""
Functional test for the import-sbom command.

This test performs an end-to-end workflow:
1. Run import-sbom command with SBOM files
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


def test_sbom_import(sbom_file, sbom_type):
    """Test importing a specific SBOM file."""
    print(f"\n=== Testing {sbom_type} SBOM Import ===")
    
    # Generate unique project and scan names
    timestamp = int(time.time())
    project_name = f"FunctionalTest-ImportSBOM-{sbom_type}-{timestamp}"
    scan_name = f"import-sbom-{sbom_type.lower()}-test-{timestamp}"
    
    # Base command arguments (without the command)
    base_args = [
        "workbench-agent",
    ]
    
    # Step 1: Run import-sbom command
    import_sbom_cmd = base_args + [
        "import-sbom",
        "--project-name", project_name,
        "--scan-name", scan_name,
        "--path", str(sbom_file)
    ]
    
    if not run_command(import_sbom_cmd, f"Import-SBOM Command ({sbom_type})"):
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
    
    if not run_command(show_cmd, f"Show Results ({sbom_type})"):
        return False
    
    # Step 3: Evaluate gates
    gates_cmd = base_args + [
        "evaluate-gates",
        "--project-name", project_name,
        "--scan-name", scan_name,
        "--fail-on-pending",
        "--fail-on-policy"
    ]
    
    if not run_command(gates_cmd, f"Evaluate Gates ({sbom_type})"):
        return False
    
    # Step 4: Download reports
    download_cmd = base_args + [
        "download-reports",
        "--project-name", project_name,
        "--scan-name", scan_name,
        "--report-scope", "project",
        "--report-type", "xlsx,spdx"
    ]
    
    if not run_command(download_cmd, f"Download Reports ({sbom_type})"):
        return False
    
    print(f"✓ {sbom_type} SBOM import functional test passed!")
    return True


def main():
    """Main test function."""
    print("Starting functional test for import-sbom command...")
    
    # Check required environment variables
    required_env_vars = ["WORKBENCH_URL", "WORKBENCH_USER", "WORKBENCH_TOKEN"]
    missing_vars = [var for var in required_env_vars if not os.getenv(var)]
    if missing_vars:
        print(f"Error: Missing required environment variables: {', '.join(missing_vars)}")
        sys.exit(1)
    
    # Use the test fixture SBOM files
    test_fixtures_dir = Path(__file__).parent.parent / "fixtures"
    
    # Test SPDX SBOM
    spdx_file = test_fixtures_dir / "spdx-document.rdf"
    if not spdx_file.exists():
        print(f"Error: SPDX test fixture file not found: {spdx_file}")
        sys.exit(1)
    
    # Test CycloneDX SBOM
    cyclonedx_file = test_fixtures_dir / "cyclonedx-bom.json"
    if not cyclonedx_file.exists():
        print(f"Error: CycloneDX test fixture file not found: {cyclonedx_file}")
        sys.exit(1)
    
    print(f"Using SPDX SBOM file: {spdx_file}")
    print(f"Using CycloneDX SBOM file: {cyclonedx_file}")
    
    # Test both SBOM formats
    success = True
    
    # Test SPDX import
    if not test_sbom_import(spdx_file, "SPDX"):
        success = False
    
    # Test CycloneDX import
    if not test_sbom_import(cyclonedx_file, "CycloneDX"):
        success = False
    
    if success:
        print("\n✓ All import-sbom functional tests passed!")
    else:
        print("\n✗ Some import-sbom functional tests failed!")
    
    return success


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)

