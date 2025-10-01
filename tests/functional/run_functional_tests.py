#!/usr/bin/env python3
"""
Local functional test runner for workbench-agent.

This script provides convenient commands to run functional tests locally.
It checks for required environment variables and provides helpful error messages.
"""

import os
import subprocess
import sys
from pathlib import Path


def check_environment():
    """Check if required environment variables are set."""
    required_vars = ["WORKBENCH_URL", "WORKBENCH_USER", "WORKBENCH_TOKEN"]
    missing_vars = [var for var in required_vars if not os.getenv(var)]
    
    if missing_vars:
        print("❌ Missing required environment variables:")
        for var in missing_vars:
            print(f"   - {var}")
        print("\nPlease set these environment variables before running tests.")
        print("Example:")
        print("   export WORKBENCH_URL='https://your-workbench.com/api.php'")
        print("   export WORKBENCH_USER='your-username'")
        print("   export WORKBENCH_TOKEN='your-api-token'")
        return False
    
    print("✅ All required environment variables are set")
    return True


def run_test(test_file, description):
    """Run a single functional test."""
    print(f"\n{'='*60}")
    print(f"Running: {description}")
    print(f"{'='*60}")
    
    test_path = Path(__file__).parent / test_file
    if not test_path.exists():
        print(f"❌ Test file not found: {test_path}")
        return False
    
    try:
        result = subprocess.run([sys.executable, str(test_path)], check=True)
        print(f"✅ {description} completed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ {description} failed with exit code {e.returncode}")
        return False


def main():
    """Main function to handle command line arguments."""
    if len(sys.argv) < 2:
        print("Usage: python run_functional_tests.py <command>")
        print("\nAvailable commands:")
        print("  scan        - Run scan functional test")
        print("  scan-git    - Run scan-git functional test")
        print("  import-da   - Run import-da functional test")
        print("  import-sbom - Run import-sbom functional test")
        print("  all         - Run all functional tests")
        print("  check-env   - Check environment variables")
        sys.exit(1)
    
    command = sys.argv[1].lower()
    
    # Check environment variables for all commands except check-env
    if command != "check-env":
        if not check_environment():
            sys.exit(1)
    
    success = True
    
    if command == "scan":
        success = run_test("test_scan_functional.py", "Scan Functional Test")
    elif command == "scan-git":
        success = run_test("test_scan_git_functional.py", "Scan-Git Functional Test")
    elif command == "import-da":
        success = run_test("test_import_da_functional.py", "Import-DA Functional Test")
    elif command == "import-sbom":
        success = run_test("test_import_sbom_functional.py", "Import-SBOM Functional Test")
    elif command == "all":
        tests = [
            ("test_scan_functional.py", "Scan Functional Test"),
            ("test_scan_git_functional.py", "Scan-Git Functional Test"),
            ("test_import_da_functional.py", "Import-DA Functional Test"),
            ("test_import_sbom_functional.py", "Import-SBOM Functional Test"),
        ]
        
        for test_file, description in tests:
            if not run_test(test_file, description):
                success = False
        
        if success:
            print(f"\n{'='*60}")
            print("🎉 All functional tests passed!")
            print(f"{'='*60}")
        else:
            print(f"\n{'='*60}")
            print("💥 Some functional tests failed!")
            print(f"{'='*60}")
    elif command == "check-env":
        check_environment()
    else:
        print(f"Unknown command: {command}")
        print("Use 'python run_functional_tests.py' to see available commands")
        sys.exit(1)
    
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
