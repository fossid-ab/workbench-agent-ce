#!/bin/bash
# Functional tests for blind-scan command
# Runs actual workbench-agent blind-scan commands

# Don't exit on error - we want to run all tests
set +e

# Parse arguments
DEBUG=false
for arg in "$@"; do
    case $arg in
        --debug)
            DEBUG=true
            shift
            ;;
        *)
            shift
            ;;
    esac
done

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Check for workbench-agent command
if ! command -v workbench-agent &> /dev/null; then
    echo -e "${RED}ERROR: workbench-agent command not found${NC}"
    echo "Please ensure workbench-agent is installed and in your PATH"
    exit 1
fi

# Check for required environment variables
if [ -z "$WORKBENCH_URL" ] || [ -z "$WORKBENCH_USER" ] || [ -z "$WORKBENCH_TOKEN" ]; then
    echo -e "${RED}ERROR: Missing required environment variables${NC}"
    echo "Please set: WORKBENCH_URL, WORKBENCH_USER, WORKBENCH_TOKEN"
    exit 1
fi

# Check for fossid-toolbox
if ! command -v fossid-toolbox &> /dev/null; then
    echo -e "${YELLOW}WARNING: fossid-toolbox not found in PATH${NC}"
    echo "Some tests may fail. Please ensure fossid-toolbox is installed."
    TOOLBOX_PATH=""
else
    TOOLBOX_PATH=$(which fossid-toolbox)
    echo "Found fossid-toolbox at: $TOOLBOX_PATH"
fi

echo -e "${GREEN}=== Running Blind-Scan Functional Tests ===${NC}"
echo "Workbench URL: $WORKBENCH_URL"
echo "Workbench User: $WORKBENCH_USER"
if [ "$DEBUG" = true ]; then
    echo -e "${BLUE}Debug logging: ENABLED${NC}"
fi
echo ""

# Build log argument
LOG_ARG=""
if [ "$DEBUG" = true ]; then
    LOG_ARG="--log DEBUG"
fi

# Create a temporary directory for test files
TMP_DIR=$(mktemp -d)
trap "rm -rf $TMP_DIR" EXIT

# Create test directory
TEST_DIR="$TMP_DIR/blind_scan_source"
mkdir -p "$TEST_DIR"
echo "print('Hello, World!')" > "$TEST_DIR/main.py"
echo "# Test Project" > "$TEST_DIR/README.md"
echo "def helper(): pass" > "$TEST_DIR/utils.py"

# Test counter
PASSED=0
FAILED=0

# Function to run a test
run_test() {
    local test_name="$1"
    shift
    local cmd="$@"
    
    echo -e "\n${YELLOW}Test: $test_name${NC}"
    echo "Command: $cmd"
    echo "---"
    
    if eval "$cmd"; then
        echo -e "${GREEN}✓ PASSED${NC}"
        ((PASSED++))
        return 0
    else
        echo -e "${RED}✗ FAILED${NC}"
        ((FAILED++))
        return 1
    fi
}

# Build toolbox path argument
TOOLBOX_ARG=""
if [ -n "$TOOLBOX_PATH" ]; then
    TOOLBOX_ARG="--fossid-toolbox-path $TOOLBOX_PATH"
fi

# Test 1: Basic blind-scan
if [ -n "$TOOLBOX_PATH" ]; then
    run_test "Basic Blind-Scan" \
        workbench-agent blind-scan \
        --project-name "FunctionalTestProject" \
        --scan-name "BlindScanTest" \
        --path "$TEST_DIR" \
        $TOOLBOX_ARG \
        $LOG_ARG
else
    echo -e "${YELLOW}Skipping blind-scan tests (fossid-toolbox not available)${NC}"
fi

# Test 2: Blind-scan with AutoID
if [ -n "$TOOLBOX_PATH" ]; then
    run_test "Blind-Scan with AutoID" \
        workbench-agent blind-scan \
        --project-name "FunctionalTestProject" \
        --scan-name "BlindAutoIDScanTest" \
        --path "$TEST_DIR" \
        $TOOLBOX_ARG \
        --autoid-file-licenses \
        --autoid-file-copyrights \
        --autoid-pending-ids \
        --show-licenses \
        --show-policy-warnings \
        $LOG_ARG
fi

# Test 3: Blind-scan with dependency analysis
if [ -n "$TOOLBOX_PATH" ]; then
    # Create package.json for DA test
    echo '{"dependencies": {"express": "^4.18.0"}}' > "$TEST_DIR/package.json"
    echo "const express = require('express');" > "$TEST_DIR/main.js"
    
    run_test "Blind-Scan with Dependency Analysis" \
        workbench-agent blind-scan \
        --project-name "FunctionalTestProject" \
        --scan-name "BlindDAScanTest" \
        --path "$TEST_DIR" \
        $TOOLBOX_ARG \
        --run-dependency-analysis \
        --show-dependencies \
        --show-vulnerabilities \
        $LOG_ARG
fi

# Summary
echo ""
echo "=== Test Summary ==="
echo -e "${GREEN}Passed: $PASSED${NC}"
echo -e "${RED}Failed: $FAILED${NC}"

if [ $FAILED -eq 0 ]; then
    exit 0
else
    exit 1
fi

