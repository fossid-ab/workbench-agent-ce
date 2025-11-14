#!/bin/bash
# Functional tests for scan-git command
# Runs actual workbench-agent scan-git commands

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

echo -e "${GREEN}=== Running Scan-Git Functional Tests ===${NC}"
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

# Test repository (using workbench-agent repo itself)
TEST_REPO="https://github.com/fossid-ab/workbench-agent"
TEST_BRANCH="main"

# Test 1: Basic scan-git with branch
run_test "Basic Scan-Git (Branch)" \
    workbench-agent scan-git \
    --project-name "FunctionalTestProject" \
    --scan-name "GitScanTest" \
    --git-url "$TEST_REPO" \
    --git-branch "$TEST_BRANCH" \
    --git-depth 1 \
    $LOG_ARG

# Test 2: Scan-git with dependency analysis
run_test "Scan-Git with Dependency Analysis" \
    workbench-agent scan-git \
    --project-name "FunctionalTestProject" \
    --scan-name "GitDAScanTest" \
    --git-url "$TEST_REPO" \
    --git-branch "$TEST_BRANCH" \
    --git-depth 1 \
    --run-dependency-analysis \
    --show-dependencies \
    --show-vulnerabilities \
    $LOG_ARG

# Test 3: Scan-git with delta scan
run_test "Scan-Git with Delta Scan" \
    workbench-agent scan-git \
    --project-name "FunctionalTestProject" \
    --scan-name "GitDeltaScanTest" \
    --git-url "$TEST_REPO" \
    --git-branch "$TEST_BRANCH" \
    --git-depth 1 \
    --delta-scan \
    --show-scan-metrics \
    $LOG_ARG

# Test 4: Scan-git with AutoID
run_test "Scan-Git with AutoID" \
    workbench-agent scan-git \
    --project-name "FunctionalTestProject" \
    --scan-name "GitAutoIDScanTest" \
    --git-url "$TEST_REPO" \
    --git-branch "$TEST_BRANCH" \
    --git-depth 1 \
    --autoid-file-licenses \
    --autoid-file-copyrights \
    --autoid-pending-ids \
    --show-licenses \
    --show-policy-warnings \
    $LOG_ARG

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

