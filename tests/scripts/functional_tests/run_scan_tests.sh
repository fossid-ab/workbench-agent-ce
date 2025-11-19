#!/bin/bash
# Functional tests for scan command
# Tests end-to-end workflow: scan → show-results → evaluate-gates → download-reports

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
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
FIXTURES_DIR="$PROJECT_ROOT/tests/fixtures"

# Test configuration
PROJECT_NAME="FunctionalTestProject"
SCAN_NAME="ScanTest-$$"

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

echo -e "${GREEN}=== Running Scan Functional Tests ===${NC}"
echo "Workbench URL: $WORKBENCH_URL"
echo "Workbench User: $WORKBENCH_USER"
echo "Project Name: $PROJECT_NAME"
echo "Scan Name: $SCAN_NAME"
if [ "$DEBUG" = true ]; then
    echo -e "${BLUE}Debug logging: ENABLED${NC}"
fi
echo ""

# Create a temporary directory for test files
TMP_DIR=$(mktemp -d)
trap "rm -rf $TMP_DIR" EXIT

# Create test directory
TEST_DIR="$TMP_DIR/scan_source"
mkdir -p "$TEST_DIR"
echo "print('Hello, World!')" > "$TEST_DIR/main.py"
echo "# Test Project" > "$TEST_DIR/README.md"
echo "requests==2.28.0" > "$TEST_DIR/requirements.txt"

# Create reports directory
REPORTS_DIR="$TMP_DIR/reports"
mkdir -p "$REPORTS_DIR"

# Test counter
PASSED=0
FAILED=0

# Function to display workflow progress
show_progress() {
    local current_step="$1"
    local steps=("scan" "results" "gates" "reports-project" "reports-scan")
    local progress=""
    
    for step in "${steps[@]}"; do
        if [ "$step" = "$current_step" ]; then
            progress+="${YELLOW}[$step]${NC} -> "
        elif [[ " ${steps[@]:0:$(($(echo "${steps[@]}" | tr ' ' '\n' | grep -n "^$current_step$" | cut -d: -f1) - 1))} " =~ " $step " ]]; then
            progress+="${GREEN}$step${NC} -> "
        else
            progress+="$step -> "
        fi
    done
    progress=${progress% -> }
    echo -e "${BLUE}[SCAN]${NC} Progress: $progress"
}

# Function to run a test
run_test() {
    local test_name="$1"
    local progress_step="$2"
    shift 2
    local cmd="$@"
    
    show_progress "$progress_step"
    echo -e "${YELLOW}Test: $test_name${NC}"
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

# Build log argument
LOG_ARG=""
if [ "$DEBUG" = true ]; then
    LOG_ARG="--log DEBUG"
fi

# Test 1: Scan
run_test "Step 1: Scan" "scan" \
    workbench-agent scan \
    --project-name "$PROJECT_NAME" \
    --scan-name "$SCAN_NAME" \
    --path "$TEST_DIR" \
    --run-dependency-analysis \
    $LOG_ARG

# Test 2: Show Results
run_test "Step 2: Show Results" "results" \
    workbench-agent show-results \
    --project-name "$PROJECT_NAME" \
    --scan-name "$SCAN_NAME" \
    --show-scan-metrics \
    --show-licenses \
    --show-components \
    --show-policy-warnings \
    --show-vulnerabilities \
    --show-dependencies \
    $LOG_ARG

# Test 3: Evaluate Gates
run_test "Step 3: Evaluate Gates" "gates" \
    workbench-agent evaluate-gates \
    --project-name "$PROJECT_NAME" \
    --scan-name "$SCAN_NAME" \
    $LOG_ARG

# Test 4: Download Reports (Project Scope)
run_test "Step 4: Download Reports (Project Scope)" "reports-project" \
    workbench-agent download-reports \
    --project-name "$PROJECT_NAME" \
    --report-scope project \
    --report-save-path "$REPORTS_DIR/project" \
    $LOG_ARG

# Test 5: Download Reports (Scan Scope)
run_test "Step 5: Download Reports (Scan Scope)" "reports-scan" \
    workbench-agent download-reports \
    --project-name "$PROJECT_NAME" \
    --scan-name "$SCAN_NAME" \
    --report-scope scan \
    --report-save-path "$REPORTS_DIR/scan" \
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
