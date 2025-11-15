#!/bin/bash
# Functional tests for scan command
# Runs actual workbench-agent scan commands with DEBUG logging

# Don't exit on error - we want to run all tests
set +e

# Parse arguments
PARALLEL=false
MAX_PARALLEL=4
DEBUG=false
for arg in "$@"; do
    case $arg in
        --parallel|-p)
            PARALLEL=true
            shift
            ;;
        --max-parallel=*)
            MAX_PARALLEL="${arg#*=}"
            PARALLEL=true
            shift
            ;;
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
FIXTURES_DIR="$PROJECT_ROOT/tests/fixtures"

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
if [ "$PARALLEL" = true ]; then
    echo -e "${BLUE}Parallel execution: ENABLED (max $MAX_PARALLEL concurrent)${NC}"
fi
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

# Create test ZIP file
TEST_ZIP="$TMP_DIR/test_scan.zip"
cd "$TEST_DIR"
zip -q -r "$TEST_ZIP" .
cd - > /dev/null

# Test counter
PASSED=0
FAILED=0
declare -a PIDS=()
declare -a TEST_NAMES=()
declare -a TEST_RESULTS=()

# Function to run a test (supports parallel execution)
run_test() {
    local test_name="$1"
    shift
    local cmd="$@"
    
    if [ "$PARALLEL" = true ]; then
        # Wait if we've reached max parallel processes
        while [ ${#PIDS[@]} -ge $MAX_PARALLEL ]; do
            for pid in "${PIDS[@]}"; do
                if ! kill -0 "$pid" 2>/dev/null; then
                    # Process finished, remove from array
                    wait "$pid"
                    local exit_code=$?
                    local idx=0
                    for p in "${PIDS[@]}"; do
                        if [ "$p" = "$pid" ]; then
                            TEST_RESULTS[$idx]=$exit_code
                            unset PIDS[$idx]
                            unset TEST_NAMES[$idx]
                            PIDS=("${PIDS[@]}")
                            TEST_NAMES=("${TEST_NAMES[@]}")
                            break
                        fi
                        ((idx++))
                    done
                    break
                fi
            done
            sleep 0.1
        done
        
        # Run test in background
        (
            echo -e "${YELLOW}[$(date +%H:%M:%S)] Starting: $test_name${NC}"
            if eval "$cmd" > "$TMP_DIR/${test_name// /_}.log" 2>&1; then
                echo -e "${GREEN}[$(date +%H:%M:%S)] ✓ PASSED: $test_name${NC}"
                exit 0
            else
                echo -e "${RED}[$(date +%H:%M:%S)] ✗ FAILED: $test_name${NC}"
                cat "$TMP_DIR/${test_name// /_}.log"
                exit 1
            fi
        ) &
        local pid=$!
        PIDS+=($pid)
        TEST_NAMES+=("$test_name")
    else
        # Sequential execution
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
    fi
}

# Build log argument
LOG_ARG=""
if [ "$DEBUG" = true ]; then
    LOG_ARG="--log DEBUG"
fi

# Test 1: Basic scan with directory
run_test "Basic Scan (Directory)" \
    workbench-agent scan \
    --project-name "FunctionalTestProject" \
    --scan-name "BasicScanTest-$$" \
    --path "$TEST_DIR" \
    $LOG_ARG

# Test 2: Scan with ZIP file
run_test "Scan with ZIP File" \
    workbench-agent scan \
    --project-name "FunctionalTestProject" \
    --scan-name "ZipScanTest-$$" \
    --path "$TEST_ZIP" \
    $LOG_ARG

# Test 3: Scan with AutoID
run_test "Scan with AutoID" \
    workbench-agent scan \
    --project-name "FunctionalTestProject" \
    --scan-name "AutoIDScanTest-$$" \
    --path "$TEST_DIR" \
    --autoid-file-licenses \
    --autoid-file-copyrights \
    --autoid-pending-ids \
    --show-licenses \
    --show-policy-warnings \
    $LOG_ARG

# Test 4: Scan with dependency analysis
run_test "Scan with Dependency Analysis" \
    workbench-agent scan \
    --project-name "FunctionalTestProject" \
    --scan-name "DAScanTest-$$" \
    --path "$TEST_DIR" \
    --run-dependency-analysis \
    --show-dependencies \
    --show-vulnerabilities \
    $LOG_ARG

# Test 5: Scan with all display options
run_test "Scan with All Display Options" \
    workbench-agent scan \
    --project-name "FunctionalTestProject" \
    --scan-name "FullDisplayScanTest-$$" \
    --path "$TEST_DIR" \
    --show-scan-metrics \
    --show-licenses \
    --show-components \
    --show-policy-warnings \
    --show-vulnerabilities \
    --show-dependencies \
    $LOG_ARG

# Wait for all parallel processes to complete
if [ "$PARALLEL" = true ]; then
    echo -e "\n${BLUE}Waiting for all tests to complete...${NC}"
    for pid in "${PIDS[@]}"; do
        wait "$pid"
        local exit_code=$?
        if [ $exit_code -eq 0 ]; then
            ((PASSED++))
        else
            ((FAILED++))
        fi
    done
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
