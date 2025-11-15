#!/bin/bash
# Parallel stress test - runs multiple test suites concurrently
# This script stress-tests the Workbench server by running many operations in parallel

set +e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Default values
MAX_PARALLEL=${MAX_PARALLEL:-8}
ITERATIONS=${ITERATIONS:-1}
DEBUG=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --max-parallel=*)
            MAX_PARALLEL="${1#*=}"
            shift
            ;;
        --iterations=*)
            ITERATIONS="${1#*=}"
            shift
            ;;
        --debug)
            DEBUG=true
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [--max-parallel=N] [--iterations=N] [--debug]"
            echo ""
            echo "Options:"
            echo "  --max-parallel=N    Maximum number of concurrent operations (default: 8)"
            echo "  --iterations=N      Number of times to run each test suite (default: 1)"
            echo "  --debug            Enable debug logging for all commands"
            echo ""
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Check for required environment variables
if [ -z "$WORKBENCH_URL" ] || [ -z "$WORKBENCH_USER" ] || [ -z "$WORKBENCH_TOKEN" ]; then
    echo -e "${RED}ERROR: Missing required environment variables${NC}"
    echo "Please set: WORKBENCH_URL, WORKBENCH_USER, WORKBENCH_TOKEN"
    exit 1
fi

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  Parallel Stress Test${NC}"
echo -e "${BLUE}========================================${NC}"
echo "Workbench URL: $WORKBENCH_URL"
echo "Workbench User: $WORKBENCH_USER"
echo "Max Parallel Operations: $MAX_PARALLEL"
echo "Iterations: $ITERATIONS"
if [ "$DEBUG" = true ]; then
    echo -e "${BLUE}Debug logging: ENABLED${NC}"
fi
echo ""

# Create temporary directory for logs
LOG_DIR=$(mktemp -d)
trap "rm -rf $LOG_DIR" EXIT

# Function to run a test script in background
run_test_script() {
    local script_name="$1"
    local iteration="$2"
    local log_file="$LOG_DIR/${script_name}_${iteration}.log"
    
        (
            echo "[$(date +%H:%M:%S)] Starting $script_name (iteration $iteration)"
            DEBUG_ARG=""
            if [ "$DEBUG" = true ]; then
                DEBUG_ARG="--debug"
            fi
            bash "$SCRIPT_DIR/$script_name" --parallel --max-parallel=$MAX_PARALLEL $DEBUG_ARG > "$log_file" 2>&1
        local exit_code=$?
        if [ $exit_code -eq 0 ]; then
            echo "[$(date +%H:%M:%S)] ✓ PASSED: $script_name (iteration $iteration)"
        else
            echo "[$(date +%H:%M:%S)] ✗ FAILED: $script_name (iteration $iteration)"
            echo "--- Log output ---"
            tail -50 "$log_file"
            echo "--- End log ---"
        fi
        exit $exit_code
    ) &
    echo $!
}

# Collect all test scripts
TEST_SCRIPTS=(
    "run_scan_tests.sh"
    "run_scan_git_tests.sh"
    "run_import_da_tests.sh"
    "run_import_sbom_tests.sh"
)

# Add blind-scan if fossid-toolbox is available
if command -v fossid-toolbox &> /dev/null; then
    TEST_SCRIPTS+=("run_blind_scan_tests.sh")
fi

# Counters
TOTAL_PASSED=0
TOTAL_FAILED=0
declare -a PIDS=()

# Generate all test jobs
declare -a JOBS=()
for script in "${TEST_SCRIPTS[@]}"; do
    for ((i=1; i<=ITERATIONS; i++)); do
        JOBS+=("$script:$i")
    done
done

echo -e "${BLUE}Total test jobs: ${#JOBS[@]}${NC}"
echo -e "${BLUE}Starting parallel execution...${NC}"
echo ""

# Run tests with controlled parallelism
JOB_INDEX=0
while [ $JOB_INDEX -lt ${#JOBS[@]} ] || [ ${#PIDS[@]} -gt 0 ]; do
    # Start new jobs if we have capacity
    while [ ${#PIDS[@]} -lt $MAX_PARALLEL ] && [ $JOB_INDEX -lt ${#JOBS[@]} ]; do
        JOB="${JOBS[$JOB_INDEX]}"
        SCRIPT_NAME="${JOB%%:*}"
        ITERATION="${JOB##*:}"
        
        PID=$(run_test_script "$SCRIPT_NAME" "$ITERATION")
        PIDS+=($PID)
        echo -e "${YELLOW}[$((JOB_INDEX + 1))/${#JOBS[@]}] Started: $SCRIPT_NAME (iteration $ITERATION) [PID: $PID]${NC}"
        ((JOB_INDEX++))
    done
    
    # Check for completed processes
    for i in "${!PIDS[@]}"; do
        PID="${PIDS[$i]}"
        if ! kill -0 "$PID" 2>/dev/null; then
            # Process finished
            wait "$PID"
            EXIT_CODE=$?
            if [ $EXIT_CODE -eq 0 ]; then
                ((TOTAL_PASSED++))
            else
                ((TOTAL_FAILED++))
            fi
            unset PIDS[$i]
            PIDS=("${PIDS[@]}")
            break
        fi
    done
    
    # Small sleep to avoid busy-waiting
    sleep 0.1
done

# Wait for any remaining processes
for PID in "${PIDS[@]}"; do
    wait "$PID"
    EXIT_CODE=$?
    if [ $EXIT_CODE -eq 0 ]; then
        ((TOTAL_PASSED++))
    else
        ((TOTAL_FAILED++))
    fi
done

# Summary
echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  Stress Test Summary${NC}"
echo -e "${BLUE}========================================${NC}"
echo -e "${GREEN}Total Passed: $TOTAL_PASSED${NC}"
echo -e "${RED}Total Failed: $TOTAL_FAILED${NC}"
echo "Total Jobs: ${#JOBS[@]}"
echo ""
echo "Log files saved in: $LOG_DIR"

if [ $TOTAL_FAILED -eq 0 ]; then
    echo -e "${GREEN}All stress tests passed!${NC}"
    exit 0
else
    echo -e "${RED}Some stress tests failed.${NC}"
    echo ""
    echo "Failed test logs:"
    for log_file in "$LOG_DIR"/*.log; do
        if grep -q "FAILED\|✗" "$log_file"; then
            echo "  - $(basename "$log_file")"
        fi
    done
    exit 1
fi

