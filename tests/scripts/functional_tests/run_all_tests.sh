#!/bin/bash
# Run all functional tests
# Executes all test scripts (optionally in parallel)

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

# Don't exit on error - we want to run all test scripts
set +e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Check for required environment variables
if [ -z "$WORKBENCH_URL" ] || [ -z "$WORKBENCH_USER" ] || [ -z "$WORKBENCH_TOKEN" ]; then
    echo -e "${RED}ERROR: Missing required environment variables${NC}"
    echo "Please set: WORKBENCH_URL, WORKBENCH_USER, WORKBENCH_TOKEN"
    exit 1
fi

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  Running All Functional Tests${NC}"
echo -e "${BLUE}========================================${NC}"
echo "Workbench URL: $WORKBENCH_URL"
echo "Workbench User: $WORKBENCH_USER"
if [ "$PARALLEL" = true ]; then
    echo -e "${BLUE}Parallel execution: ENABLED (max $MAX_PARALLEL concurrent)${NC}"
fi
if [ "$DEBUG" = true ]; then
    echo -e "${BLUE}Debug logging: ENABLED${NC}"
fi
echo ""

# Test scripts to run
TEST_SCRIPTS=(
    "run_scan_tests.sh"
    "run_scan_git_tests.sh"
    "run_blind_scan_tests.sh"
    "run_import_da_tests.sh"
    "run_import_sbom_tests.sh"
)

# Counters
TOTAL_PASSED=0
TOTAL_FAILED=0
FAILED_SCRIPTS=()
declare -a PIDS=()

# Function to run a test script
run_test_script() {
    local script="$1"
    local script_path="$SCRIPT_DIR/$script"
    
    if [ ! -f "$script_path" ]; then
        echo -e "${YELLOW}Warning: Script not found: $script${NC}"
        return 1
    fi
    
    if [ "$PARALLEL" = true ]; then
        # Run in background
        (
            echo -e "${BLUE}[$(date +%H:%M:%S)] Starting: $script${NC}"
            DEBUG_ARG=""
            if [ "$DEBUG" = true ]; then
                DEBUG_ARG="--debug"
            fi
            bash "$script_path" $DEBUG_ARG
            local exit_code=$?
            if [ $exit_code -eq 0 ]; then
                echo -e "${GREEN}[$(date +%H:%M:%S)] ✓ $script completed successfully${NC}"
            else
                echo -e "${RED}[$(date +%H:%M:%S)] ✗ $script failed${NC}"
            fi
            exit $exit_code
        ) &
        echo $!
    else
        # Sequential execution
        echo -e "\n${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "${BLUE}Running: $script${NC}"
        echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        
        DEBUG_ARG=""
        if [ "$DEBUG" = true ]; then
            DEBUG_ARG="--debug"
        fi
        bash "$script_path" $DEBUG_ARG
        local exit_code=$?
        
        if [ $exit_code -eq 0 ]; then
            echo -e "${GREEN}✓ $script completed successfully${NC}"
        else
            echo -e "${RED}✗ $script failed${NC}"
            FAILED_SCRIPTS+=("$script")
            ((TOTAL_FAILED++))
        fi
        
        echo ""
        return $exit_code
    fi
}

# Run each test script
for script in "${TEST_SCRIPTS[@]}"; do
    if [ "$PARALLEL" = true ]; then
        # Wait if we've reached max parallel processes
        while [ ${#PIDS[@]} -ge $MAX_PARALLEL ]; do
            for pid in "${PIDS[@]}"; do
                if ! kill -0 "$pid" 2>/dev/null; then
                    # Process finished
                    wait "$pid"
                    local exit_code=$?
                    if [ $exit_code -ne 0 ]; then
                        FAILED_SCRIPTS+=("$script")
                        ((TOTAL_FAILED++))
                    else
                        ((TOTAL_PASSED++))
                    fi
                    # Remove from array
                    local idx=0
                    for p in "${PIDS[@]}"; do
                        if [ "$p" = "$pid" ]; then
                            unset PIDS[$idx]
                            PIDS=("${PIDS[@]}")
                            break
                        fi
                        ((idx++))
                    done
                    break
                fi
            done
            sleep 0.1
        done
        
        PID=$(run_test_script "$script")
        if [ -n "$PID" ]; then
            PIDS+=($PID)
        fi
    else
        run_test_script "$script"
    fi
done

# Wait for all parallel processes to complete
if [ "$PARALLEL" = true ]; then
    echo -e "\n${BLUE}Waiting for all test scripts to complete...${NC}"
    for pid in "${PIDS[@]}"; do
        wait "$pid"
        local exit_code=$?
        if [ $exit_code -ne 0 ]; then
            ((TOTAL_FAILED++))
        else
            ((TOTAL_PASSED++))
        fi
    done
fi

# Summary
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  Test Summary${NC}"
echo -e "${BLUE}========================================${NC}"

if [ ${#FAILED_SCRIPTS[@]} -eq 0 ]; then
    echo -e "${GREEN}All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}Failed scripts:${NC}"
    for script in "${FAILED_SCRIPTS[@]}"; do
        echo -e "  ${RED}✗ $script${NC}"
    done
    exit 1
fi

