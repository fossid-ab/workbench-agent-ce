#!/bin/bash
# Functional tests for import-sbom command
# Runs actual workbench-agent import-sbom commands

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

echo -e "${GREEN}=== Running Import-SBOM Functional Tests ===${NC}"
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

# Test 1: Import CycloneDX JSON
if [ -f "$FIXTURES_DIR/cyclonedx-bom.json" ]; then
    run_test "Import CycloneDX JSON" \
        workbench-agent import-sbom \
        --project-name "FunctionalTestProject" \
        --scan-name "SBOMImportCycloneDXTest" \
        --path "$FIXTURES_DIR/cyclonedx-bom.json" \
        $LOG_ARG
else
    echo -e "${YELLOW}Skipping: cyclonedx-bom.json not found${NC}"
fi

# Test 2: Import SPDX RDF
if [ -f "$FIXTURES_DIR/spdx-document.rdf" ]; then
    run_test "Import SPDX RDF" \
        workbench-agent import-sbom \
        --project-name "FunctionalTestProject" \
        --scan-name "SBOMImportSPDXTest" \
        --path "$FIXTURES_DIR/spdx-document.rdf" \
        $LOG_ARG
else
    echo -e "${YELLOW}Skipping: spdx-document.rdf not found${NC}"
fi

# Test 3: Import SBOM with results display
if [ -f "$FIXTURES_DIR/cyclonedx-bom.json" ]; then
    run_test "Import SBOM with Results Display" \
        workbench-agent import-sbom \
        --project-name "FunctionalTestProject" \
        --scan-name "SBOMImportDisplayTest" \
        --path "$FIXTURES_DIR/cyclonedx-bom.json" \
        --show-dependencies \
        --show-vulnerabilities \
        --show-policy-warnings \
        --show-components \
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

