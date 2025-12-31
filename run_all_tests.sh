#!/bin/bash
# run_all_tests.sh - Execute all tests in farewell-core
#
# This script runs:
# 1. Hardhat unit tests (test/*.ts)
# 2. Integration tests (test-integration.sh)
#
# Usage:
#   ./run_all_tests.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

cd "$SCRIPT_DIR"

echo -e "${BLUE}=====================================${NC}"
echo -e "${BLUE}   Farewell Core - All Tests${NC}"
echo -e "${BLUE}=====================================${NC}"
echo ""

# Track overall results
TESTS_FAILED=0

# Function to run a test suite
run_test_suite() {
    local suite_name="$1"
    local command="$2"
    
    echo -e "${BLUE}------------------------------------${NC}"
    echo -e "${BLUE}Running: $suite_name${NC}"
    echo -e "${BLUE}------------------------------------${NC}"
    echo ""
    
    if eval "$command"; then
        echo ""
        echo -e "${GREEN}✓ $suite_name passed${NC}"
        echo ""
        return 0
    else
        echo ""
        echo -e "${RED}✗ $suite_name failed${NC}"
        echo ""
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    fi
}

# 1. Run Hardhat unit tests
run_test_suite "Hardhat Unit Tests" "npm test"

# 2. Run integration tests
if [ -f "$SCRIPT_DIR/scripts/test-integration.sh" ]; then
    chmod +x "$SCRIPT_DIR/scripts/test-integration.sh"
    run_test_suite "Integration Tests" "\"$SCRIPT_DIR/scripts/test-integration.sh\""
else
    echo -e "${YELLOW}Warning: Integration test script not found, skipping${NC}"
    echo ""
fi

# Summary
echo -e "${BLUE}=====================================${NC}"
echo -e "${BLUE}   Test Summary${NC}"
echo -e "${BLUE}=====================================${NC}"
echo ""

if [ "$TESTS_FAILED" -eq 0 ]; then
    echo -e "${GREEN}All test suites passed!${NC}"
    exit 0
else
    echo -e "${RED}$TESTS_FAILED test suite(s) failed.${NC}"
    exit 1
fi

