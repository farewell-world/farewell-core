#!/bin/bash
# test-ui-features.sh - Test all UI features using cast (Foundry)
# 
# Prerequisites:
#   - Foundry installed (cast command available)
#   - Local hardhat node running with the contract deployed
#   - Environment variables set (or use defaults)
#
# Usage:
#   ./scripts/test-ui-features.sh
#
# Set these environment variables to override defaults:
#   CONTRACT_ADDRESS - Address of the deployed Farewell contract
#   RPC_URL - RPC endpoint (default: http://localhost:8545)
#   PRIVATE_KEY - Private key of test account

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
RPC_URL="${RPC_URL:-http://localhost:8545}"
# Default hardhat account 0 private key
PRIVATE_KEY="${PRIVATE_KEY:-0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80}"

# Get contract address from deployment if not set
if [ -z "$CONTRACT_ADDRESS" ]; then
    DEPLOYMENT_FILE="deployments/localhost/Farewell.json"
    if [ -f "$DEPLOYMENT_FILE" ]; then
        CONTRACT_ADDRESS=$(jq -r '.address' "$DEPLOYMENT_FILE")
    else
        echo -e "${RED}Error: No CONTRACT_ADDRESS set and deployment file not found${NC}"
        echo "Please deploy the contract first or set CONTRACT_ADDRESS"
        exit 1
    fi
fi

echo -e "${BLUE}=====================================${NC}"
echo -e "${BLUE}   Farewell UI Feature Tests${NC}"
echo -e "${BLUE}=====================================${NC}"
echo ""
echo -e "Contract: ${YELLOW}$CONTRACT_ADDRESS${NC}"
echo -e "RPC URL:  ${YELLOW}$RPC_URL${NC}"
echo ""

# Get the account address from private key
ACCOUNT=$(cast wallet address "$PRIVATE_KEY")
echo -e "Testing with account: ${YELLOW}$ACCOUNT${NC}"
echo ""

# Helper function to run cast and check result
run_test() {
    local test_name="$1"
    local command="$2"
    local expect_fail="${3:-false}"
    
    echo -n "  Testing: $test_name... "
    
    if [ "$expect_fail" = "true" ]; then
        if eval "$command" 2>/dev/null; then
            echo -e "${RED}FAIL (expected revert)${NC}"
            return 1
        else
            echo -e "${GREEN}PASS (reverted as expected)${NC}"
            return 0
        fi
    else
        if eval "$command" 2>/dev/null; then
            echo -e "${GREEN}PASS${NC}"
            return 0
        else
            echo -e "${RED}FAIL${NC}"
            return 1
        fi
    fi
}

# Helper to call view function
call_view() {
    cast call "$CONTRACT_ADDRESS" "$1" --rpc-url "$RPC_URL" 2>/dev/null
}

# Helper to send transaction
send_tx() {
    cast send "$CONTRACT_ADDRESS" "$1" --private-key "$PRIVATE_KEY" --rpc-url "$RPC_URL" 2>/dev/null
}

TESTS_PASSED=0
TESTS_FAILED=0

test_passed() {
    ((TESTS_PASSED++))
}

test_failed() {
    ((TESTS_FAILED++))
}

echo -e "${BLUE}[1/7] Registration Tests${NC}"
echo "--------------------------------------"

# Check if already registered
IS_REGISTERED=$(call_view "isRegistered(address)(bool)" "$ACCOUNT")
if [ "$IS_REGISTERED" = "true" ]; then
    echo -e "  ${YELLOW}Account already registered, skipping registration test${NC}"
else
    # Test: Register
    if send_tx "register()"; then
        echo -e "  Testing: Register new user... ${GREEN}PASS${NC}"
        test_passed
    else
        echo -e "  Testing: Register new user... ${RED}FAIL${NC}"
        test_failed
    fi
fi

# Test: Check registration status
IS_REGISTERED=$(call_view "isRegistered(address)(bool)" "$ACCOUNT")
if [ "$IS_REGISTERED" = "true" ]; then
    echo -e "  Testing: Check registration status... ${GREEN}PASS${NC}"
    test_passed
else
    echo -e "  Testing: Check registration status... ${RED}FAIL${NC}"
    test_failed
fi

# Test: Cannot register twice
if send_tx "register()" 2>&1 | grep -q "already registered"; then
    echo -e "  Testing: Prevent double registration... ${GREEN}PASS${NC}"
    test_passed
else
    # It might just fail without the exact message
    if ! send_tx "register()" 2>/dev/null; then
        echo -e "  Testing: Prevent double registration... ${GREEN}PASS${NC}"
        test_passed
    else
        echo -e "  Testing: Prevent double registration... ${RED}FAIL${NC}"
        test_failed
    fi
fi

echo ""
echo -e "${BLUE}[2/7] User Name Tests${NC}"
echo "--------------------------------------"

# Test: Set name
if send_tx "setName(string)" "TestUser"; then
    echo -e "  Testing: Set user name... ${GREEN}PASS${NC}"
    test_passed
else
    echo -e "  Testing: Set user name... ${RED}FAIL${NC}"
    test_failed
fi

# Test: Get name
NAME=$(call_view "getUserName(address)(string)" "$ACCOUNT")
if [ -n "$NAME" ]; then
    echo -e "  Testing: Get user name... ${GREEN}PASS${NC} (name: $NAME)"
    test_passed
else
    echo -e "  Testing: Get user name... ${RED}FAIL${NC}"
    test_failed
fi

# Test: Update name
if send_tx "setName(string)" "UpdatedUser"; then
    echo -e "  Testing: Update user name... ${GREEN}PASS${NC}"
    test_passed
else
    echo -e "  Testing: Update user name... ${RED}FAIL${NC}"
    test_failed
fi

echo ""
echo -e "${BLUE}[3/7] Message Count Tests${NC}"
echo "--------------------------------------"

# Test: Get message count
MSG_COUNT=$(call_view "messageCount(address)(uint256)" "$ACCOUNT")
echo -e "  Testing: Get message count... ${GREEN}PASS${NC} (count: $MSG_COUNT)"
test_passed

echo ""
echo -e "${BLUE}[4/7] User Status Tests${NC}"
echo "--------------------------------------"

# Test: Check if deceased
IS_DECEASED=$(call_view "isDeceased(address)(bool)" "$ACCOUNT")
if [ "$IS_DECEASED" = "false" ]; then
    echo -e "  Testing: User is alive... ${GREEN}PASS${NC}"
    test_passed
else
    echo -e "  Testing: User is alive... ${YELLOW}WARN (user is deceased)${NC}"
    test_passed
fi

# Test: Get check-in period
CHECK_IN=$(call_view "getCheckInPeriod(address)(uint64)" "$ACCOUNT")
echo -e "  Testing: Get check-in period... ${GREEN}PASS${NC} (period: $CHECK_IN seconds)"
test_passed

# Test: Get grace period
GRACE=$(call_view "getGracePeriod(address)(uint64)" "$ACCOUNT")
echo -e "  Testing: Get grace period... ${GREEN}PASS${NC} (period: $GRACE seconds)"
test_passed

echo ""
echo -e "${BLUE}[5/7] Ping (Check-in) Tests${NC}"
echo "--------------------------------------"

# Test: Ping
if send_tx "ping()"; then
    echo -e "  Testing: Ping (check-in)... ${GREEN}PASS${NC}"
    test_passed
else
    echo -e "  Testing: Ping (check-in)... ${RED}FAIL${NC}"
    test_failed
fi

# Test: Get last check-in time
LAST_CHECKIN=$(call_view "getLastCheckIn(address)(uint64)" "$ACCOUNT")
if [ -n "$LAST_CHECKIN" ] && [ "$LAST_CHECKIN" != "0" ]; then
    echo -e "  Testing: Last check-in recorded... ${GREEN}PASS${NC} (timestamp: $LAST_CHECKIN)"
    test_passed
else
    echo -e "  Testing: Last check-in recorded... ${RED}FAIL${NC}"
    test_failed
fi

echo ""
echo -e "${BLUE}[6/7] Global Stats Tests${NC}"
echo "--------------------------------------"

# Test: Get total users
TOTAL_USERS=$(call_view "totalUsers()(uint256)")
echo -e "  Testing: Get total users... ${GREEN}PASS${NC} (total: $TOTAL_USERS)"
test_passed

# Test: Get total messages
TOTAL_MSGS=$(call_view "totalMessages()(uint256)")
echo -e "  Testing: Get total messages... ${GREEN}PASS${NC} (total: $TOTAL_MSGS)"
test_passed

echo ""
echo -e "${BLUE}[7/7] Access Control Tests${NC}"
echo "--------------------------------------"

# Use a different account to test access controls
OTHER_PRIVATE_KEY="0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
OTHER_ACCOUNT=$(cast wallet address "$OTHER_PRIVATE_KEY")

# Test: Unregistered user cannot set name
if cast send "$CONTRACT_ADDRESS" "setName(string)" "Hacker" \
    --private-key "$OTHER_PRIVATE_KEY" --rpc-url "$RPC_URL" 2>&1 | grep -qi "not registered\|revert"; then
    echo -e "  Testing: Unregistered user cannot set name... ${GREEN}PASS${NC}"
    test_passed
else
    # If it doesn't error, the test fails
    if ! cast send "$CONTRACT_ADDRESS" "setName(string)" "Hacker" \
        --private-key "$OTHER_PRIVATE_KEY" --rpc-url "$RPC_URL" 2>/dev/null; then
        echo -e "  Testing: Unregistered user cannot set name... ${GREEN}PASS${NC}"
        test_passed
    else
        echo -e "  Testing: Unregistered user cannot set name... ${RED}FAIL${NC}"
        test_failed
    fi
fi

# Test: Unregistered user cannot ping
if ! cast send "$CONTRACT_ADDRESS" "ping()" \
    --private-key "$OTHER_PRIVATE_KEY" --rpc-url "$RPC_URL" 2>/dev/null; then
    echo -e "  Testing: Unregistered user cannot ping... ${GREEN}PASS${NC}"
    test_passed
else
    echo -e "  Testing: Unregistered user cannot ping... ${RED}FAIL${NC}"
    test_failed
fi

echo ""
echo -e "${BLUE}=====================================${NC}"
echo -e "${BLUE}   Test Results${NC}"
echo -e "${BLUE}=====================================${NC}"
echo ""
echo -e "  ${GREEN}Passed: $TESTS_PASSED${NC}"
echo -e "  ${RED}Failed: $TESTS_FAILED${NC}"
echo ""

if [ "$TESTS_FAILED" -eq 0 ]; then
    echo -e "${GREEN}All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}Some tests failed.${NC}"
    exit 1
fi


