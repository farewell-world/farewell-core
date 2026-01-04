#!/bin/bash
# test-integration.sh - Run integration tests with a local hardhat node
#
# This script:
# 1. Starts a local hardhat node
# 2. Deploys the contract
# 3. Runs the UI feature tests
# 4. Cleans up
#
# Usage:
#   ./scripts/test-integration.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

cd "$PROJECT_DIR"

echo -e "${BLUE}=====================================${NC}"
echo -e "${BLUE}   Farewell Integration Tests${NC}"
echo -e "${BLUE}=====================================${NC}"
echo ""

# Check if hardhat node is already running
if curl -s http://localhost:8545 > /dev/null 2>&1; then
    echo -e "${YELLOW}Hardhat node already running on port 8545${NC}"
    NODE_ALREADY_RUNNING=true
else
    echo -e "${BLUE}Starting hardhat node...${NC}"
    npx hardhat node > /tmp/hardhat-node.log 2>&1 &
    HARDHAT_PID=$!
    NODE_ALREADY_RUNNING=false
    
    # Wait for node to start
    echo -n "Waiting for node to start"
    for i in {1..30}; do
        if curl -s http://localhost:8545 > /dev/null 2>&1; then
            echo -e " ${GREEN}OK${NC}"
            break
        fi
        echo -n "."
        sleep 1
    done
    
    if ! curl -s http://localhost:8545 > /dev/null 2>&1; then
        echo -e " ${RED}FAILED${NC}"
        echo "Could not start hardhat node. Check /tmp/hardhat-node.log"
        exit 1
    fi
fi

# Cleanup function
cleanup() {
    if [ "$NODE_ALREADY_RUNNING" = "false" ] && [ -n "$HARDHAT_PID" ]; then
        echo -e "${BLUE}Stopping hardhat node...${NC}"
        kill $HARDHAT_PID 2>/dev/null || true
    fi
}
trap cleanup EXIT

# Deploy contract
echo -e "${BLUE}Deploying contract...${NC}"
npx hardhat deploy --network localhost

# Run the tests
echo ""
echo -e "${BLUE}Running UI feature tests...${NC}"
echo ""

chmod +x "$SCRIPT_DIR/test-ui-features.sh"
"$SCRIPT_DIR/test-ui-features.sh"


