#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   ./register.sh \
#     --checkin 30 \
#     --grace 7
#     [--contract 0x859be49c6C24bC7800AB02e5A2F188c8C14f23DB]
#

CHECKIN=""
GRACE=""
RPC_URL=""
PRIVATE_KEY=""
CONTRACT_ADDRESS="0x859be49c6C24bC7800AB02e5A2F188c8C14f23DB" # default per your message

while [[ $# -gt 0 ]]; do
  case "$1" in
    --checkin)   CHECKIN="$2"; shift 2 ;;
    --grace) GRACE="$2"; shift 2 ;;
    --rpc)      RPC_URL="$2"; shift 2 ;;
    --pk)       PRIVATE_KEY="$2"; shift 2 ;;
    --contract) CONTRACT_ADDRESS="$2"; shift 2 ;;
    *) echo "Unknown arg: $1"; exit 1 ;;
  esac
done

if [[ -z "${CHECKIN}" || -z "${GRACE}" || -z "${RPC_URL}" || -z "${PRIVATE_KEY}" ]]; then
  echo "Missing required arguments. See usage in the header."
  exit 1
fi

# checks
if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required. Install jq and retry."
  exit 1
fi
if ! command -v node >/dev/null 2>&1; then
  echo "node is required. Install Node.js >= 18 and retry."
  exit 1
fi

# Resolve script dir to locate register.cjs
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
HELPER="${SCRIPT_DIR}/register.cjs"
if [[ ! -f "${HELPER}" ]]; then
  echo "Missing helper: ${HELPER}"
  exit 1
fi

echo "Submitting to Farewell at ${CONTRACT_ADDRESS}"
echo "Check-in period: ${CHECKIN} days"
echo "Grace period: ${GRACE} days"
echo

# Node helper does: sk = S XOR skShare, AES-GCM encrypts file, FHE-encrypts inputs, sends tx
TXJSON=$(RPC_URL="${RPC_URL}" PRIVATE_KEY="${PRIVATE_KEY}" node "${HELPER}" \
--contract "${CONTRACT_ADDRESS}" \
--checkin "${CHECKIN}" \
--grace "${GRACE}")

STATUS=$?
if [[ $STATUS -ne 0 ]]; then
echo "  ERROR submitting $f"
continue
fi

# pretty print
# echo "${TXJSON}" | jq -r '
#   "  txHash: \(.txHash)\n  block: \(.blockNumber // "pending")\n  gasUsed: \(.gasUsed // "?")"
# '
# echo
echo "${TXJSON}"