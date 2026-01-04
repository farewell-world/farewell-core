#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   ./submit_folder.sh \
#     --folder ./messages \
#     --settings ./settings.json \
#     --rpc https://sepolia.infura.io/v3/YOUR_KEY \
#     --pk 0xYOUR_PRIVATE_KEY \
#     [--contract 0xC6a9Fc951483a70D3B6C77caE7585b595938c670]
#
# settings.json fields (example):
# {
#   "recipient": "alice@example.com",
#   "skShare": "0x3a2b... (32 hex chars -> 16 bytes -> 128-bit)",
#   "publicMessage": "Hello, blockchain!"
# }
#
# Notes:
# - skShare must be *128-bit* (16 bytes) as hex string with 0x prefix.
# - We sample S randomly per file (128-bit) and compute sk = S XOR skShare.
# - The script will submit one tx per file.

FOLDER=""
SETTINGS=""
RPC_URL=""
PRIVATE_KEY=""
CONTRACT_ADDRESS="0x859be49c6C24bC7800AB02e5A2F188c8C14f23DB" # default per your message

while [[ $# -gt 0 ]]; do
  case "$1" in
    --folder)   FOLDER="$2"; shift 2 ;;
    --settings) SETTINGS="$2"; shift 2 ;;
    --rpc)      RPC_URL="$2"; shift 2 ;;
    --pk)       PRIVATE_KEY="$2"; shift 2 ;;
    --contract) CONTRACT_ADDRESS="$2"; shift 2 ;;
    *) echo "Unknown arg: $1"; exit 1 ;;
  esac
done

if [[ -z "${FOLDER}" || -z "${SETTINGS}" || -z "${RPC_URL}" || -z "${PRIVATE_KEY}" ]]; then
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

RECIPIENT=$(jq -r '.recipient // empty' "${SETTINGS}")
SK_SHARE=$(jq -r '.skShare // empty' "${SETTINGS}")
PUBLIC_MESSAGE=$(jq -r '.publicMessage // empty' "${SETTINGS}")

if [[ -z "${RECIPIENT}" ]]; then
  echo "settings.json: 'recipient' is required (e.g., an email string)."
  exit 1
fi
if [[ -z "${SK_SHARE}" ]]; then
  echo "settings.json: 'skShare' (0x + 32 hex chars) is required."
  exit 1
fi
if [[ ! "${SK_SHARE}" =~ ^0x[0-9a-fA-F]{32}$ ]]; then
  echo "settings.json: 'skShare' must be 128-bit hex (0x + 32 hex)."
  exit 1
fi
if [[ -z "${PUBLIC_MESSAGE}" ]]; then
  echo "settings.json: 'publicMessage' is required (string; can be empty string if you prefer)."
  exit 1
fi

# Resolve script dir to locate fhe_submit.cjs
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
HELPER="${SCRIPT_DIR}/fhe_submit.cjs"
if [[ ! -f "${HELPER}" ]]; then
  echo "Missing helper: ${HELPER}"
  exit 1
fi

shopt -s nullglob
FILES=( "${FOLDER}"/* )
if (( ${#FILES[@]} == 0 )); then
  echo "No files found in ${FOLDER}"
  exit 0
fi

echo "Submitting ${#FILES[@]} file(s) to Farewell at ${CONTRACT_ADDRESS}"
echo "Recipient: ${RECIPIENT}"
echo "Public message: ${PUBLIC_MESSAGE}"
echo

for f in "${FILES[@]}"; do
  if [[ ! -f "$f" ]]; then
    continue
  fi

  # Sample a random 128-bit S (16 bytes -> 32 hex) with 0x prefix
  if command -v openssl >/dev/null 2>&1; then
    S_HEX="0x$(openssl rand -hex 16)"
  else
    # fallback via node
    S_HEX="$(node -e 'console.log("0x"+crypto.randomBytes(16).toString("hex"))')"
  fi

  echo "File: $f"
  echo "  S (random 128-bit): ${S_HEX}"
  # Node helper does: sk = S XOR skShare, AES-GCM encrypts file, FHE-encrypts inputs, sends tx
  TXJSON=$(RPC_URL="${RPC_URL}" PRIVATE_KEY="${PRIVATE_KEY}" node "${HELPER}" \
    --contract "${CONTRACT_ADDRESS}" \
    --recipient "${RECIPIENT}" \
    --skshare "${SK_SHARE}" \
    --s "${S_HEX}" \
    --public-message "${PUBLIC_MESSAGE}" \
    --file "$f")

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
done
