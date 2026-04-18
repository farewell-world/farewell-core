#!/usr/bin/env bash
# Single-party Phase 2 trusted setup for the Farewell delivery circuit.
#
# Downloads the Hermez Phase 1 Powers of Tau file (sized to our constraint
# count), runs snarkjs groth16 setup, contributes a one-shot Phase 2
# randomness beacon, and exports the Solidity verifier and verification
# key. See circuits/README.md for the trust model (Sepolia-POC only).
#
# Must be run AFTER circuits/build.sh has produced build/farewell_delivery.r1cs.

set -euo pipefail

cd "$(dirname "$0")/.."

PTAU_SIZE=22                                   # 2^22 = 4.2M constraints, covers ~2.87M we observed
PTAU="circuits/build/powersOfTau28_hez_final_${PTAU_SIZE}.ptau"
PTAU_URL="https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_${PTAU_SIZE}.ptau"
R1CS="circuits/build/farewell_delivery.r1cs"
ZKEY_0="circuits/build/farewell_delivery_0000.zkey"
ZKEY_1="circuits/build/farewell_delivery_final.zkey"
VKEY="circuits/build/verification_key.json"

if [[ ! -f "$R1CS" ]]; then
  echo "error: $R1CS is missing. Run circuits/build.sh first." >&2
  exit 1
fi

# Powers of Tau (Phase 1). Hermez publishes these at publicly-verifiable
# Google Cloud URLs; we cache locally between runs.
if [[ ! -f "$PTAU" ]]; then
  echo "Downloading Powers of Tau Phase 1 (2^${PTAU_SIZE}, ~288 MB) ..."
  curl -fL -o "$PTAU" "$PTAU_URL"
fi

# Phase 2: per-circuit setup.
echo "Running snarkjs groth16 setup ..."
npx snarkjs groth16 setup "$R1CS" "$PTAU" "$ZKEY_0"

# Contribution. Ask the operator for a random string (beacon entropy).
: "${CONTRIBUTOR_NAME:=farewell-testnet-poc}"
: "${CONTRIBUTOR_ENTROPY:=$(openssl rand -hex 32)}"
echo "Contributing Phase 2 randomness (contributor=$CONTRIBUTOR_NAME) ..."
echo "$CONTRIBUTOR_ENTROPY" | npx snarkjs zkey contribute \
  "$ZKEY_0" "$ZKEY_1" \
  --name="$CONTRIBUTOR_NAME" \
  -v

# Export the verification key for on-chain verifier generation.
npx snarkjs zkey export verificationkey "$ZKEY_1" "$VKEY"

# Clean up the intermediate zkey — only the final one is kept.
rm -f "$ZKEY_0"

echo
echo "Trusted setup complete. Artifacts:"
ls -lh "$ZKEY_1" "$VKEY" | awk '{print "  " $NF " (" $5 ")"}'
echo
echo "Next: snarkjs zkey export solidityverifier $ZKEY_1 contracts/zkemail/FarewellGroth16Verifier.sol"
