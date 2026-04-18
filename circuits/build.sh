#!/usr/bin/env bash
# Compile the Farewell delivery circuit to R1CS + WASM.
# See circuits/README.md for the rationale and follow-up setup.sh for
# the trusted-setup step.

set -euo pipefail

cd "$(dirname "$0")/.."

mkdir -p circuits/build

circom circuits/farewell_delivery.circom \
  --r1cs --wasm --sym \
  -o circuits/build \
  -l node_modules

echo
echo "Build complete:"
ls -lh circuits/build/farewell_delivery.r1cs \
       circuits/build/farewell_delivery_js/farewell_delivery.wasm \
  | awk '{print "  " $NF " (" $5 ")"}'
