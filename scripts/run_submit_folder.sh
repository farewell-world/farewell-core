#!/usr/bin/bash
#

export PRIVATE_KEY="REDACTED_PRIVATE_KEY"
export RPC_URL="https://sepolia.infura.io/v3/REDACTED_INFURA_KEY" 
./submit_folder.sh \
  --folder $1 \
  --settings ./setup.json \
  --rpc "$RPC_URL" \
  --pk "$PRIVATE_KEY" \
  --contract 0x2594985A1963c4f7904a38aEf7e7efb830774b9f

