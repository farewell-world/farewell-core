#!/usr/bin/bash
#

export PRIVATE_KEY="REDACTED_PRIVATE_KEY"
export RPC_URL="https://sepolia.infura.io/v3/REDACTED_INFURA_KEY" 
./register.sh \
  --checkin 30 \
  --grace 7 \
  --rpc "$RPC_URL" \
  --pk "$PRIVATE_KEY" \
  --contract 0x859be49c6C24bC7800AB02e5A2F188c8C14f23DB

