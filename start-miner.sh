#!/bin/bash

# Default to production environment
ENV="mainnet"
NETUID=60
NETWORK="finney"

if [ "$1" == "--test" ]; then
    ENV="testnet"
    NETUID=350
    NETWORK="test"
fi

echo "Starting miner in $ENV environment with netuid $NETUID"
python -m neurons.miner --netuid $NETUID \
    --subtensor.chain_endpoint $NETWORK --subtensor.network $NETWORK \
    --wallet.name miner --wallet.hotkey default \
    --axon.port 8092 --axon.external_port 8092 \
    --logging.debug