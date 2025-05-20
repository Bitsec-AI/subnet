#!/bin/bash

# Default to production environment
ENV="mainnet"
NETUID=60
NETWORK="finney"

if [ "$1" == "--test" -o "$1" == "--testnet" ]; then
    ENV="testnet"
    NETUID=350
    NETWORK="test"
fi

# Activate virtual environment
echo "Activating virtual environment"
source venv/bin/activate

echo "Starting validator in $ENV environment with netuid $NETUID"
venv/bin/python3 -m neurons.validator --netuid $NETUID \
    --subtensor.chain_endpoint $NETWORK --subtensor.network $NETWORK \
    --wallet.name validator --wallet.hotkey default \
    --axon.port 8091 --axon.external_port 8091 \
    --logging.debug
