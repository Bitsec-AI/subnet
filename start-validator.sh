#!/bin/bash
NETUID=60 # Default to mainnet

# Activate virtual environment
echo "Activating virtual environment"
source venv/bin/activate

echo "Starting validator with netuid $NETUID"
venv/bin/python3 -m neurons.validator --netuid $NETUID --subtensor.chain_endpoint finney \
    --wallet.name validator --wallet.hotkey default \
    --axon.port 8091 --axon.external_port 8091 \
    --logging.debug
