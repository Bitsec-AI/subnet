#!/bin/bash
NETUID=60 # Default to mainnet

# Activate virtual environment
source venv/bin/activate

# Start miner and save PID
venv/bin/python3 -m neurons.miner --netuid $NETUID --subtensor.chain_endpoint finney \
    --wallet.name miner --wallet.hotkey default \
    --axon.port 8092 --axon.external_port 8092 \
    --logging.debug