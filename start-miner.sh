#!/bin/bash
NETUID=60 # Default to mainnet

# Start miner and save PID
python -m neurons.miner --netuid $NETUID --subtensor.chain_endpoint finney \
    --wallet.name miner --wallet.hotkey default \
    --axon.port 8092 --axon.external_port 8092 \
    --logging.debug