#!/bin/bash
NETUID=60 # Default to mainnet

echo "Starting validator with netuid $NETUID"
python -m neurons.validator --netuid $NETUID --subtensor.chain_endpoint finney \
    --wallet.name validator --wallet.hotkey default \
    --axon.port 8091 --axon.external_port 8091 \
    --logging.debug
