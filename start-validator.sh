#!/bin/bash

# Default to production environment
ENV="mainnet"
NETUID=60
NETWORK="finney"
PORT=8090  # Default port

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --test|--testnet)
            ENV="testnet"
            NETUID=350
            NETWORK="test"
            shift
            ;;
        --port)
            PORT="$2"
            shift 2
            ;;
        *)
            echo "Unknown argument: $1"
            exit 1
            ;;
    esac
done

# Activate virtual environment
echo "Activating virtual environment"
source venv/bin/activate

echo "Starting validator in $ENV environment with netuid $NETUID on port $PORT"
venv/bin/python3 -m neurons.validator --netuid $NETUID \
    --subtensor.chain_endpoint $NETWORK --subtensor.network $NETWORK \
    --wallet.name validator --wallet.hotkey default \
    --axon.port $PORT --axon.external_port $PORT \
    --logging.debug
