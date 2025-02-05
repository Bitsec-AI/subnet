#!/bin/bash
NETUID=209 # Default to testnet


# Kill previous instance if running
PID_FILE="miner.pid"
if [ -f "$PID_FILE" ]; then
    OLD_PID=$(cat "$PID_FILE")
    kill -9 $OLD_PID
    sleep 1
    rm "$PID_FILE"
fi

# Activate virtual environment
source venv/bin/activate
echo "Activated virtual environment"

# Parse command-line arguments for netuid
while [[ "$#" -gt 0 ]]; do
  case $1 in
    --netuid)
      NETUID="$2"
      shift # past argument
      shift # past value
      ;;
    *)
      shift # past unrecognized argument
      ;;
  esac
done

# Start miner and save PID
python -m neurons.miner --netuid $NETUID --subtensor.chain_endpoint test \
    --wallet.name miner --wallet.hotkey default \
    --axon.port 8092 --axon.external_port 8092 \
    --logging.debug