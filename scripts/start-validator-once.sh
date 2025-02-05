#!/bin/bash
NETUID=209 # Default to testnet

echo "Starting validator in ./scripts/start-validator-once.sh..."

# Kill previous instance if running
PID_FILE="../validator.pid"
if [ -f "$PID_FILE" ]; then
    OLD_PID=$(cat "$PID_FILE")
    kill -9 $OLD_PID
    sleep 1
    rm "$PID_FILE"
fi

echo "Activating virtual environment"
source venv/bin/activate


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


echo "Starting validator with netuid $NETUID"
python -m neurons.validator --netuid $NETUID --subtensor.chain_endpoint test \
    --wallet.name validator --wallet.hotkey default \
    --axon.port 8091 --axon.external_port 8091 \
    --logging.debug
