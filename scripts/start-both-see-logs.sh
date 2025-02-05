#!/bin/bash

# Start the processes
# ./start-validator.sh > validator.log 2>&1 & 
./../start-validator.sh & 
PID1=$!
# ./start-miner.sh > miner.log 2>&1 &
./../start-miner.sh &
PID2=$!

# Set up trap to kill processes when user presses Ctrl+C
trap 'kill $PID1 $PID2; echo "All processes stopped"; exit' INT TERM EXIT

# Show both logs
if ! command -v tmux &> /dev/null; then
    # If tmux is not installed, show logs in tail
    tail -f validator.log miner.log
else
    tmux new-session -d -s bitsec 'tmux set -g mouse on; tail -f validator.log'
    tmux split-window -v 'tail -f miner.log'
    tmux -2 attach-session -t bitsec
fi