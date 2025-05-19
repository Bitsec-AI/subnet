#!/bin/bash

# Get the absolute path of the current directory
CURRENT_DIR=$(pwd)

# Create the systemd user directory if it doesn't exist
mkdir -p ~/.config/systemd/user/

# Create logs directory
mkdir -p logs

# Function to create a service file
create_service_file() {
    local service_name=$1
    
    local use_testnet=$2
    local network_choice="mainnet"
    local testnet_flag=""
    if [ "$use_testnet" = "testnet" ]; then
        network_choice="testnet"
        testnet_flag="--testnet"
    fi

    local target_file=~/.config/systemd/user/${service_name}-${network_choice}.service
    local log_file=${CURRENT_DIR}/logs/${service_name}-${network_choice}.log
    local error_log_file=${CURRENT_DIR}/logs/${service_name}-${network_choice}-error.log
    
    # Create the service file with the correct path
    cat > "$target_file" << EOF
[Unit]
Description=Bittensor ${service_name^} Service on ${network_choice}
After=network.target

[Service]
Type=simple
WorkingDirectory=${CURRENT_DIR}
Environment=PYTHONPATH=${CURRENT_DIR}
ExecStart=/bin/bash ${CURRENT_DIR}/start-${service_name}.sh ${testnet_flag}
StandardOutput=append:${log_file}
StandardError=append:${error_log_file}
Restart=always
RestartSec=10
StartLimitInterval=0
EOF

    # Add health check for validator
    if [ "$service_name" = "validator" ]; then
        cat >> "$target_file" << EOF

# Health check
ExecStartPre=/bin/sleep 10
ExecStartPost=/bin/bash -c 'until curl -s http://localhost:\${PROXY_PORT:-8091}/healthcheck > /dev/null; do sleep 5; done'
EOF
    fi

    # Add Install section
    cat >> "$target_file" << EOF

[Install]
WantedBy=multi-user.target
EOF

    echo "Created ${service_name} service file at ${target_file}"
    echo "Logs will be written to:"
    echo "  - ${log_file}"
    echo "  - ${error_log_file}"
    
    # Reload systemd
    systemctl --user daemon-reload
    
    # Enable and start the service
    systemctl --user enable ${service_name}-${network_choice}.service
    systemctl --user start ${service_name}-${network_choice}.service
}

# Ask which service to create
echo "Which service would you like to create?"
echo "1) Validator"
echo "2) Miner"
read -p "Enter your choice (1 or 2): " service_choice

echo "Which network would you like to use?"
echo "1) Mainnet"
echo "2) Testnet"
read -p "Enter your choice (1 or 2): " network_choice

# Convert network choice to name
if [ "$network_choice" = "2" ]; then
    network_choice="testnet"
elif [ "$network_choice" = "1" ]; then
    network_choice="mainnet"
else
    echo "Invalid choice. Please run the script again and select testnet or mainnet."
    exit 1
fi

case $service_choice in
    1)
        create_service_file "validator" "$network_choice"
        ;;
    2)
        create_service_file "miner" "$network_choice"
        ;;
    *)
        echo "Invalid choice. Please run the script again and select 1 or 2."
        exit 1
        ;;
esac 