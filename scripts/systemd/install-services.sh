#!/bin/bash

# Used to check if validator-proxy is still running
VALIDATOR_PROXY_PORT=8091

# Check if the script is run as root
if [ ${EUID} -ne 0 ]
then
	echo "This script must be run as root, so it can install the service file in /etc/systemd/system/"
	exit 1
fi

# Check if the .env file exists
if [ ! -f .env ]; then
    echo "Error: .env file not found. Required for environment variables like OPENAI_API_KEY. Please create one in the root directory e.g.  cp env.sample .env"
    exit 1
fi

# Get the absolute path of the current directory
CURRENT_DIR=$(pwd)

# Function to create a service file
create_service_file() {
    local service_name=$1
    local use_testnet=$2
    
    # Set ports based on service and network
    local port
    if [ "$service_name" = "validator" ]; then
        if [ "$use_testnet" = "testnet" ]; then
            port=8080  # Validator testnet
        else
            port=8090  # Validator mainnet
        fi
    else
        if [ "$use_testnet" = "testnet" ]; then
            port=9080  # Miner testnet
        else
            port=9090  # Miner mainnet
        fi
    fi

    local network_choice="mainnet"
    local testnet_flag=""
    if [ "$use_testnet" = "testnet" ]; then
        network_choice="testnet"
        testnet_flag="--testnet"
    fi

    local target_file=/etc/systemd/system/bitsec-${service_name}-${network_choice}.service
    local log_file=${CURRENT_DIR}/logs/${service_name}-${network_choice}.log
    local error_log_file=${CURRENT_DIR}/logs/${service_name}-${network_choice}-error.log
    
    # Check Has already been installed 
    if [ -f ${target_file} ]; then
        echo "Error: service ${target_file} already installed. Attempting to remove it..."
        systemctl stop bitsec-${service_name}-${network_choice}.service
        if [ $? -ne 0 ]; then
            echo "Error: failed to stop service ${target_file}. Please manually remove the service file."
            exit 1
        fi

        systemctl disable bitsec-${service_name}-${network_choice}.service
        if [ $? -ne 0 ]; then
            echo "Error: failed to disable service ${target_file}. Please manually remove the service file."
            exit 1
        fi

        rm ${target_file}
        echo "Successfully removed ${target_file}"
        rm ${log_file} ${error_log_file}
        echo "Successfully removed old logs ${log_file} ${error_log_file}"
    fi

    # Create logs directory
    mkdir -p logs

    # Create the service file with the correct path
    cat > "$target_file" << EOF
[Unit]
Description=Bittensor ${service_name^} Service on ${network_choice}
After=network.target

[Service]
Type=simple
WorkingDirectory=${CURRENT_DIR}
Environment=PYTHONPATH=${CURRENT_DIR}
Environment=PATH=${CURRENT_DIR}/venv/bin:${PATH}
EnvironmentFile=${CURRENT_DIR}/.env

# Add debug environment variables
Environment=PYTHONUNBUFFERED=1
Environment=DEBUG=1

# Use absolute paths and explicit bash
ExecStart=/bin/bash -c 'source ${CURRENT_DIR}/venv/bin/activate && ${CURRENT_DIR}/start-${service_name}.sh ${testnet_flag} --port ${port}'
StandardOutput=append:${log_file}
StandardError=append:${error_log_file}

# To get wallet, set user and group
User=${SUDO_USER:-$USER}
Group=${SUDO_USER:-$USER}

# Restart the service if it fails
Restart=always
RestartSec=10
StartLimitInterval=0
EOF

    # Add health check for validator
    if [ "$service_name" = "validator" ]; then
        cat >> "$target_file" << EOF

# Watchdog for continuous health monitoring
ExecStartPre=/bin/sleep 120
WatchdogSec=30
ExecStartPost=/bin/bash -c 'curl -s -f http://localhost:${port}/healthcheck > /dev/null'
ExecStartPost=/bin/bash -c 'while true; do curl -s -f http://localhost:${port}/healthcheck > /dev/null || exit 1; sleep 30; done'
TimeoutStartSec=300
TimeoutStopSec=300
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
    echo "Reloading systemd... systemctl daemon-reload"
    systemctl daemon-reload
    
    echo "Enabling service... systemctl enable bitsec-${service_name}-${network_choice}.service"
    systemctl enable bitsec-${service_name}-${network_choice}.service
    if [ $? -ne 0 ]; then  # If it returns an error, print the logs
        tail ${log_file} ${error_log_file}
        echo "May be useful: 
            systemctl status bitsec-${service_name}-${network_choice}.service
            systemctl stop bitsec-${service_name}-${network_choice}.service
            systemctl disable bitsec-${service_name}-${network_choice}.service
            tail -f ${log_file} ${error_log_file}"
        exit 1
    fi

    echo "Starting service... systemctl start bitsec-${service_name}-${network_choice}.service"
    systemctl start bitsec-${service_name}-${network_choice}.service
    if [ $? -ne 0 ]; then  # If it returns an error, print the logs
        tail ${log_file} ${error_log_file}
        echo "May be useful: 
            systemctl status bitsec-${service_name}-${network_choice}.service
            systemctl stop bitsec-${service_name}-${network_choice}.service
            systemctl disable bitsec-${service_name}-${network_choice}.service
            tail -f ${log_file} ${error_log_file}"
        exit 1
    fi

    echo "Successfully started! Current status: systemctl status bitsec-${service_name}-${network_choice}.service"
    systemctl status bitsec-${service_name}-${network_choice}.service

    echo "Reminders: 
    systemctl status bitsec-${service_name}-${network_choice}.service
    systemctl stop bitsec-${service_name}-${network_choice}.service
    systemctl disable bitsec-${service_name}-${network_choice}.service
    tail -f ${log_file} ${error_log_file}"
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