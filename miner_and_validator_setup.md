# Step 1: Build/Install

This section is for first-time setup and installations.

```
btcli wallet new_coldkey --wallet.name owner --no-use-password --quiet
btcli wallet new_coldkey --wallet.name miner --no-use-password --quiet
btcli wallet new_hotkey --wallet.name miner --wallet.hotkey default --quiet
btcli wallet new_coldkey --wallet.name validator --no-use-password --quiet
btcli wallet new_hotkey --wallet.name validator --wallet.hotkey default --quiet
touch .wallets_setup
btcli wallet list
```

# Step 2: Send tokens to all the wallets

Go to Bittensor Discord, and submit a Request for Testnet TAO
Send TAO to your tokens.

# Step 3: Register to subnet

Once all wallets have tokens, register the miner and validator to the subnet.

## For TESTNET:

```
btcli subnet register --wallet.name miner --netuid 350 --wallet.hotkey default --subtensor.chain_endpoint test
btcli subnet register --wallet.name validator --netuid 350 --wallet.hotkey default --subtensor.chain_endpoint test
```

## For MAINNET:

```
btcli subnet register --wallet.name miner --netuid 60 --wallet.hotkey default --subtensor.chain_endpoint finney
btcli subnet register --wallet.name validator --netuid 60 --wallet.hotkey default --subtensor.chain_endpoint finney
```

# Step 4:

## Miner

If you are using testnet, remember to pass the **testnet** netuid to the miner: `./start-miner.sh --testnet`.

If you get errors in any environment, try the following:

```
brew install pyenv-virtualenv
pyenv virtualenv 3.11.9 bt-venv
pyenv activate bt-venv
pip install -r requirements.txt
./start_miner.sh
```

## Validator

To start the validator, run `./start-validator.sh --testnet`.

### Future:

When generating synthetic vulnerabilities, you will eventually need to make sure the code is valid Solidity. We plan to use Foundry to compile the code. To install it:

1. If on a Mac, you may need to run `brew install libusb` first.
2. `curl -L https://foundry.paradigm.xyz | bash`
3. Then install by running: `foundryup`

## Optional: Run as systemd services

Run `bash scripts/systemd/install-services.sh`.

It will: 
1. ask you if you want to install the miner or validator service
2. if it should use the mainnet or testnet 
3. create the service file in `/etc/systemd/system/` 
4. enable it 
5. start it
6. tell you where the logs are

## Check status
- `systemctl status bitsec-validator-mainnet.service`
- `systemctl status validator-testnet.service`
- `systemctl status bitsec-miner-mainnet.service`
- `systemctl status bitsec-miner-testnet.service`

## Stop services
- `systemctl stop bitsec-validator-mainnet.service`
- `systemctl stop bitsec-validator-testnet.service`
- `systemctl stop bitsec-miner-mainnet.service`
- `systemctl stop bitsec-miner-testnet.service`

## Manually start services
- `systemctl start bitsec-validator-mainnet.service`
- `systemctl start bitsec-validator-testnet.service`
- `systemctl start bitsec-miner-mainnet.service`
- `systemctl start bitsec-miner-testnet.service`

## Check logs
- `tail -f logs/bitsec-validator-mainnet.log`
- `tail -f logs/bitsec-validator-testnet.log`
- `tail -f logs/bitsec-miner-mainnet.log`
- `tail -f logs/bitsec-miner-testnet.log`



