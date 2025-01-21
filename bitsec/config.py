"""
Configuration constants for the bitsec project.

Update these values when setting up your own subnet.
"""
from pathlib import Path
from typing import Dict, Any

# Network constants
MAINNET_UID: int = None
TESTNET_UID: int = 209

# Weights & Biases configuration
WANDB_ENTITY: str = "bitsec"
MAINNET_WANDB_PROJECT: str = "bitsec-mainnet"
TESTNET_WANDB_PROJECT: str = "bitsec-testnet"

# Cache directories
BITSEC_CACHE_DIR: Path = Path.home() / '.cache' / 'bitsec'
BITSEC_CACHE_DIR.mkdir(parents=True, exist_ok=True)

# Default ports
DEFAULT_AXON_PORT: int = 8091
DEFAULT_EXTERNAL_PORT: int = 8091

# Validator specific constants
VALIDATOR_CONFIG: Dict[str, Any] = {
    "timeout": 10.0,
    "num_concurrent_forwards": 1,
    "sample_size": 50,
    "moving_average_alpha": 0.1,
    "vpermit_tao_limit": 4096
}

# Miner specific constants
MINER_CONFIG: Dict[str, Any] = {
    "blacklist": {
        "force_validator_permit": False,
        "allow_non_registered": False
    }
} 