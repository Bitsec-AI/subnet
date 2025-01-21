import time
import yaml

from bitsec.utils.testWAndB import test_wandb
import wandb
import bittensor as bt

import bitsec
from bitsec.utils.config import config

# https://wandb.ai/gregschwartz/bitsec-validator

# other projects using wandb
# https://github.com/BitMind-AI/bitmind-subnet/blob/main/bitmind/validator/config.py#L27
# https://github.com/BitMind-AI/bitmind-subnet/blob/d0ac7f8593d6abbbaeb6c36412c1d49f4f11ddf4/bitmind/validator/scripts/util.py#L4
# https://github.com/search?q=repo%3ABitMind-AI%2Fbitmind-subnet%20wandb&type=code
# https://github.com/omegalabsinc/omegalabs-bittensor-subnet/blob/a20176c6c0f5f770285a92fc1fc3ea129366ef02/omega/base/validator.py#L202


def init_wandb_run() -> None:
    """Initialize a Weights & Biases run for tracking.

    Args:
        config (bt.Config): The configuration object containing wandb settings
        run_base_name (str): Base name for the run
        uid (str): The node's uid
        hotkey (str): The node's hotkey address

    Returns:
        wandb.Run | None: The initialized wandb run, or None if wandb is disabled
    """
    if config.wandb.off or config.wandb.offline:
        return None

    run_name = f'{run_base_name}-{uid}-{bitsec.__version__}'
    
    wandb_config = {
        'run_name': run_name,
        'uid': uid,
        'hotkey': hotkey,
        'version': bitsec.__version__,
        'network': 'mainnet' if config.netuid == MAINNET_UID else 'testnet'
    }

    bt.logging.info(f"Initializing W&B run for '{config.wandb.entity}/{config.wandb.project_name}'")

    try:
        return wandb.init(
            name=run_name,
            project=config.wandb.project_name,  # Use the value from config
            # entity=config.wandb.entity,         # Use the value from config
            config=wandb_config,
            dir=config.neuron.full_path,
            reinit=True,
            mode="offline" if config.wandb.offline else "online"
        )
    except wandb.UsageError as e:
        bt.logging.warning(f"Failed to initialize wandb: {e}")
        bt.logging.warning("Did you run wandb login?")
        return None