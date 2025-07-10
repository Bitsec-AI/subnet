# The MIT License (MIT)
# Copyright © 2023 Yuma Rao
# TODO(developer): Set your name
# Copyright © 2023 <your name>

# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
# documentation files (the “Software”), to deal in the Software without restriction, including without limitation
# the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all copies or substantial portions of
# the Software.

# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
# THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
# THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
# DEALINGS IN THE SOFTWARE.

import asyncio
import time
import sys

# Bittensor
import bittensor as bt

# Logging
import wandb
from bitsec import __version__
from bitsec.base.validator import BaseValidatorNeuron
from bitsec.validator import forward
from neurons.validator_proxy import ValidatorProxy


class Validator(BaseValidatorNeuron):
    """
    Your validator neuron class. You should use this class to define your validator's behavior. In particular, you should replace the forward function with your own logic.

    This class inherits from the BaseValidatorNeuron class, which in turn inherits from BaseNeuron. The BaseNeuron class takes care of routine tasks such as setting up wallet, subtensor, metagraph, logging directory, parsing config, etc. You can override any of the methods in BaseNeuron if you need to customize the behavior.

    This class provides reasonable default behavior for a validator such as keeping a moving average of the scores of the miners and using them to set weights at the end of each epoch. Additionally, the scores are reset for new hotkeys at the end of each epoch.
    """

    def __init__(self, config=None):
        super(Validator, self).__init__(config=config)

        # Initialize wandb only if not disabled
        if not self.config.wandb.off and not self.config.wandb.offline:
            run_name = f'bitsec/validator-{self.uid}-{__version__}'
            wandb_config = {
                "uid": self.uid,
                "validator_hotkey": self.wallet.hotkey.ss58_address,
                "version": __version__,
                "type": 'validator',
                "netuid": self.config.netuid,
                "subtensor_network": self.config.network,
            }
            
            wandb.init(
                name=run_name,
                project=self.config.wandb.project_name,
                entity=self.config.wandb.entity,
                config=wandb_config,
                notes=self.config.wandb.notes,
                mode="offline" if self.config.wandb.offline else "online"
            )

        bt.logging.info("load_state()")
        self.load_state()

        self.last_responding_miner_uids = []
        self.validator_proxy = ValidatorProxy(self)

    async def forward(self):
        """
        Validator forward pass. Consists of:
        - Generating the query
        - Querying the miners
        - Getting the responses
        - Rewarding the miners
        - Updating the scores
        """
        # TODO(developer): Rewrite this function based on your protocol definition.
        return await forward(self)

    def check_for_thread_exception(self):
        if self.thread_exception is not None:
            bt.logging.error(self.thread_exception)

            self.dendrite.close_session()

            wandb.finish()

            if self.validator_proxy:
                asyncio.run(self.validator_proxy.stop_server())

            sys.exit(1)

# The main function parses the configuration and runs the validator.
if __name__ == "__main__":
    with Validator() as validator:
        while True:
            validator.check_for_thread_exception()
            bt.logging.info(f"uid {validator.uid} tick")
            time.sleep(60)
