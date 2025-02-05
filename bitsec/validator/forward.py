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

import random
import bittensor as bt

from bitsec.protocol import prepare_code_synapse
from bitsec.validator.reward import get_rewards
from bitsec.utils.data import create_challenge
from bitsec.utils.uids import get_random_uids


async def forward(self):
    """
    The forward function is called by the validator every time step.
    It is responsible for querying the network and scoring the responses.

    Steps are:
    1. Sample miner UIDs
    2. Get a code sample. 50/50 chance of:
        A. SECURE (label = 0): No vulnerability injected.
        B. VULNERABLE (label = 1): Inject a vulnerability into the code.
    3. Apply random data augmentation to turn the code sample into a challenge.
    4. Prepare a Synapse
    5. Query miner axons
    6. Log results, including challenge and miner responses
    7. Compute rewards and update scores

    Args:
        self (:obj:`bittensor.neuron.Neuron`): The neuron object which contains all the necessary state for the validator.

    """
    # Initialize seen_miners set if it doesn't exist
    if not hasattr(self, 'seen_miners'):
        self.seen_miners = set()

    # get_random_uids is an example method, but you can replace it with your own.
    miner_uids = get_random_uids(self, k=self.config.neuron.sample_size)
    bt.logging.info(f"Attempting to connect to {self.config.neuron.sample_size} miners, UIDs found: {miner_uids}")

    if len(miner_uids) == 0:
        bt.logging.warning(f"❌❌❌❌❌ No miners found, skipping challenge")
        return

    vulnerable = random.random() < 0.5
    challenge, expected_response = create_challenge(vulnerable=vulnerable)
    bt.logging.info(f"created challenge")

    # The dendrite client queries the network.
    axons = [self.metagraph.axons[uid] for uid in miner_uids]
    bt.logging.info(f"⏳ Connecting to miner axons at: {[axon.ip + ':' + str(axon.port) for axon in axons]}")
    
    responses = await self.dendrite(
        # Send the query to selected miner axons in the network.
        axons=axons,
        synapse=prepare_code_synapse(code=challenge),
        deserialize=True,
    )

    # Log the results for monitoring purposes.
    bt.logging.info(f"Received {len(responses)} responses")

    # Adjust the scores based on responses from miners.
    rewards = get_rewards(expected_response=expected_response, responses=responses)

    # bt.logging.info(f"Scored responses: {rewards}")
    # Update the scores based on the rewards. You may want to define your own update_scores function for custom behavior.
    self.update_scores(rewards, miner_uids)
