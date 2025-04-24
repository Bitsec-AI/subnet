# The MIT License (MIT)
# Copyright © 2021 Yuma Rao
# Copyright © 2023 Opentensor Foundation
# Copyright © 2023 Opentensor Technologies Inc

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

from bitsec.protocol import PredictionResponse, IdentityAttestation, StakeWeightLimit
import bittensor as bt
from typing import List, Union, Any, Dict
from bittensor.subnets import SubnetsAPI
from bitsec.protocol import Vulnerability
from bitsec.validator.make_report import format_vulnerability_to_report


# CodeAPI allows validators to query miners using real code. This gateway allows external client services
class CodeAPI(SubnetsAPI):
    def __init__(self, wallet: "bt.wallet"):
        super().__init__(wallet)
        self.netuid = 204
        self.name = "bitsec"
        self.identity_attestations = {}
        self.max_stake_weight = 1000.0

    def process_responses(
        self, responses: List[Union["bt.Synapse", Any]]
    ) -> List[PredictionResponse]:
        outputs = []
        for response in responses:
            if response.dendrite.status_code != 200:
                continue
            return outputs.append(PredictionResponse.from_tuple(response))
        return outputs

    def aggregate_responses(self, responses: List[PredictionResponse]) -> List[Vulnerability]:
        """
        Aggregates multiple miner responses into a single list of vulnerabilities.

        Args:
            responses (List[PredictionResponse]): List of responses from miners.

        Returns:
            List[Vulnerability]: Aggregated list of vulnerabilities.
        """
        aggregated_vulnerabilities = []
        for response in responses:
            aggregated_vulnerabilities.extend(response.vulnerabilities)
        return aggregated_vulnerabilities

    def generate_report(self, aggregated_vulnerabilities: List[Vulnerability]) -> str:
        """
        Generates a report from aggregated vulnerabilities.

        Args:
            aggregated_vulnerabilities (List[Vulnerability]): Aggregated list of vulnerabilities.

        Returns:
            str: Generated report in markdown format.
        """
        return format_vulnerability_to_report(aggregated_vulnerabilities)

    def add_identity_attestation(self, node_id: str, identity_proof: str):
        """
        Adds an identity attestation for a node.

        Args:
            node_id (str): The unique identifier of the node.
            identity_proof (str): Proof of identity, such as a DID or KYC verification.
        """
        self.identity_attestations[node_id] = IdentityAttestation(node_id=node_id, identity_proof=identity_proof)

    def set_max_stake_weight(self, node_id: str, max_stake_weight: float):
        """
        Sets the maximum stake weight for a node.

        Args:
            node_id (str): The unique identifier of the node.
            max_stake_weight (float): The maximum stake weight allowed for the node.
        """
        self.max_stake_weight = StakeWeightLimit(node_id=node_id, max_stake_weight=max_stake_weight)
