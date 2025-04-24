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

import json
import bittensor as bt
import pydantic
from typing import List, Optional, Tuple, Union
from bitsec.base.vulnerability_category import VulnerabilityCategory
from bitsec.base.vulnerability_severity import VulnerabilitySeverity

def prepare_code_synapse(code: str):
    """
    Prepares code for use with CodeSynapse object.

    Args:
        code (str): The input to be prepared.

    Returns:
        CodeSynapse: An instance of CodeSynapse containing the encoded code and a default prediction value.
    """
    vulnerability_categories = VulnerabilityCategory.list()
    return CodeSynapse(code=code, acceptable_vulnerability_categories=vulnerability_categories)

# This is the protocol for the dummy miner and validator.
# It is a simple request-response protocol where the validator sends a request
# to the miner, and the miner responds with a dummy response.

# ---- miner ----
# Example usage:
#   def miner_forward( synapse: CodeSynapse ) -> CodeSynapse:
#       ...
#       synapse.predictions = vulnerability_detection_model_outputs
#       return synapse
#   axon = bt.axon().attach( miner_forward ).serve(netuid=...).start()

# ---- validator ---
# Example usage:
#   dendrite = bt.dendrite()
#   codes = [code_1, ..., code_n]
#   predictions = dendrite.query( CodeSynapse( codes = codes ) )
#   assert len(predictions) == len(codes)


# Vulnerability is a lines_of_code_range in the codebase with description
class LineRange(pydantic.BaseModel):
    """Represents a range of lines in code."""
    start: int = pydantic.Field(description="Start line of the range")
    end: int = pydantic.Field(description="End line of the range")

    model_config = { "populate_by_name": True }

    # get field attrs from model
    def __getattr__(self, name):
        try:
            return self.model_dump()[name]
        except KeyError:
            raise AttributeError(f"'{self.__class__.__name__}' has no attribute '{name}'")

    def __dict__(self):
        """Make JSON serializable by default."""
        return self.model_dump()

class Vulnerability(pydantic.BaseModel):
    """Represents a security vulnerability found in code."""
    title: str = pydantic.Field(
        description="A short title for the vulnerability."
    )
    severity: VulnerabilitySeverity = pydantic.Field(
        description="The severity of the vulnerability."
    )
    line_ranges: Optional[List[LineRange]] = pydantic.Field(
        description="An array of lines of code ranges where the vulnerability is located. Optional, but strongly recommended. Consecutive lines should be a single range, eg lines 1-3 should NOT be [{start: 1, end: 1}, {start: 2, end: 2}, {start: 3, end: 3}] INSTEAD SHOULD BE [{start: 1, end: 3}].",
        default=None
    )
    category: VulnerabilityCategory = pydantic.Field(
        description="The category of vulnerability detected."
    )
    description: str = pydantic.Field(
        description="Detailed description of the vulnerability, including financial impact and why this is a vulnerability."
    )
    vulnerable_code: str = pydantic.Field(
        description="Code snippet that contains the vulnerability"
    )
    code_to_exploit: str = pydantic.Field(
        description="Code snippet that exploits the vulnerability."
    )
    rewritten_code_to_fix_vulnerability: str = pydantic.Field(
        description="Code snippet that prevents the vulnerability from being exploited."
    )
    
    model_config = { "populate_by_name": True }

    @classmethod
    def sort_vulnerabilities(cls, vulnerabilities: List['Vulnerability']) -> List['Vulnerability']:
        """Sorts the list of vulnerabilities by their severity, then intelligently after that."""
        return sorted(
            vulnerabilities,
            key=lambda v: (
                # Sort severity highest first eg 99_CRITICAL, 85_HIGH...
                -1 * v.severity.numeric_value(),
                
                # Then sort by line range start, since that will decrease scrolling while verifying.
                # And if no line range it'll be harder to verify and fix, so put at end.
                v.line_ranges[0]["start"] if v.line_ranges and len(v.line_ranges) > 0 and v.line_ranges[0]["start"] is not None else float('inf'),

                # Sorting by category and description is silly, but guarantees sort order.
                v.category.lower(),
                v.description.lower(),
            )
        )


    # get field attrs from model
    def __getattr__(self, name):
        try:
            return self.model_dump()[name]
        except KeyError:
            raise AttributeError(f"'{self.__class__.__name__}' has no attribute '{name}'")

    def __dict__(self):
        """Make JSON serializable by default."""
        return self.model_dump()

class VulnerabilityByMiner(Vulnerability):
    """
    Represents a security vulnerability found in code by a specific miner.
    Extends the base Vulnerability class with miner-specific information.
    """
    miner_id: str = pydantic.Field(
        description="The unique identifier of the miner that discovered this vulnerability"
    )

    model_config = { "populate_by_name": True }

    # get field attrs from model
    def __getattr__(self, name):
        try:
            return self.model_dump()[name]
        except KeyError:
            raise AttributeError(f"'{self.__class__.__name__}' has no attribute '{name}'")

    @classmethod
    def from_json(cls, json_data: Union[str, str, dict]) -> 'VulnerabilityByMiner':
        """Create a VulnerabilityByMiner from JSON data.
        
        Args:
            json_data: Either a JSON string or a dictionary containing the response data
            
        Returns:
            VulnerabilityByMiner: A new instance of VulnerabilityByMiner
        """
        if isinstance(json_data, str):
            json_data = json.loads(json_data)
        return cls(**json_data)

    @classmethod
    def from_tuple(cls, data: Tuple[str, Vulnerability]) -> 'VulnerabilityByMiner':
        """Create a VulnerabilityByMiner from a tuple of (miner_id, Vulnerability).
        
        Args:
            data: Tuple containing (miner_id, Vulnerability instance)
            
        Returns:
            VulnerabilityByMiner: A new instance with all Vulnerability fields plus miner_id
        """
        miner_id, vuln = data
        # Create a dict with all Vulnerability fields plus miner_id
        vuln_dict = vuln.model_dump()
        vuln_dict['miner_id'] = miner_id
        return cls.model_validate(vuln_dict)

    def to_tuple(self) -> Tuple[str, Vulnerability]:
        """Convert to tuple of (miner_id, Vulnerability).
        
        Returns:
            Tuple[str, Vulnerability]: The miner_id and a Vulnerability instance
        """
        # Create base Vulnerability instance from all fields except miner_id
        vuln_dict = self.model_dump(exclude={'miner_id'})
        return (self.miner_id, Vulnerability.model_validate(vuln_dict))

# PredictionResponse is the response from the Miner
class PredictionResponse(pydantic.BaseModel):
    """
    PredictionResponse contains the predicted vulnerability status and the list of vulnerabilities.
    To turn into JSON, use the model_dump_json() instance method.
    """
    prediction: bool = pydantic.Field(
        description="Vulnerabilities were found"
    )
    vulnerabilities: List[Vulnerability] = pydantic.Field(
        description="List of detected vulnerabilities"
    )

    model_config = { "populate_by_name": True }

    def sort_vulnerabilities(self):
        """Sorts the list of vulnerabilities by their severity, then intelligently after that. Updates the vulnerabilities list in place.
        """
        self.vulnerabilities = Vulnerability.sort_vulnerabilities(self.vulnerabilities)

    # get field attrs from model
    def __getattr__(self, name):
        try:
            return self.model_dump()[name]
        except KeyError:
            raise AttributeError(f"'{self.__class__.__name__}' has no attribute '{name}'")

    @classmethod
    def from_json(cls, json_data: Union[str, dict]) -> 'PredictionResponse':
        """Create a PredictionResponse from JSON data.
        
        Args:
            json_data: Either a JSON string or a dictionary containing the response data
            
        Returns:
            PredictionResponse: A new instance of PredictionResponse
        """
        if isinstance(json_data, str):
            json_data = json.loads(json_data)
        return cls(**json_data)

    @classmethod
    def from_tuple(cls, data: Tuple[bool, List[Vulnerability]]) -> 'PredictionResponse':
        return cls(prediction=data[0], vulnerabilities=data[1])

    def to_tuple(self) -> Tuple[bool, List[Vulnerability]]:
        return (self.prediction, self.vulnerabilities)

class CodeSynapse(bt.Synapse):
    """
    This protocol helps in handling code/prediction request and response communication between
    the miner and the validator.

    Attributes:
    - code: a str of code
    - prediction: a bool indicating the probabilty that the code has a critical / severe vulnerability.
        True is considered generated/modified, False is considered real.
    """

    # Required request input, filled by sending dendrite caller.
    code: str

    acceptable_vulnerability_categories: List[VulnerabilityCategory] = pydantic.Field(
        description="List of acceptable vulnerability categories, if empty then any categories are acceptable"
    )

    # Optional request output, filled by receiving axon.
    response: PredictionResponse = pydantic.Field(
        default_factory=lambda: PredictionResponse(prediction=False, vulnerabilities=[]),
        title="Miner Prediction",
        description="Prediction response containing probability and vulnerabilities",
        frozen=False
    )

    def deserialize(self) -> PredictionResponse:
        """
        Deserialize the output. This method retrieves the response from
        the miner, deserializes it and returns it as the output of the dendrite.query() call.

        Returns:
        - PredictionResponse: The deserialized miner prediction and vulnerabilities
        """
        return self.response

class IdentityAttestation(pydantic.BaseModel):
    """
    Represents an identity attestation for a node.
    """
    node_id: str = pydantic.Field(
        description="The unique identifier of the node"
    )
    identity_proof: str = pydantic.Field(
        description="Proof of identity, such as a DID or KYC verification"
    )

    model_config = { "populate_by_name": True }

    # get field attrs from model
    def __getattr__(self, name):
        try:
            return self.model_dump()[name]
        except KeyError:
            raise AttributeError(f"'{self.__class__.__name__}' has no attribute '{name}'")

    def __dict__(self):
        """Make JSON serializable by default."""
        return self.model_dump()

class StakeWeightLimit(pydantic.BaseModel):
    """
    Represents the maximum stake weight limit for a node.
    """
    node_id: str = pydantic.Field(
        description="The unique identifier of the node"
    )
    max_stake_weight: float = pydantic.Field(
        description="The maximum stake weight allowed for the node"
    )

    model_config = { "populate_by_name": True }

    # get field attrs from model
    def __getattr__(self, name):
        try:
            return self.model_dump()[name]
        except KeyError:
            raise AttributeError(f"'{self.__class__.__name__}' has no attribute '{name}'")

    def __dict__(self):
        """Make JSON serializable by default."""
        return self.model_dump()
