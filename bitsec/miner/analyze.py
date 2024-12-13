# Sample miner uses LLM prompts to find vulnerabilities in code
# This example uses a basic prompt template for demonstration purposes

import json
import re
import os
from bitsec.protocol import PredictionResponse
from bitsec.utils.data import SAMPLE_DIR
from bitsec.utils.llm import chat_completion
import bittensor as bt

# Templates for prompts
VULN_PROMPT_TEMPLATE = """
### Instructions:
Thoroughly scan the code line by line for potentially flawed logic or problematic code that could cause security vulnerabilities.

Ignore privacy concerns since the code is deployed on a public blockchain.

### Code:
{code}

List vulnerabilities and possible ways for potential financial loss:
"""


def analyze_code(
    code: str,
    model: str | None = None,
    temperature: float | None = None,
    max_tokens: int = 4000
) -> PredictionResponse:
    """
    Calls OpenAI API to analyze provided code for vulnerabilities.

    Args:
        code (str): The code to analyze.
        model (str, optional): The model to use for analysis.
        temperature (float, optional): Sampling temperature.
        max_tokens (int, optional): Maximum number of tokens to generate. Defaults to 4000.

    Returns:
        PredictionResponse: The analysis result from the model.
    """
    prompt = VULN_PROMPT_TEMPLATE.format(code=code)
    kwargs = {
        'prompt': prompt,
        'response_format': PredictionResponse,
        'max_tokens': max_tokens
    }
    if model is not None:
        kwargs['model'] = model
    if temperature is not None:
        kwargs['temperature'] = temperature
    
    return chat_completion(**kwargs)

def default_testnet_code(code: str) -> bool:
    """
    Checks if the provided code matches the default testnet code.

    Args:
        code (str): The code to check.

    Returns:
        bool: True if code matches default testnet code, False otherwise.
    """
    file_path = os.path.join(SAMPLE_DIR, "nft-reentrancy.sol")

    if not os.path.exists(file_path):
        return f"Error: The file '{file_path}' does not exist."
    
    try:
        with open(file_path, 'r') as file:
            file_contents = file.read()
    except IOError:
        return f"Error: Unable to read the file '{file_path}'."
    
    return file_contents == code

def code_to_vulns(code: str) -> PredictionResponse:
    """
    Main function to analyze code and format the results into a PredictionResponse.

    Args:
        code (str): The code to analyze.

    Returns:
        PredictionResponse: The structured vulnerability report.
    """

    ## short circuit testnet default code
    if default_testnet_code(code) == True:
        bt.logging.info("Default Testnet Code detected. Sending default prediction.")
        return PredictionResponse.from_tuple([True,[]])

    try:
        bt.logging.info(f"analyzing code:\n{code}")
        analysis = analyze_code(code)
        bt.logging.info(f"Analysis complete. Result:\n{analysis}")

        if type(analysis) is not PredictionResponse:
            raise ValueError("Analysis did not return a PredictionResponse object.")

        return analysis
    except Exception as e:
        bt.logging.error(f"An error occurred during analysis: {e}")
        raise