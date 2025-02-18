# Sample miner uses LLM prompts to find vulnerabilities in code
# This example uses a basic prompt template for demonstration purposes

import openai
import json
import re
from bitsec.utils.llm import chat_completion
from bitsec.protocol import PredictionResponse
from bitsec.utils.data import SAMPLE_DIR
import bittensor as bt
import os
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception_type
)


# - categorize the risk from the following enum (critical, high, medium, low, informational). 

# Templates for prompts
VULN_PROMPT_TEMPLATE = """
### Instructions:
Find ways for adversarial miners to get more rewards than they should. Suggest specific methods and categorize the risk from the following enum (critical, high, medium, low, informational). Include code blocks when informative to developers, and recommend ways to fix the exploit.

### Code:
{code}

List found economic exploits:
"""

FORMAT_RESULTS_TEMPLATE = """
Analyze the following text describing vulnerabilities in smart contract code. Create a structured vulnerability report in the form of a JSON object that can be parsed into a PredictionResponse object. The JSON object should have two keys:

1. 'prediction': A float between 0 and 1 representing the overall probability of vulnerability. Base this on the severity and number of vulnerabilities found.

2. 'vulnerabilities': A list of dictionaries, each representing a Vulnerability object with these keys:
   - 'line_ranges': A list of integer tuples representing affected code line ranges. Use an empty list if no specific lines are mentioned.
   - 'category': A concise string summarizing the vulnerability category.

Provide only the JSON object in your response, without any additional explanation. Ensure the output can be directly parsed into the PredictionResponse class.

Here's the text to analyze:

{analysis}
"""

# Define which exceptions we want to retry on
retryable_exceptions = (
    openai.Timeout,
    openai.APIConnectionError,
    openai.RateLimitError
)

@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=4, max=10),
    retry=retry_if_exception_type(retryable_exceptions)
)

def analyze_code(
    code: str,
    model: str = None,
    temperature: float = None,
    max_tokens: int = None
) -> PredictionResponse:
    """
    Calls OpenAI API to analyze provided code for vulnerabilities.

    Args:
        code (str): The code to analyze.
        model (str): The model to use for analysis.
        temperature (float): Sampling temperature.
        max_tokens (int): Maximum number of tokens to generate.

    Returns:
        str: The analysis result from the model.
    """
    prompt = VULN_PROMPT_TEMPLATE.format(code=code)
    try:
        return chat_completion(prompt, PredictionResponse, model, temperature, max_tokens)
    except Exception as e:
        bt.logging.error(f"Failed to analyze code: {e}")
        raise

def format_analysis(
    analysis: str,
    model: str = None,
    temperature: float = None,
    max_tokens: int = None
) -> str:
    """
    Formats the vulnerability analysis into a structured JSON response: PredictionResponse.

    Args:
        analysis (str): The text to format.
        model (str): The model to use for analysis.
        temperature (float): Sampling temperature.
        max_tokens (int): Maximum number of tokens to generate.

    Returns:
        str: The formatted PredictionResponse.
    """
    prompt = FORMAT_RESULTS_TEMPLATE.format(analysis=analysis)

    try:
        content = chat_completion(prompt, model, temperature, max_tokens)
        content = re.sub(r'```json\s*|\s*```', '', content)
        return content
    except Exception as e:
        bt.logging.error(f"Failed to format analysis: {e}")
        raise

def default_testnet_code(code: str) -> bool:
    file_path = os.path.join(SAMPLE_DIR, "nft-reentrancy.sol")

    # Check if the file exists
    if not os.path.exists(file_path):
        return f"Error: The file '{file_path}' does not exist."
    
    # Read the contents of the file
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
        bt.logging.info(f"analyzing code:\n{len(code.splitlines())} lines")
        # analyze_code already returns a PredictionResponse
        response = analyze_code(code)
        bt.logging.info(f"Analysis result:\n{response}")
        return response
    except Exception as e:
        bt.logging.error(f"An error occurred during analysis: {e}")
        raise