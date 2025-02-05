# Utility function for interacting with LLMs
import bittensor as bt
from typing import Type, Optional, TypeVar, Union
import openai
from openai import OpenAI
import os
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception_type
)
from rich.console import Console
console = Console()

# Define generic type T
T = TypeVar('T')

# OpenAI API key config
if not os.getenv("OPENAI_API_KEY"):
    bt.logging.error("OpenAI API key is not set. Please set the 'OPENAI_API_KEY' environment variable.")
    raise ValueError("OpenAI API key is not set.")

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

# Default parameters
DEFAULT_MODEL = "gpt-4o-mini-2024-07-18"
DEFAULT_TEMPERATURE = 0.1
DEFAULT_MAX_TOKENS = 1000

# At the top with other globals
TOTAL_SPEND_CENTS = 0.0

COST_USD_PER_MILLION_TOKENS = {
    "gpt-4o": {
        "input": 2.50,
        "input_cached": 1.25,
        "output": 10.00
    },
    "gpt-4o-mini": {
        "input": 0.150,
        "input_cached": 0.075,
        "output": 0.600
    },
    "o1-preview": {
        "input": 15.00,
        "input_cached": 7.50,
        "output": 60.00
    },
    "o1-mini": {
        "input": 3.00,
        "input_cached": 1.50,
        "output": 12.00
    },
    "testing": {
        "input": 0.00,
        "input_cached": 0.00,
        "output": 0.00
    }
}

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
def chat_completion(
    prompt: str,
    response_format: Optional[Type[T]] = None,
    model: str = None,
    temperature: float = None,
    max_tokens: int = None
) -> Union[str, T]:
    """
    Calls OpenAI API to analyze provided prompt.

    Args:
        prompt (str): The prompt to analyze.
        response_format (Optional[Type[T]]): The expected response format.
        model (str): The model to use for analysis. Optional.
        temperature (float): Sampling temperature. Optional.
        max_tokens (int): Maximum number of tokens to generate. Optional.

    Returns:
        Union[str, T]: The analysis result from the model, either as string or specified object.
    """
    # Set default values if None
    model = model or DEFAULT_MODEL
    temperature = temperature or DEFAULT_TEMPERATURE
    max_tokens = max_tokens or DEFAULT_MAX_TOKENS

    parameters = {
        "messages": [{"role": "system", "content": prompt}],
        "model": model,
        "temperature": temperature,
        "max_tokens": max_tokens
    }
    if response_format is not None:
        parameters["response_format"] = response_format

    try:
        response = client.beta.chat.completions.parse(**parameters)
        try:
            if bt.logging.current_state_value in ["Debug", "Trace"]:
                token_fee, token_cost_description = get_token_cost(response)
                if token_fee > 0:
                    global TOTAL_SPEND_CENTS
                    TOTAL_SPEND_CENTS += token_fee
                    console.print(f"💰 LLM: [green]¢{token_fee:.3f}[/green] -- [light_green]{token_cost_description}[/light_green] -- Total: [bold green]¢{TOTAL_SPEND_CENTS:.3f}[/bold green]")
        except Exception as e:
            bt.logging.info(f"Error getting token cost: {e}")


        # Guard against empty or invalid responses
        if response is None or response.choices is None or not hasattr(response, "choices") or len(response.choices) == 0 or not hasattr(response.choices[0], "message") or response.choices[0].message is None:
            raise ValueError("AI returned empty or invalid response.", response)
        
        # Shorter access to message, more readable
        message = response.choices[0].message

        # Make debugging easier
        # if hasattr(message, "content"):
        #     print(f"\033[90mLLM Response: {message.content}\033[0m")

        if hasattr(message, "refusal") and message.refusal:
            raise ValueError(f"Prompt was refused: {message.refusal}")
        
        if response_format:
            if hasattr(message, "parsed") and message.parsed is not None:
                if isinstance(message.parsed, response_format):
                    return message.parsed
                else:
                    bt.logging.error(f"Response wasn't format {response_format}, was {type(message.parsed)}, content: {message.content}")
                    raise ValueError(f"Response format {response_format} not found in response.")
            else:
                raise ValueError(f"Response didn't have parsed attribute, content: {message.content}")
        
        if hasattr(message, "content"):
            return message.content
        
        # Else, raise an error
        raise ValueError("Response didn't have content attribute.", message)
    
    except Exception as e:
        # Error will be logged by calling function
        raise

def get_token_cost(response: openai.types.completion.Completion) -> tuple[float, str]:
    """
    Calculate the cost of tokens used in an OpenAI API response in cents.

    Args:
        response (openai.types.completion.Completion): The API response object.

    Returns:
        tuple[float, str]: A tuple containing:
            - float: Total cost in cents
            - str: Detailed description of the cost breakdown
    """
    if response.usage is None or response.usage.completion_tokens is None or response.usage.prompt_tokens is None or response.usage.total_tokens is None:
        return 0.0, "No usage data"

    description = ""
    fee = 0

    # Handle empty or invalid model name
    if not response.model or not isinstance(response.model, str):
        raise ValueError("Model name invalid")

    # Remove version number from model name, e.g. o1-mini-2024-09-12
    model = "-".join(filter(lambda x: not x.isdigit(), response.model.split("-")))
    model = model.strip()

    # Make sure model is in the cost dictionary
    if model not in COST_USD_PER_MILLION_TOKENS:
        raise ValueError(f"Model {model} not found in cost dictionary: {COST_USD_PER_MILLION_TOKENS}")

    # Get the costs for this model
    model_costs = COST_USD_PER_MILLION_TOKENS[model]
    # Convert dollar costs to cents
    costs = {k: v * 100 for k, v in model_costs.items()}

    cached = response.usage.prompt_tokens_details.cached_tokens
    
    input_fee = costs["input"] * (response.usage.prompt_tokens - cached) / 1_000_000
    description += f"Input: ¢{input_fee:.3f}"

    if cached > 0:
        input_cached_fee = costs["input_cached"] * cached / 1_000_000
        fee += input_fee + input_cached_fee
        description += f" (cached: ¢{input_cached_fee:.3f})"

    output_fee = costs["output"] * response.usage.completion_tokens / 1_000_000
    fee += output_fee
    description += f", Output: ¢{output_fee:.3f}"

    reasoning = response.usage.completion_tokens_details.reasoning_tokens
    accepted_prediction = response.usage.completion_tokens_details.accepted_prediction_tokens
    rejected_prediction = response.usage.completion_tokens_details.rejected_prediction_tokens

    if reasoning > 0 or accepted_prediction > 0 or rejected_prediction > 0:
        reasoning_fee = costs["output"] * reasoning / 1_000_000
        accepted_prediction_fee = costs["output"] * accepted_prediction / 1_000_000
        rejected_prediction_fee = costs["output"] * rejected_prediction / 1_000_000

        fee += reasoning_fee + accepted_prediction_fee + rejected_prediction_fee
        description += f". Reasoning: ¢{reasoning_fee:.3f}, Prediction: accepted ¢{accepted_prediction_fee:.3f}, rejected ¢{rejected_prediction_fee:.3f}"

    return fee, description
