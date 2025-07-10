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
DEFAULT_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o")
DEFAULT_TEMPERATURE = 0.1
DEFAULT_MAX_TOKENS = 10000

# At the top with other globals
TOTAL_SPEND_CENTS = 0.0
TOTAL_SPEND_DESCRIPTION = []

# https://openai.com/api/pricing/
SETTINGS_AND_COST_USD_PER_MILLION_TOKENS = {
    "gpt-4o": {
        "input": 2.50,
        "input_cached": 1.25,
        "output": 10.00,
        "max_tokens": 16384
    },
    "gpt-4o-mini": {
        "input": 0.150,
        "input_cached": 0.075,
        "output": 0.600,
        "max_tokens": 16384
    },
    "o1": {
        "input": 15.00,
        "input_cached": 7.50,
        "output": 60.00,
        "no_system_prompt": True,
        "no_temperature": True,
        "max_tokens_key": "max_completion_tokens",
        "max_tokens": 100000
    },
    "o1-mini": {
        "input": 1.10,
        "input_cached": 0.55,
        "output": 4.40,
        "no_system_prompt": True,
        "no_structured_output": True,
        "no_temperature": True,
        "max_tokens_key": "max_completion_tokens",
        "max_tokens": 65536
    },
    "o3-mini": {
        "input": 1.10,
        "input_cached": 0.55,
        "output": 4.40,
        "no_system_prompt": True,
        "max_tokens_key": "max_completion_tokens",
        "max_tokens": 100000
    },
    "gpt-4.5-preview": {
        "input": 75,
        "input_cached": 37.5,
        "output": 150,
        "max_tokens": 16384
    },
    "testing": {
        "input": 1,
        "input_cached": 1,
        "output": 1,
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
        response_format (Optional[Type[T]]): The expected response format. Optional. If not supported by model, response will be returned as string.
        model (str): The model to use for analysis. Optional.
        temperature (float): Sampling temperature. Optional. Temperature may not be supported by model, in which case it will be ignored.
        max_tokens (int): Maximum number of tokens to generate. Optional. Passing max as float("inf") means use model's max from SETTINGS_AND_COST_USD_PER_MILLION_TOKENS

    Returns:
        Union[str, T]: The analysis result from the model, either as string or specified object.
    """
    # Set default values if None
    model = model or DEFAULT_MODEL
    max_tokens = max_tokens or DEFAULT_MAX_TOKENS

    parameters = {
        "model": model
    }

    # If model has date parts, remove them
    model_core = "-".join(filter(lambda x: not x.isdigit(), model.split("-")))
    model_core = model_core.strip()

    if model_core not in SETTINGS_AND_COST_USD_PER_MILLION_TOKENS:
        raise ValueError(f"Model {model} not found in cost dictionary: {SETTINGS_AND_COST_USD_PER_MILLION_TOKENS}")

    model_settings_and_costs = SETTINGS_AND_COST_USD_PER_MILLION_TOKENS[model_core]

    # Temperature may not be supported by model
    if temperature is not None and ("no_temperature" not in model_settings_and_costs or not model_settings_and_costs["no_temperature"]):
        parameters["temperature"] = temperature

    if "no_system_prompt" in model_settings_and_costs and model_settings_and_costs["no_system_prompt"]:
        role = "user"
    else:
        role = "developer"
    parameters["messages"] = [{"role": role, "content": prompt}]

    # Passing max as float("inf") means use model's max from SETTINGS_AND_COST_USD_PER_MILLION_TOKENS
    if max_tokens == float("inf"):
        max_tokens = model_settings_and_costs["max_tokens"] if "max_tokens" in model_settings_and_costs else None
    elif max_tokens:
        parameters["max_completion_tokens"] = max_tokens
    elif model_settings_and_costs["max_tokens"] is not None:
        parameters["max_completion_tokens"] = model_settings_and_costs["max_tokens"]

    if response_format is not None:
        if "no_structured_output" in model_settings_and_costs and model_settings_and_costs["no_structured_output"]:
            console.print(f"LLM: [bold yellow]WARNING: model {model} does not allow structured output or response_format, returning as string instead[/bold yellow]")
        else:
            parameters["response_format"] = response_format

    try:
        response = client.beta.chat.completions.parse(**parameters)

        try:
            token_fee, token_cost_description = get_token_cost(response)
            if token_fee > 0:
                console.print(f"💰 LLM: [bold green]¢{token_fee:.3f}[/bold green] -- [light_green]{token_cost_description}[/light_green] -- Total: [green]¢{TOTAL_SPEND_CENTS:.3f}[/green]")
            else:
                console.print(f"💰 LLM: [bold red]token_fee is missing or invalid: '{token_fee}'[/bold red] -- [light_red]{token_cost_description}[/light_red] -- Total: [red]¢{TOTAL_SPEND_CENTS:.3f}[/red]")
        except Exception as e:
            if bt.logging.current_state_value in ["Debug", "Trace"]:
                bt.logging.info(f"Error getting token cost: {e}")
                console.print(f"💰 LLM: [red]Error getting token cost: {e}[/red]")

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
                    console.print(f"LLM: [bold red]ERROR: response wasn't format {response_format}, was {type(message.parsed)}, content: {message.content}[/bold red]")
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
        raise ValueError("No usage data")

    description = ""
    fee = 0

    # Handle empty or invalid model name
    if not response.model or not isinstance(response.model, str):
        raise ValueError("Model name invalid: " + response.model)

    # Remove version number from model name, e.g. o1-mini-2024-09-12
    model = "-".join(filter(lambda x: not x.isdigit(), response.model.split("-")))
    model = model.strip()

    # Make sure model is in the cost dictionary
    if model not in SETTINGS_AND_COST_USD_PER_MILLION_TOKENS:
        raise ValueError(f"Model {model} not found in cost dictionary: {SETTINGS_AND_COST_USD_PER_MILLION_TOKENS}")

    # Get the costs for this model
    model_settings_and_costs = SETTINGS_AND_COST_USD_PER_MILLION_TOKENS[model]
    # Convert dollar costs to cents
    costs = {k: v * 100 for k, v in model_settings_and_costs.items()}

    cached = response.usage.prompt_tokens_details.cached_tokens if response.usage.prompt_tokens_details else 0
    bt.logging.info(f"cached: {cached}")
    input_fee = costs["input"] * (response.usage.prompt_tokens - cached) / 1_000_000
    if input_fee > 0:
        description += f"Input: {show_first_non_zero_digit(input_fee)}"
        fee += input_fee
        bt.logging.info(f"input_fee: {input_fee}")
    else:
        description += f"Input fee calculation error: Input cost is {input_fee} eg <= 0 (this should not happen!)"

    if cached > 0:
        input_cached_fee = costs["input_cached"] * cached / 1_000_000
        fee += input_cached_fee
        description += f" (cached: {show_first_non_zero_digit(input_cached_fee)})"

    output_fee = costs["output"] * response.usage.completion_tokens / 1_000_000
    fee += output_fee

    if output_fee > 0:  
        description += f", Output: {show_first_non_zero_digit(output_fee)}"
    else:
        description += f"Output fee calculation error: Output cost is {output_fee} eg <= 0 (this should not happen!)"

    reasoning = response.usage.completion_tokens_details.reasoning_tokens
    accepted_prediction = response.usage.completion_tokens_details.accepted_prediction_tokens
    rejected_prediction = response.usage.completion_tokens_details.rejected_prediction_tokens

    if reasoning > 0 or accepted_prediction > 0 or rejected_prediction > 0:
        reasoning_fee = costs["output"] * reasoning / 1_000_000
        accepted_prediction_fee = costs["output"] * accepted_prediction / 1_000_000
        rejected_prediction_fee = costs["output"] * rejected_prediction / 1_000_000

        fee += reasoning_fee + accepted_prediction_fee + rejected_prediction_fee
        description += f". Reasoning: {show_first_non_zero_digit(reasoning_fee)}, Prediction: accepted {show_first_non_zero_digit(accepted_prediction_fee)}, rejected {show_first_non_zero_digit(rejected_prediction_fee)}"

    global TOTAL_SPEND_CENTS
    TOTAL_SPEND_CENTS += fee

    global TOTAL_SPEND_DESCRIPTION
    TOTAL_SPEND_DESCRIPTION.append(description)

    return fee, description

def show_first_non_zero_digit(cost: float) -> str:
    """
    Format cost with enough decimal places to show first non-zero digit, in case the default 2 decimals shows 0.00 etc.
    
    Args:
        cost (float): Cost in cents
        
    Returns:
        str: Formatted cost string with ¢ or $ symbol
    """
    if cost == 0:
        return "¢0"
    
    # If cost is >= $1 (100 cents), convert to dollars and show 2 decimal places
    if cost >= 100:
        dollars = cost / 100
        return f"${dollars:.2f}"
    
    # Handle cents as before
    decimals = 1
    while decimals < 10:  # Limit to 10 decimal places
        formatted = f"¢{cost:.{decimals}f}"
        if float(formatted[1:]) > 0:  # Remove ¢ symbol for comparison
            return formatted
        decimals += 1
    
    return f"¢{cost:.10f}"  # Max decimals if still zero

def get_total_spend_cents() -> float:
    """
    Get the total spend in cents.
    """
    global TOTAL_SPEND_CENTS
    return TOTAL_SPEND_CENTS

def get_total_spend_cents_description() -> str:
    """
    Get the total spend in cents.
    """
    global TOTAL_SPEND_DESCRIPTION
    return TOTAL_SPEND_DESCRIPTION

def reset_total_spend_description():
    """
    Reset the total spend description.
    """
    global TOTAL_SPEND_DESCRIPTION
    TOTAL_SPEND_DESCRIPTION = []
