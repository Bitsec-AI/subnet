from bitsec.utils.llm import chat_completion
from bitsec.protocol import Vulnerability, PredictionResponse
from typing import List
import bittensor as bt

VULNERABILITY_TO_REPORT_TEMPLATE = """You are an expert in economic security analysis for decentralized computing systems, specifically for the Bittensor network. 

Your task is to generate a new economic analysis report for a system that involves miners, validators, and reward mechanisms. The report should focus on potential financial vulnerabilities and economic exploits within the system.

For each vulnerability, the report should contain the following sections:

1. **Economic Exploit:** Describe the vulnerability and how it could be exploited for financial gain.
2. **Code Examples:** Include code snippets illustrating vulnerability and how it can be exploited. 
3. **Mitigation Strategy:** Provide code snippets with the vulnerability fixed.

Format the report in markdown:

# [vulnerability number eg 1.] [Vulnerability Category]
[vulnerability description]

### Vulnerable Code
```
[vulnerable code]
```

### Code to Exploit
```
[code to exploit]
```

### Rewritten Code to Fix Vulnerability
```
[rewritten code to fix vulnerability]
```

---------
Note: Do not include any other text than the sections above.
Note: If any of the sections are not code, do not include the ``` code block.
---------

Here is the list of vulnerabilities:
{vulnerabilities}
"""

def format_vulnerability_to_report(
    vulnerabilities: List[Vulnerability],
    model: str = None,
    temperature: float = None,
) -> str:
    """
    Format the vulnerability analysis into a human readable report.

    Args:
        vulnerabilities (List[Vulnerability]): The vulnerabilities to format.
        model (str): The model to use for analysis.
        temperature (float): Sampling temperature.
        max_tokens (int): Maximum number of tokens to generate.

    Returns:
        str: The formatted report.
    """
    prompt = VULNERABILITY_TO_REPORT_TEMPLATE.format(vulnerabilities=vulnerabilities)
    max_tokens = 16384

    try:
        response = chat_completion(prompt, model=model, temperature=temperature, max_tokens=max_tokens)
        return response
    except Exception as e:
        bt.logging.error(f"Failed to format analysis: {e}")
        raise

def aggregate_responses(responses: List[PredictionResponse]) -> List[Vulnerability]:
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

def generate_report(aggregated_vulnerabilities: List[Vulnerability]) -> str:
    """
    Generates a report from aggregated vulnerabilities.

    Args:
        aggregated_vulnerabilities (List[Vulnerability]): Aggregated list of vulnerabilities.

    Returns:
        str: Generated report in markdown format.
    """
    return format_vulnerability_to_report(aggregated_vulnerabilities)
