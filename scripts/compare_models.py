#!/usr/bin/env python3
"""
Script to compare different LLM models for challenge generation.

This script generates challenges using different models and logs the results
and costs to files with timestamps.

To run:

```
$ python scripts/compare_models.py
```
It will run all the models in 
- MODELS_TO_TEST_STRUCTURED_OUTPUT, and output each model's PredictionResponse to the console
- MODELS_TO_TEST_UNSTRUCTURED_OUTPUT and output the raw response to the console

It will also create a subdirectory `model_comparison_results` and then a directory below that with date timestamp. This will contain:

- input_clean_code.sol -- Code it started with
- input_vulnerability.md -- Description of vulnerability injected
- results.json -- The results from all the models, particularly the cost and time taken for each model

Plus files to contain each models result named by the model name, eg

- gpt-4o-mini_generated_code.sol   
- o1-2024-12-17_generated_code.sol 
- o1-mini_output.md -- note it is .md because the model can't return structured output
- etc

Finally, it will print the total cost and time taken to the console.
"""
MODELS_TO_TEST_STRUCTURED_OUTPUT = [
    "gpt-4o-mini",
    "gpt-4o",
    "o1-2024-12-17",
    "o3-mini-2025-1-31",
]
MODELS_TO_TEST_UNSTRUCTURED_OUTPUT = [
    "o1-mini",
]
SCREEN_WIDTH = 120


import os
import sys
from datetime import datetime
import json
from typing import Dict, Any
from textwrap import dedent
import time
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

# Configure paths
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(SCRIPT_DIR)
OUTPUT_DIR = os.path.join(ROOT_DIR, 'model_comparison_results')

# Add project root to Python path
sys.path.insert(0, ROOT_DIR)

from bitsec.utils.data import get_random_secure_filename, get_random_vulnerability_filename, create_challenge_with_inputs
from bitsec.utils.llm import get_total_spend_cents, show_first_non_zero_digit

# Prettier output
console = Console()

def setup_output_dir() -> str:
    """
    Create output directory with timestamp.
    
    Returns:
        str: Path to the created output directory
    """
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    output_dir = os.path.join(OUTPUT_DIR, timestamp)
    os.makedirs(output_dir, exist_ok=True)
    return output_dir

def format_vulnerability_info(vulnerability_info: Dict | None) -> str:
    """
    Format vulnerability information for display.
    
    Args:
        vulnerability_info (Dict | None): Dictionary containing vulnerability information, or None for unstructured output
        
    Returns:
        str: Formatted string for display
    """
    if vulnerability_info is None:
        return "Model returned unstructured output, no vulnerability information available"
        
    vulnerabilities = vulnerability_info.get("vulnerabilities")
    if not vulnerabilities:
        return "No vulnerabilities added!!!! :("
    
    output = []
    for vuln in vulnerabilities:
        # Handle multiline descriptions by proper indentation
        description = dedent(vuln.get("description", "")).strip()
        description_lines = description.split("\n")
        indented_description = "\n      ".join(description_lines)
        
        output.append(f"  • Type: {vuln.get('type', 'Unknown')}")
        output.append(f"    Severity: {vuln.get('severity', 'Unknown')}")
        output.append(f"    Description:\n      {indented_description}")
        if vuln.get("line_numbers"):
            output.append(f"    Line Numbers: {', '.join(map(str, vuln['line_numbers']))}")
        output.append("")  # Add blank line between vulnerabilities
    
    return "\n".join(output)

def format_duration(seconds: float) -> str:
    """
    Format duration in seconds to a human readable string.
    
    Args:
        seconds (float): Duration in seconds
        
    Returns:
        str: Formatted duration string
    """
    if seconds < 60:
        return f"{seconds:.1f}s"
    minutes = int(seconds // 60)
    seconds = seconds % 60
    return f"{minutes}m {seconds:.1f}s"

def run_model_comparison(
    clean_code: str,
    vulnerability_description: str,
    output_dir: str
) -> Dict[str, Any]:
    """
    Run challenge generation with different models and collect results.
    
    Args:
        clean_code (str): The secure code to modify
        vulnerability_description (str): Description of vulnerability to inject
        output_dir (str): Directory to save results
        
    Returns:
        Dict[str, Any]: Dictionary containing results and costs for each model
    """
    results = {}
    
    for model in list(set(MODELS_TO_TEST_STRUCTURED_OUTPUT + MODELS_TO_TEST_UNSTRUCTURED_OUTPUT)):
        console.print(f"Calling {model} ...")
        initial_spend = get_total_spend_cents()
        start_time = time.time()
        
        try:
            # Generate challenge with current model
            is_unstructured = model in MODELS_TO_TEST_UNSTRUCTURED_OUTPUT
            modified_code, vulnerability_info, cost, cost_description = create_challenge_with_inputs(
                clean_code=clean_code,
                vulnerability_description=vulnerability_description,
                model=model,
                respond_as_str=is_unstructured
            )
            
            # Calculate metrics
            duration = time.time() - start_time
            cost_pretty = show_first_non_zero_digit(cost)
            
            # Print detailed success info with pretty formatting
            title = Text()
            title.append("✓ ", style="green")
            title.append(f"{model}, Cost: {cost_pretty}, {cost_description}, Time: {format_duration(duration)}")
            
            # Save generated code to file
            code_filename = f"{model}_generated_code.sol" if not is_unstructured else f"{model}_output.md"
            with open(os.path.join(output_dir, code_filename), 'w') as f:
                f.write(modified_code)

            # Save results
            vulnerability_info_dict = None
            if vulnerability_info is None:
                content = f"Model returned unstructured output\n\n{modified_code}"
            else:
                vulnerability_info_dict = vulnerability_info.model_dump()
                content = format_vulnerability_info(vulnerability_info_dict)

            console.print(Panel(content, title=title, expand=False, width=SCREEN_WIDTH))

            results[model] = {
                "success": True,
                "cost_cents": cost_pretty,
                "cost_description": cost_description,
                "duration_seconds": duration,
                "vulnerability_info": vulnerability_info_dict,
            }
        except Exception as e:
            duration = time.time() - start_time
            results[model] = {
                "success": False,
                "duration_seconds": duration,
                "error": str(e)
            }
            console.print(Panel(f"Error: {str(e)}", title=f"[red]✗ {model} ({format_duration(duration)})[/red]", expand=False, width=SCREEN_WIDTH))
    
    return results

def main():
    """Main function to run model comparison."""
    start_time = time.time()
    
    # Create output directory
    output_dir = setup_output_dir()
    console.print(f"Saving results to: {output_dir}")
    
    # Get random sample files
    secure_filename = get_random_secure_filename()
    vulnerability_filename = get_random_vulnerability_filename()
    
    # Read input files
    clean_code = open(secure_filename, 'r').read()
    vulnerability_description = open(vulnerability_filename, 'r').read()

    # print first line of vulnerability description
    vulnerability_description_first_line = vulnerability_description.split('\n')[0]
    print(f"vulnerability_description: {vulnerability_description_first_line}")
    
    # Save input files for reference
    with open(os.path.join(output_dir, 'input_clean_code.sol'), 'w') as f:
        f.write(clean_code)
    with open(os.path.join(output_dir, 'input_vulnerability.md'), 'w') as f:
        f.write(vulnerability_description)
    
    # Run comparison
    results = run_model_comparison(clean_code, vulnerability_description, output_dir)
    
    # Calculate total duration
    total_duration = time.time() - start_time
    total_cost = get_total_spend_cents()
    
    # Save results
    results_file = os.path.join(output_dir, 'results.json')
    final_results = {
        "total_duration_seconds": total_duration,
        "total_cost_cents": total_cost,
        "models": results
    }
    with open(results_file, 'w') as f:
        json.dump(final_results, f, indent=2)

    console.print(f"\nTotal cost: {show_first_non_zero_digit(total_cost)}")
    console.print(f"Total time: {format_duration(total_duration)}")
    console.print(f"Results saved to: {output_dir}")

if __name__ == "__main__":
    main() 