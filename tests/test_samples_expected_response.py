import os
import pytest
from flaky import flaky
import bittensor as bt
from bitsec.miner.analyze import analyze_code
from bitsec.protocol import PredictionResponse, Vulnerability, LineRange
from bitsec.utils.data import get_all_code_samples, load_sample_file
from bitsec.validator.reward import score_response
from rich.console import Console
from rich.table import Table

SPEND_MONEY = os.environ.get("SPEND_MONEY", False)

console = Console()
if SPEND_MONEY:
    bt.logging.set_debug()

def setup_identical_responses():
    """
    Create two identical vulnerability responses for testing.
    Tests can modify specific parts to test different scenarios.

    Yields:
        PredictionResponse, PredictionResponse: Two identical response objects
    """
    line_range = LineRange(start=1, end=9)
    vulnerability = Vulnerability(
        short_description="Potential for reentrancy attack during withdrawal.",
        detailed_description="Can lead to loss of funds",
        line_ranges=[line_range]
    )
    
    response1 = PredictionResponse(
        prediction=True,
        vulnerabilities=[vulnerability]
    )
    
    # Create a deep copy to avoid shared references
    response2 = PredictionResponse.model_validate(response1.model_dump())
    
    return response1, response2

@flaky(max_runs=3)
def test_similarity_of_short_descriptions1():
    if not SPEND_MONEY:
        return

    response1, response2 = setup_identical_responses()
    short_description_2 = "Withdrawal is vulnerable to reentrancy attack."
    response2.vulnerabilities[0].short_description = short_description_2

    score, reason, _, _, _ = score_response(response1, response2)
    assert score >= 4, f"Score is {score}, expected 4. Reason: {reason}\nShort descriptions: {response1.vulnerabilities[0].short_description} and {short_description_2}"

@flaky(max_runs=3)
def test_similarity_of_short_descriptions2():
    if not SPEND_MONEY:
        return

    response1, response2 = setup_identical_responses()
    short_description_2 = "Reentrancy attack."
    response2.vulnerabilities[0].short_description = short_description_2
    score, reason, _, _, _ = score_response(response1, response2)
    assert score >= 4, f"Score is {score}, expected 4. Reason: {reason}\nShort descriptions: {response1.vulnerabilities[0].short_description} and {short_description_2}"

@flaky(max_runs=3)
def test_similarity_of_long_descriptions():
    if not SPEND_MONEY:
        return

    response1, response2 = setup_identical_responses()
    long_description_2 = "because of the vulnerability to a reentrancy attack during withdrawal, funds can be stolen"
    response2.vulnerabilities[0].detailed_description = long_description_2
    score, reason, _, _, _ = score_response(response1, response2)
    assert score >= 4, f"Score is {score}, expected 4. Reason: {reason}\nLong descriptions: {response1.vulnerabilities[0].detailed_description} and {long_description_2}"


@flaky(max_runs=3)
def test_response_for_every_sample():
    """Test response with real response."""
    if not SPEND_MONEY:
        print(f"Skipping test {test_response_for_every_sample.__name__}, since it costs money")
        return

    vulnerable_filenames = get_all_code_samples(vulnerable=True)
    for filename in vulnerable_filenames:
        code, expected_response = load_sample_file(filename)
        result = analyze_code(code)
        assert isinstance(result, PredictionResponse)
        assert result.prediction == expected_response.prediction, f"{filename}: Prediction is {result.prediction}, expected {expected_response.prediction}"
        # do not check number of vulnerabilities, since test bot is very simple and does not find all vulnerabilities

        score, reason, vulnerabilities_expected_and_found, vulnerabilities_expected_but_not_found, vulnerabilities_found_but_not_expected = score_response(expected_response, result)
        assert score >= 2, f"{filename}: Score is {score}, expected at least 2"
        print_vulnerability_comparison(filename, score, reason, vulnerabilities_expected_and_found, vulnerabilities_expected_but_not_found, vulnerabilities_found_but_not_expected, console, bt)
    
    secure_filenames = get_all_code_samples(vulnerable=False)
    for filename in secure_filenames:
        code, expected_response = load_sample_file(filename)
        result = analyze_code(code)
        assert isinstance(result, PredictionResponse)
        assert result.prediction == expected_response.prediction, f"{filename}: Prediction is {result.prediction}, expected {expected_response.prediction}"

        score, reason, vulnerabilities_expected_and_found, vulnerabilities_expected_but_not_found, vulnerabilities_found_but_not_expected = score_response(expected_response, result)
        assert score >= 4, f"{filename}: Score is {score}, expected at least 4"

        if vulnerabilities_expected_but_not_found or vulnerabilities_found_but_not_expected:
            print_vulnerability_comparison(filename, score, reason, vulnerabilities_expected_and_found, vulnerabilities_expected_but_not_found, vulnerabilities_found_but_not_expected, console, bt)
        else:
            bt.logging.info(f"{filename}: Score is {score}")


def print_vulnerability_comparison(
    filename: str,
    score: float,
    reason: str,
    vulnerabilities_expected_and_found: list[str],
    vulnerabilities_expected_but_not_found: list[str],
    vulnerabilities_found_but_not_expected: list[str],
    console: Console,
    bt: bt # bitTensor logger
) -> None:
    """
    Print a table comparing expected and actual vulnerabilities.

    Args:
        filename: Name of the file being analyzed
        score: Analysis score
        reason: Reason for the score
        vulnerabilities_expected_and_found: List of correctly identified vulnerabilities
        vulnerabilities_expected_but_not_found: List of missed vulnerabilities
        vulnerabilities_found_but_not_expected: List of false positive vulnerabilities
        console: Rich console instance for output
    """
    if bt.logging.current_state_value not in ["Debug", "Trace"]:
        return

    table = Table(title=f"score: [bold blue]{score}[/bold blue] [dark grey]{filename}[/dark grey]\n[grey]{reason}[/grey]")
    table.add_column("Vulnerability")
    table.add_column("Correct")
    table.add_column("Response")

    # Add rows in order: correct, missing, false positives
    for vuln in sorted(vulnerabilities_expected_and_found):
        table.add_row(vuln, "✓", "✓")
    
    for vuln in sorted(vulnerabilities_expected_but_not_found):
        table.add_row(vuln, "✓", " ", style="red")
    
    for vuln in sorted(vulnerabilities_found_but_not_expected):
        table.add_row(vuln, " ", "✓", style="red")

    console.print(table)
    console.print()
