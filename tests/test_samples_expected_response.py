import os
import pytest
from flaky import flaky
import bittensor as bt
from bitsec.protocol import PredictionResponse, Vulnerability, LineRange
from bitsec.validator.reward import jaccard_score
from bitsec.base.vulnerability_category import VulnerabilityCategory

SPEND_MONEY = os.environ.get("SPEND_MONEY", False)

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
        category=VulnerabilityCategory.REENTRANCY,
        description="Can lead to loss of funds",
        line_ranges=[line_range],
        vulnerable_code="",
        code_to_exploit="",
        rewritten_code_to_fix_vulnerability=""
    )
    
    response1 = PredictionResponse(
        prediction=True,
        vulnerabilities=[vulnerability]
    )
    
    # Create a deep copy to avoid shared references
    response2 = PredictionResponse.model_validate(response1.model_dump())
    
    return response1, response2

@flaky(max_runs=5, min_passes=1, rerun_filter=lambda err, *args: True)
def test_similarity_of_short_descriptions1():
    if not SPEND_MONEY:
        return

    response1, response2 = setup_identical_responses()
    description_2 = "Withdrawal is vulnerable to reentrancy attack."
    response2.vulnerabilities[0].description = description_2

    score = jaccard_score(response1, response2)
    assert score >= 1, f"Score is {score}, expected 1\nShort descriptions: {response1.vulnerabilities[0].description} and {description_2}"

@flaky(max_runs=5, min_passes=1, rerun_filter=lambda err, *args: True)
def test_similarity_of_short_descriptions2():
    if not SPEND_MONEY:
        return

    response1, response2 = setup_identical_responses()
    description_2 = "Reentrancy attack."
    response2.vulnerabilities[0].description = description_2
    score = jaccard_score(response1, response2)
    assert score >= 1, f"Score is {score}, expected 1\nShort descriptions: {response1.vulnerabilities[0].description} and {description_2}"

@flaky(max_runs=5, min_passes=1, rerun_filter=lambda err, *args: True)
def test_similarity_of_long_descriptions():
    if not SPEND_MONEY:
        return

    response1, response2 = setup_identical_responses()
    long_description_2 = "because of the vulnerability to a reentrancy attack during withdrawal, funds can be stolen"
    response2.vulnerabilities[0].description = long_description_2
    score = jaccard_score(response1, response2)
    assert score >= 1, f"Score is {score}, expected 1\nLong descriptions: {response1.vulnerabilities[0].description} and {long_description_2}"