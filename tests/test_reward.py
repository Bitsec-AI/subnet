import os
import pytest
# from flaky import flaky
import bittensor as bt
from unittest.mock import patch
import numpy as np
from bitsec.validator.reward import reward, jaccard_score, get_rewards
from bitsec.protocol import PredictionResponse, Vulnerability, LineRange
from bitsec.base.vulnerability_category import VulnerabilityCategory

SPEND_MONEY = os.environ.get("SPEND_MONEY", True)
if SPEND_MONEY:
    bt.logging.set_debug()

# pytestmark = pytest.mark.flaky(reruns=3)

@pytest.fixture
def mock_prediction_response():
    return PredictionResponse(
        prediction=True,
        vulnerabilities=[
            Vulnerability(
                category=VulnerabilityCategory.ARITHMETIC_OVERFLOW_AND_UNDERFLOW,
                line_ranges=[LineRange(start=1, end=9)],
                description="Can lead to loss of funds",
                vulnerable_code="",
                code_to_exploit="",
                rewritten_code_to_fix_vulnerability=""
            )
        ]
    )


vuln1 = Vulnerability(category=VulnerabilityCategory.ARITHMETIC_OVERFLOW_AND_UNDERFLOW, line_ranges=[LineRange(start=1, end=9)], description="Can lead to loss of funds", vulnerable_code="", code_to_exploit="", rewritten_code_to_fix_vulnerability="")
vuln2 = Vulnerability(category=VulnerabilityCategory.WEAK_ACCESS_CONTROL, line_ranges=[LineRange(start=10, end=20)], description="Allows unauthorized access to sensitive data", vulnerable_code="", code_to_exploit="", rewritten_code_to_fix_vulnerability="")
vuln3 = Vulnerability(category=VulnerabilityCategory.REENTRANCY, line_ranges=[LineRange(start=21, end=30)], description="Can lead to loss of funds", vulnerable_code="", code_to_exploit="", rewritten_code_to_fix_vulnerability="")
vuln4 = Vulnerability(category=VulnerabilityCategory.INCORRECT_CALCULATION, line_ranges=[LineRange(start=30, end=40)], description="Allows unauthorized access to terminate the contract", vulnerable_code="", code_to_exploit="", rewritten_code_to_fix_vulnerability="")
vuln5 = Vulnerability(category=VulnerabilityCategory.BAD_RANDOMNESS, line_ranges=[LineRange(start=30, end=40)], description="Allows unauthorized access to terminate the contract", vulnerable_code="", code_to_exploit="", rewritten_code_to_fix_vulnerability="")
vuln6 = Vulnerability(category=VulnerabilityCategory.FRONT_RUNNING, line_ranges=[LineRange(start=30, end=40)], description="Allows unauthorized access to terminate the contract", vulnerable_code="", code_to_exploit="", rewritten_code_to_fix_vulnerability="")

def test_mock_reward_perfect_score(mock_prediction_response):
    result = reward(mock_prediction_response, mock_prediction_response)
    assert result == 1.0

def test_reward_prediction_not_matching():
    expected_response = PredictionResponse(prediction=True, vulnerabilities=[vuln1])
    response = PredictionResponse(prediction=False, vulnerabilities=[])
    result = reward(expected_response, response)
    assert result == 0.0

    expected_response = PredictionResponse(prediction=False, vulnerabilities=[])
    response = PredictionResponse(prediction=True, vulnerabilities=[vuln2])
    result = reward(expected_response, response)
    assert result == 0.0

def test_jaccard_score_expected_0_actual_1():
    expected_response = PredictionResponse(prediction=False, vulnerabilities=[])
    response = PredictionResponse(prediction=True, vulnerabilities=[vuln2])
    result = jaccard_score(expected_response, response)
    assert result == 0.0

def test_jaccard_score_expected_0_actual_2():
    expected_response = PredictionResponse(prediction=False, vulnerabilities=[])
    response = PredictionResponse(prediction=True, vulnerabilities=[vuln1, vuln2])
    result = jaccard_score(expected_response, response)
    assert result == 0

def test_jaccard_score_expected_1_actual_1():
    expected_response = PredictionResponse(prediction=True, vulnerabilities=[vuln1])
    response = PredictionResponse(prediction=True, vulnerabilities=[vuln1])
    result = jaccard_score(expected_response, response)
    assert result == 1

def test_jaccard_score_expected_1_actual_2():
    expected_response = PredictionResponse(prediction=True, vulnerabilities=[vuln1])
    response = PredictionResponse(prediction=True, vulnerabilities=[vuln1, vuln2])
    result = jaccard_score(expected_response, response)
    assert result == 0.5

def test_jaccard_score_expected_2_actual_1():
    expected_response = PredictionResponse(prediction=True, vulnerabilities=[vuln1, vuln2])
    response = PredictionResponse(prediction=True, vulnerabilities=[vuln1])
    result = jaccard_score(expected_response, response)
    assert result == 0.5

def test_jaccard_score_expected_2_actual_2():
    expected_response = PredictionResponse(prediction=True, vulnerabilities=[vuln1, vuln2])
    response = PredictionResponse(prediction=True, vulnerabilities=[vuln1, vuln2])
    result = jaccard_score(expected_response, response)
    assert result == 1

def test_jaccard_score_expected_2_actual_3():
    expected_response = PredictionResponse(prediction=True, vulnerabilities=[vuln1, vuln2])
    response = PredictionResponse(prediction=True, vulnerabilities=[vuln1, vuln2, vuln3])
    result = jaccard_score(expected_response, response)
    assert result == 2/3

def test_jaccard_score_expected_2_actual_4():
    expected_response = PredictionResponse(prediction=True, vulnerabilities=[vuln1, vuln2])
    response = PredictionResponse(prediction=True, vulnerabilities=[vuln1, vuln2, vuln3, vuln4])
    result = jaccard_score(expected_response, response)
    assert result == 2/4

def test_jaccard_score_expected_3_actual_6():
    expected_response = PredictionResponse(prediction=True, vulnerabilities=[vuln1, vuln2, vuln3])
    response = PredictionResponse(prediction=True, vulnerabilities=[vuln1, vuln2, vuln3, vuln4, vuln5, vuln6])
    result = jaccard_score(expected_response, response)
    assert result == 3/6

def test_reward_both_empty_vulnerabilities():
    expected_response = PredictionResponse(prediction=True, vulnerabilities=[])
    response = PredictionResponse(prediction=True, vulnerabilities=[])
    result = reward(expected_response, response)
    assert result == 1.0

def test_reward_one_empty_vulnerabilities():
    expected_response = PredictionResponse(prediction=True, vulnerabilities=[vuln1])
    response = PredictionResponse(prediction=True, vulnerabilities=[])
    result = reward(expected_response, response)
    assert result == 0.0

def test_jaccard_score_identical_responses():
    expected_response = PredictionResponse(prediction=True, vulnerabilities=[vuln1, vuln2])
    response = PredictionResponse(prediction=True, vulnerabilities=[vuln1, vuln2])
    result = jaccard_score(expected_response, response)
    assert result == 1.0

def test_jaccard_score_no_overlap():
    expected_response = PredictionResponse(prediction=True, vulnerabilities=[vuln1, vuln2])
    response = PredictionResponse(prediction=True, vulnerabilities=[vuln3, vuln4])
    result = jaccard_score(expected_response, response)
    assert result == 0.0

def test_jaccard_score_partial_overlap():
    expected_response = PredictionResponse(prediction=True, vulnerabilities=[vuln1, vuln2, vuln3])
    response = PredictionResponse(prediction=True, vulnerabilities=[vuln2, vuln3, vuln4])
    result = jaccard_score(expected_response, response)
    assert result == 2/4

def test_jaccard_score_subset():
    expected_response = PredictionResponse(prediction=True, vulnerabilities=[vuln1, vuln2])
    response = PredictionResponse(prediction=True, vulnerabilities=[vuln1, vuln2, vuln3])
    result = jaccard_score(expected_response, response)
    assert result == 2/3

def test_get_rewards_multiple_responses():
    expected_response = PredictionResponse(prediction=True, vulnerabilities=[vuln1, vuln2])
    responses = [
        PredictionResponse(prediction=True, vulnerabilities=[vuln1, vuln2]),
        PredictionResponse(prediction=True, vulnerabilities=[vuln1]),
        PredictionResponse(prediction=True, vulnerabilities=[vuln3, vuln4]),
        PredictionResponse(prediction=False, vulnerabilities=[vuln1, vuln2])
    ]
    rewards = get_rewards(expected_response, responses)
    assert len(rewards) == 4
    assert rewards[0] == 1.0
    assert rewards[1] == 0.5
    assert rewards[2] == 0.0
    assert rewards[3] == 0.0

def test_get_rewards_empty_responses():
    expected_response = PredictionResponse(prediction=True, vulnerabilities=[vuln1])
    rewards = get_rewards(expected_response, [])
    assert len(rewards) == 0
    assert isinstance(rewards, np.ndarray)

def test_jaccard_score_duplicate_vulnerabilities():
    expected_response = PredictionResponse(prediction=True, vulnerabilities=[vuln1, vuln1])
    response = PredictionResponse(prediction=True, vulnerabilities=[vuln1])
    result = jaccard_score(expected_response, response)
    assert result == 1.0

def test_jaccard_score_different_descriptions_same_category():
    vuln1_different_desc = Vulnerability(
        category=VulnerabilityCategory.ARITHMETIC_OVERFLOW_AND_UNDERFLOW,
        line_ranges=[LineRange(start=1, end=9)],
        description="Different description",
        vulnerable_code="",
        code_to_exploit="",
        rewritten_code_to_fix_vulnerability=""
    )
    expected_response = PredictionResponse(prediction=True, vulnerabilities=[vuln1])
    response = PredictionResponse(prediction=True, vulnerabilities=[vuln1_different_desc])
    result = jaccard_score(expected_response, response)
    assert result == 1.0

def test_jaccard_score_different_line_ranges_same_category():
    vuln1_different_lines = Vulnerability(
        category=VulnerabilityCategory.ARITHMETIC_OVERFLOW_AND_UNDERFLOW,
        line_ranges=[LineRange(start=100, end=200)],
        description="Can lead to loss of funds",
        vulnerable_code="",
        code_to_exploit="",
        rewritten_code_to_fix_vulnerability=""
    )
    expected_response = PredictionResponse(prediction=True, vulnerabilities=[vuln1])
    response = PredictionResponse(prediction=True, vulnerabilities=[vuln1_different_lines])
    result = jaccard_score(expected_response, response)
    assert result == 1.0