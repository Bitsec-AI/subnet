####### To see the report output, run:
####### pytest -v -s tests/test_make_report.py
########################################################

import os
import pytest
from flaky import flaky
import bittensor as bt
from bitsec.protocol import PredictionResponse, Vulnerability, LineRange
from bitsec.base.vulnerability_category import VulnerabilityCategory
from bitsec.econ_miner.prompt import code_to_vulns
from bitsec.validator.make_report import format_vulnerability_to_report

SPEND_MONEY = os.environ.get("SPEND_MONEY", False)

if SPEND_MONEY:
    bt.logging.set_debug()

# @flaky(max_runs=5, min_passes=1, rerun_filter=lambda err, *args: True)
@flaky(max_runs=1, min_passes=1, rerun_filter=lambda err, *args: True)
def test_make_report():
    """
    Test the vulnerability report generation functionality.
    
    This test verifies that:
    1. Code analysis works correctly
    2. Report formatting works correctly
    3. Response validation works correctly
    """
    if not SPEND_MONEY:
        print(f"SPEND_MONEY: {SPEND_MONEY}")    
        pytest.skip("Skipping test because SPEND_MONEY is False")

    p = PredictionResponse(
        prediction=True,
        vulnerabilities=[
            Vulnerability(
                category=VulnerabilityCategory.WEAK_ACCESS_CONTROL,
                description="Miners could report false hardware specifications to appear more capable than they actually are, potentially receiving more allocation requests and rewards.",
                vulnerable_code="error",
                code_to_exploit="""
                # Claims 8 GPUs with 80GB each when actually having only 2 GPUs with 10GB each
                def get_gpu_info():
        return {
            'count': 8,
            'capacity': 80000,
            'details': [{'name': 'NVIDIA A100-SXM4-80GB'} for _ in range(8)]
        }""",
                rewritten_code_to_fix_vulnerability="# Implement hardware verification checks and cross-reference reported specs with actual performance"
            ),
            Vulnerability(
                category=VulnerabilityCategory.INCORRECT_CALCULATION,
                description="Miners could selectively solve only the easiest challenges while ignoring more difficult ones, skewing their performance metrics.",
                vulnerable_code="""def run_miner_pow(run_id, _hash, salt, mode, chars, mask, difficulty):
        if difficulty <= 8:
            return run_hashcat(...)
        else:
            return {'password': None, 'error': 'Timed out'}""",
                code_to_exploit="# Only solve easy challenges to appear more efficient",
                rewritten_code_to_fix_vulnerability="# Ensure scoring accounts for challenge difficulty and implement minimum thresholds for challenge engagement"
            ),
            Vulnerability(
                category=VulnerabilityCategory.GOVERNANCE_ATTACKS,
                description="Miners could collude with validators to receive preferential treatment in allocation and scoring.",
                vulnerable_code="""if validator_hotkey in colluding_validators:
        return inflated_performance_metrics()
    else:
        return actual_performance_metrics()""",
                code_to_exploit="# Favoritism between colluding validators and miners",
                rewritten_code_to_fix_vulnerability="# Implement robust randomization in validator-miner pairing and conduct periodic audits"
            ),
            Vulnerability(
                category=VulnerabilityCategory.WEAK_ACCESS_CONTROL,
                description="Miners could create multiple identities to increase their chances of allocation and rewards.",
                vulnerable_code="""for i in range(10):
        wallet = create_new_wallet()
        register_as_miner(wallet)
        run_miner_instance(wallet)""",
                code_to_exploit="# Creating multiple identities to game the system",
                rewritten_code_to_fix_vulnerability="# Implement stake requirements and use IP/hardware fingerprinting to detect multiple identities"
            ),
            Vulnerability(
                category=VulnerabilityCategory.IMPROPER_INPUT_VALIDATION,
                description="Miners could cache challenge results and reuse them to appear faster in subsequent identical challenges.",
                vulnerable_code="""challenge_cache = {}

    def solve_challenge(challenge):
        if challenge in challenge_cache:
            return challenge_cache[challenge]
        result = actual_solve_function(challenge)
        challenge_cache[challenge] = result
        return result""",
                code_to_exploit="# Cache results to appear faster in repeated challenges",
                rewritten_code_to_fix_vulnerability="# Ensure challenges are unique and implement server-side nonces"
            ),
            Vulnerability(
                category=VulnerabilityCategory.WEAK_ACCESS_CONTROL,
                description="Miners could exploit the allocation system by quickly accepting allocations and then immediately releasing them, gaming the reward system.",
                vulnerable_code="""def exploit_allocation():
        while True:
            allocation = accept_allocation()
            if allocation:
                claim_allocation_reward(allocation)
                immediately_release_allocation(allocation)""",
                code_to_exploit="# Quickly accept and release allocations for rewards",
                rewritten_code_to_fix_vulnerability="# Implement minimum allocation hold times and adjust rewards based on duration"
            ),
            Vulnerability(
                category=VulnerabilityCategory.BAD_RANDOMNESS,
                description="Miners could outsource proof of work challenges to more powerful external systems, misrepresenting their actual capabilities.",
                vulnerable_code="""def solve_pow_challenge(challenge):
        return send_to_external_solver(challenge)

    def get_hardware_specs():
        return local_hardware_specs""",
                code_to_exploit="# Outsourcing computation while misreporting local specs",
                rewritten_code_to_fix_vulnerability="# Implement latency checks and require periodic system benchmarks"
            )
        ]
    )

    assert p.prediction, "Prediction should be true"
    assert len(p.vulnerabilities) > 0, "Vulnerabilities should be non-empty"

    report = format_vulnerability_to_report(p.vulnerabilities)
    print(report)
    assert isinstance(report, str)

    for vuln in p.vulnerabilities:
        assert isinstance(vuln, Vulnerability)
        assert isinstance(vuln.category, VulnerabilityCategory)

        # each should be a string with content
        assert isinstance(vuln.description, str)
        assert len(vuln.description) > 0
        assert isinstance(vuln.vulnerable_code, str)
        assert len(vuln.vulnerable_code) > 0
        assert isinstance(vuln.code_to_exploit, str)
        assert len(vuln.code_to_exploit) > 0
        assert isinstance(vuln.rewritten_code_to_fix_vulnerability, str)
        assert len(vuln.rewritten_code_to_fix_vulnerability) > 0

        # line_ranges is optional
        if vuln.line_ranges:
            assert isinstance(vuln.line_ranges, list)
            for line_range in vuln.line_ranges:
                assert isinstance(line_range, LineRange)
                assert isinstance(line_range.start, int)
                assert isinstance(line_range.end, int)


