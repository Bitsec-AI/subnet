import os
import time
import json
import random
import statistics
from typing import List, Dict, Any, Tuple
from bitsec.utils.data import get_all_vulnerability_and_secure_filenames, create_challenge
from bitsec.protocol import PredictionResponse, Vulnerability

class BenchmarkSuite:
    def __init__(self, num_challenges: int = 10):
        self.num_challenges = num_challenges
        self.real_world_contracts = []
        self.synthetic_contracts = []
        self.load_contracts()

    def load_contracts(self):
        vuln_filenames, secure_filenames = get_all_vulnerability_and_secure_filenames()
        self.real_world_contracts = secure_filenames
        self.synthetic_contracts = vuln_filenames

    def run_benchmark(self) -> Dict[str, Any]:
        results = {
            "true_positives": 0,
            "false_positives": 0,
            "true_negatives": 0,
            "false_negatives": 0,
            "detection_latencies": [],
            "report_completeness_scores": []
        }

        for _ in range(self.num_challenges):
            is_vulnerable = random.choice([True, False])
            contract, expected_response = create_challenge(is_vulnerable)
            start_time = time.time()
            prediction_response = self.run_miner(contract)
            end_time = time.time()
            detection_latency = end_time - start_time

            if is_vulnerable:
                if prediction_response.prediction:
                    results["true_positives"] += 1
                else:
                    results["false_negatives"] += 1
            else:
                if prediction_response.prediction:
                    results["false_positives"] += 1
                else:
                    results["true_negatives"] += 1

            results["detection_latencies"].append(detection_latency)
            report_completeness_score = self.calculate_report_completeness(prediction_response, expected_response)
            results["report_completeness_scores"].append(report_completeness_score)

        results["true_positive_rate"] = results["true_positives"] / self.num_challenges
        results["false_positive_rate"] = results["false_positives"] / self.num_challenges
        results["detection_latency"] = statistics.mean(results["detection_latencies"])
        results["report_completeness"] = statistics.mean(results["report_completeness_scores"])

        return results

    def run_miner(self, contract: str) -> PredictionResponse:
        # Placeholder for miner execution logic
        return PredictionResponse(prediction=False, vulnerabilities=[])

    def calculate_report_completeness(self, prediction_response: PredictionResponse, expected_response: PredictionResponse) -> float:
        predicted_vulns = {vuln.description for vuln in prediction_response.vulnerabilities}
        expected_vulns = {vuln.description for vuln in expected_response.vulnerabilities}
        common_vulns = predicted_vulns.intersection(expected_vulns)
        if not expected_vulns:
            return 1.0 if not predicted_vulns else 0.0
        return len(common_vulns) / len(expected_vulns)

    def generate_report(self, results: Dict[str, Any], output_path: str):
        with open(output_path, 'w') as f:
            json.dump(results, f, indent=4)

if __name__ == "__main__":
    benchmark_suite = BenchmarkSuite(num_challenges=10)
    results = benchmark_suite.run_benchmark()
    benchmark_suite.generate_report(results, "benchmark_report.json")
    print("Benchmark completed. Report generated at benchmark_report.json")
