"""
Integration module for the Bitsec subnet.

This module provides a cohesive integration of all the enhanced components:
1. Reputation-based scoring for miners
2. Sybil attack detection and prevention
3. Comprehensive vulnerability reporting
4. Benchmarking system for different vulnerability types
"""

import logging
import os
import json
from typing import Dict, List, Any, Optional, Tuple, Set
from pathlib import Path
from datetime import datetime
import bittensor as bt

from bitsec.reputation import ReputationSystem, VulnerabilityScore
from bitsec.security.sybil_detection import SybilDetection, SybilProtection
from bitsec.reporting.vulnerability_report import VulnerabilityReportGenerator
from bitsec.benchmarking.vulnerability_benchmark import VulnerabilityBenchmark, BenchmarkSuite
from bitsec.protocol import CodeSynapse, PredictionResponse


class BitsecSubnet:
    """
    Main integration class for the Bitsec subnet.
    
    This class combines all enhanced components into a cohesive system for
    vulnerability detection and analysis, with robustness against Sybil attacks
    and accurate reward distribution.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the Bitsec subnet integration.
        
        Args:
            config: Configuration dictionary for the subnet
        """
        self.config = config or {}
        
        # Set up storage paths
        base_path = self.config.get('storage_path', os.path.expanduser("~/.bitsec"))
        self.base_path = Path(base_path)
        self.base_path.mkdir(parents=True, exist_ok=True)
        
        # Initialize components
        self.reputation_system = ReputationSystem(
            storage_path=os.path.join(base_path, "reputation"),
            accuracy_weight=self.config.get('reputation', {}).get('accuracy_weight', 0.4),
            consistency_weight=self.config.get('reputation', {}).get('consistency_weight', 0.2),
            uniqueness_weight=self.config.get('reputation', {}).get('uniqueness_weight', 0.3),
            severity_weight=self.config.get('reputation', {}).get('severity_weight', 0.1)
        )
        
        self.sybil_detection = SybilDetection(
            storage_path=os.path.join(base_path, "sybil"),
            similarity_threshold=self.config.get('sybil', {}).get('similarity_threshold', 0.85)
        )
        
        self.sybil_protection = SybilProtection(
            min_stake=self.config.get('sybil', {}).get('min_stake', 0.1),
            max_miners_per_wallet=self.config.get('sybil', {}).get('max_miners_per_wallet', 5)
        )
        
        self.report_generator = VulnerabilityReportGenerator(
            storage_path=os.path.join(base_path, "reports"),
            consensus_threshold=self.config.get('reporting', {}).get('consensus_threshold', 0.25)
        )
        
        self.benchmark_system = VulnerabilityBenchmark(
            storage_path=os.path.join(base_path, "benchmarks")
        )
        
        # Create default benchmark suite if not exists
        self._ensure_benchmark_suite()
        
        # Set up logging
        self.logger = logging.getLogger("bitsec.integration")
        self.logger.info("Bitsec subnet integration initialized")
    
    def process_miner_responses(self, 
                               query_id: str, 
                               code: str, 
                               responses: Dict[str, PredictionResponse], 
                               miner_weights: Optional[Dict[str, float]] = None) -> Dict[str, Any]:
        """
        Process responses from miners for a code vulnerability analysis query.
        
        This method:
        1. Analyzes responses for Sybil attack patterns
        2. Updates miner reputation scores
        3. Generates a consolidated vulnerability report
        4. Adjusts rewards based on detection quality and Sybil analysis
        
        Args:
            query_id: Unique identifier for the query
            code: Code that was analyzed
            responses: Dictionary mapping miner IDs to their responses
            miner_weights: Optional dictionary mapping miner IDs to their weights
            
        Returns:
            Dictionary containing the processing results
        """
        self.logger.info(f"Processing responses for query {query_id} from {len(responses)} miners")
        
        # 1. Analyze for potential Sybil attacks
        sybil_groups = self.sybil_detection.analyze_responses(query_id, responses)
        if sybil_groups:
            self.logger.warning(f"Detected {len(sybil_groups)} potential Sybil groups")
        
        # Record responses in the Sybil detection system
        for miner_id, response in responses.items():
            self.sybil_detection.record_response(
                miner_id=miner_id,
                response=response,
                timestamp=datetime.now()
            )
        
        # 2. Update miner reputation
        reputation_updates = {}
        for miner_id, response in responses.items():
            # Convert vulnerabilities to vulnerability scores
            vulnerability_scores = []
            if hasattr(response, 'vulnerabilities'):
                for vuln in response.vulnerabilities:
                    score = VulnerabilityScore(
                        severity=getattr(vuln, 'severity', 5.0),
                        complexity=getattr(vuln, 'complexity', 5.0),
                        uniqueness=getattr(vuln, 'uniqueness', 5.0),
                        confirmation=1,
                        is_false_positive=False  # Determined later via consensus
                    )
                    vulnerability_scores.append(score)
            
            # Update reputation
            updated_score = self.reputation_system.update_reputation(
                miner_id=miner_id,
                vulnerability_scores=vulnerability_scores
            )
            reputation_updates[miner_id] = updated_score
        
        # 3. Generate vulnerability report
        report = self.report_generator.generate_report(
            project_name=f"Analysis_{query_id}",
            miner_responses=responses,
            miner_weights=miner_weights
        )
        
        # Save detailed HTML report
        html_report_path = self.report_generator.save_html_report(report)
        
        # 4. Calculate rewards using reputation scores
        reputation_scores = self.reputation_system.get_all_scores()
        total_reward = self.config.get('rewards', {}).get('total_reward', 10.0)  # Total reward amount
        raw_rewards = self.reputation_system.calculate_rewards(
            total_reward=total_reward,
            participation_threshold=self.config.get('rewards', {}).get('participation_threshold', 0.1)
        )
        
        # 5. Adjust rewards based on Sybil detection
        adjusted_rewards = self.sybil_detection.adjust_rewards(raw_rewards)
        
        # Generate comprehensive result
        result = {
            "query_id": query_id,
            "timestamp": datetime.now().isoformat(),
            "miner_count": len(responses),
            "sybil_groups_detected": len(sybil_groups),
            "sybil_groups": [list(group) for group in sybil_groups],
            "reputation_updates": reputation_updates,
            "vulnerability_report": {
                "report_id": report.report_id,
                "total_findings": report.statistics["consensus_stats"]["total_findings"],
                "severity_counts": report.statistics["severity_counts"],
                "security_score": report.overall_security_score,
                "report_path": html_report_path
            },
            "rewards": {
                "raw_rewards": raw_rewards,
                "adjusted_rewards": adjusted_rewards
            }
        }
        
        return result
    
    def run_benchmark_test(self, 
                          miner_endpoints: Dict[str, Any],
                          vulnerability_types: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Run benchmark tests on miners for specific vulnerability types.
        
        Args:
            miner_endpoints: Dictionary mapping miner IDs to their endpoints
            vulnerability_types: Optional list of vulnerability types to test
            
        Returns:
            Dictionary containing the benchmark results and report
        """
        # Run the benchmark
        results = self.benchmark_system.run_benchmark(
            suite_name="Default Vulnerability Test Suite",
            miner_endpoints=miner_endpoints,
            vulnerability_types=vulnerability_types
        )
        
        # Generate benchmark report
        report = self.benchmark_system.generate_benchmark_report(
            vulnerability_type=vulnerability_types[0] if vulnerability_types and len(vulnerability_types) == 1 else None
        )
        
        # Save HTML report
        html_report_path = ""
        try:
            html_report = self.benchmark_system.generate_html_report(report)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = os.path.join(self.base_path, "benchmarks", f"benchmark_report_{timestamp}.html")
            
            with open(output_path, 'w') as f:
                f.write(html_report)
            
            html_report_path = output_path
        except Exception as e:
            self.logger.error(f"Error saving HTML benchmark report: {e}")
        
        return {
            "timestamp": datetime.now().isoformat(),
            "vulnerability_types": vulnerability_types or report.get("vulnerability_types", []),
            "miners_tested": list(miner_endpoints.keys()),
            "results_by_type": {vuln_type: [r.to_dict() for r in type_results] 
                               for vuln_type, type_results in results.items()},
            "report_summary": report.get("summary", {}),
            "html_report_path": html_report_path
        }
    
    def register_miner(self, 
                      miner_id: str, 
                      wallet_address: str, 
                      stake_amount: float) -> Tuple[bool, str]:
        """
        Register a new miner with Sybil protection checks.
        
        Args:
            miner_id: Unique identifier for the miner
            wallet_address: The blockchain wallet address of the miner
            stake_amount: Amount of stake provided by the miner
            
        Returns:
            Tuple of (success, message)
        """
        # Check if registration is allowed
        success, message = self.sybil_protection.can_register_miner(
            wallet_address=wallet_address,
            miner_id=miner_id,
            stake_amount=stake_amount
        )
        
        if not success:
            self.logger.warning(f"Miner registration rejected: {message}")
            return success, message
        
        # Register in Sybil protection system
        success, message = self.sybil_protection.register_miner(
            wallet_address=wallet_address,
            miner_id=miner_id,
            stake_amount=stake_amount
        )
        
        if success:
            # Register in Sybil detection system
            self.sybil_detection.register_miner(
                miner_id=miner_id,
                wallet_address=wallet_address
            )
            
            # Register in reputation system
            self.reputation_system.register_miner(miner_id)
            
            self.logger.info(f"Miner {miner_id} registered successfully")
        
        return success, message
    
    def _ensure_benchmark_suite(self) -> None:
        """Ensure that the default benchmark suite exists."""
        if not self.benchmark_system.benchmark_suites:
            # Create default benchmark suite if none exists
            self.benchmark_system.create_default_benchmark_suite()
            self.logger.info("Created default vulnerability benchmark suite")
    
    def save_state(self) -> bool:
        """
        Save the current state of all components.
        
        Returns:
            True if successful
        """
        try:
            # State saving is handled internally by each component
            # We just log a message
            self.logger.info("Saved subnet state")
            return True
        except Exception as e:
            self.logger.error(f"Error saving subnet state: {e}")
            return False


# Factory function to create Bitsec subnet integration
def create_bitsec_subnet(config: Optional[Dict[str, Any]] = None) -> BitsecSubnet:
    """
    Create a BitsecSubnet integration instance with the given config.
    
    Args:
        config: Configuration dictionary for the subnet
        
    Returns:
        BitsecSubnet instance
    """
    return BitsecSubnet(config) 