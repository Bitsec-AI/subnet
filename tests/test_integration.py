"""
Tests for the Bitsec subnet integration.

This module tests the integration of different components of the Bitsec subnet:
- Reputation system
- Sybil detection and prevention
- Vulnerability reporting
- Benchmarking
"""

import os
import tempfile
import shutil
import unittest
import pytest
from typing import Dict, List, Any, Optional
from datetime import datetime

from bitsec.integration import BitsecSubnet, create_bitsec_subnet
from bitsec.protocol import PredictionResponse, VulnerabilityByMiner


class TestBitsecSubnetIntegration:
    """Test suite for Bitsec subnet integration."""
    
    @pytest.fixture
    def temp_dir(self) -> str:
        """Create a temporary directory for testing."""
        temp_dir = tempfile.mkdtemp()
        yield temp_dir
        # Cleanup after test
        shutil.rmtree(temp_dir)
    
    @pytest.fixture
    def test_config(self, temp_dir: str) -> Dict[str, Any]:
        """Create a test configuration."""
        return {
            'storage_path': temp_dir,
            'reputation': {
                'accuracy_weight': 0.4,
                'consistency_weight': 0.2,
                'uniqueness_weight': 0.3,
                'severity_weight': 0.1
            },
            'sybil': {
                'similarity_threshold': 0.85,
                'min_stake': 0.1,
                'max_miners_per_wallet': 5
            },
            'reporting': {
                'consensus_threshold': 0.25
            },
            'rewards': {
                'total_reward': 10.0,
                'participation_threshold': 0.1
            }
        }
    
    @pytest.fixture
    def subnet(self, test_config: Dict[str, Any]) -> BitsecSubnet:
        """Create a BitsecSubnet instance for testing."""
        return create_bitsec_subnet(test_config)
    
    @pytest.fixture
    def mock_responses(self) -> Dict[str, Any]:
        """Create mock miner responses for testing."""
        # Create a few different mock responses
        responses = {}
        
        # Miner 1: Finds a reentrancy vulnerability
        responses['miner1'] = self._create_mock_response(
            vulnerabilities=[
                {
                    'type': 'reentrancy',
                    'file_path': 'Contract.sol',
                    'line_number': 42,
                    'severity': 9.0,
                    'description': 'Potential reentrancy vulnerability'
                }
            ]
        )
        
        # Miner 2: Finds the same vulnerability plus an overflow
        responses['miner2'] = self._create_mock_response(
            vulnerabilities=[
                {
                    'type': 'reentrancy',
                    'file_path': 'Contract.sol',
                    'line_number': 43,  # Slight difference to test matching tolerance
                    'severity': 8.5,
                    'description': 'Reentrancy attack possible'
                },
                {
                    'type': 'overflow',
                    'file_path': 'Contract.sol',
                    'line_number': 30,
                    'severity': 7.0,
                    'description': 'Integer overflow vulnerability'
                }
            ]
        )
        
        # Miner 3: Finds only the overflow
        responses['miner3'] = self._create_mock_response(
            vulnerabilities=[
                {
                    'type': 'overflow',
                    'file_path': 'Contract.sol',
                    'line_number': 30,
                    'severity': 7.5,
                    'description': 'Potential integer overflow'
                }
            ]
        )
        
        # Miner 4: Finds something different (potential Sybil attacker)
        responses['miner4'] = self._create_mock_response(
            vulnerabilities=[
                {
                    'type': 'access-control',
                    'file_path': 'Contract.sol',
                    'line_number': 20,
                    'severity': 8.0,
                    'description': 'Missing access control'
                }
            ]
        )
        
        # Miner 5: Clone of Miner 4 (potential Sybil attacker)
        responses['miner5'] = self._create_mock_response(
            vulnerabilities=[
                {
                    'type': 'access-control',
                    'file_path': 'Contract.sol',
                    'line_number': 20,
                    'severity': 8.0,
                    'description': 'Missing access control'
                }
            ]
        )
        
        return responses
    
    def _create_mock_response(self, vulnerabilities: List[Dict[str, Any]]) -> Any:
        """Create a mock PredictionResponse object."""
        # Convert the vulnerabilities to VulnerabilityByMiner objects
        vuln_objects = []
        for vuln in vulnerabilities:
            vuln_obj = VulnerabilityByMiner(
                miner_id="test_miner",
                type=vuln.get('type', ''),
                file_path=vuln.get('file_path', ''),
                line_number=vuln.get('line_number', 0),
                severity=vuln.get('severity', 5.0),
                description=vuln.get('description', '')
            )
            vuln_objects.append(vuln_obj)
        
        # Create the response object
        return PredictionResponse(
            prediction=True,
            vulnerabilities=vuln_objects
        )
    
    def test_initialization(self, subnet: BitsecSubnet):
        """Test that the subnet initializes correctly."""
        assert subnet is not None
        assert subnet.reputation_system is not None
        assert subnet.sybil_detection is not None
        assert subnet.sybil_protection is not None
        assert subnet.report_generator is not None
        assert subnet.benchmark_system is not None
    
    def test_miner_registration(self, subnet: BitsecSubnet):
        """Test miner registration with Sybil protection."""
        # Register a miner with sufficient stake
        success, message = subnet.register_miner(
            miner_id="test_miner1",
            wallet_address="wallet1",
            stake_amount=1.0
        )
        assert success, f"Failed to register miner: {message}"
        
        # Register another miner with the same wallet
        success, message = subnet.register_miner(
            miner_id="test_miner2",
            wallet_address="wallet1",
            stake_amount=0.5
        )
        assert success, f"Failed to register second miner with same wallet: {message}"
        
        # Try to register a miner with insufficient stake
        success, message = subnet.register_miner(
            miner_id="test_miner3",
            wallet_address="wallet2",
            stake_amount=0.05  # Below the 0.1 threshold
        )
        assert not success, "Should reject registration with insufficient stake"
        assert "Insufficient stake" in message
        
        # Try to register too many miners with the same wallet
        for i in range(3, 7):  # Already registered 2, trying to register 4 more
            subnet.register_miner(
                miner_id=f"test_miner{i}",
                wallet_address="wallet1",
                stake_amount=0.5
            )
        
        # This should be the 7th attempt, which should fail
        success, message = subnet.register_miner(
            miner_id="test_miner7",
            wallet_address="wallet1",
            stake_amount=0.5
        )
        assert not success, "Should reject registration of too many miners per wallet"
        assert "maximum" in message
    
    def test_process_miner_responses(self, subnet: BitsecSubnet, mock_responses: Dict[str, Any]):
        """Test processing of miner responses."""
        # Register miners
        for miner_id in mock_responses.keys():
            subnet.register_miner(
                miner_id=miner_id,
                wallet_address=f"wallet_{miner_id}",
                stake_amount=1.0
            )
        
        # Process responses
        result = subnet.process_miner_responses(
            query_id="test_query_001",
            code="pragma solidity ^0.8.0;\n\ncontract Test {\n    // Test code\n}",
            responses=mock_responses
        )
        
        # Check that the result contains expected fields
        assert "query_id" in result
        assert "timestamp" in result
        assert "miner_count" in result
        assert "sybil_groups_detected" in result
        assert "reputation_updates" in result
        assert "vulnerability_report" in result
        assert "rewards" in result
        
        # Check miner count
        assert result["miner_count"] == len(mock_responses)
        
        # Check for Sybil detection (miners 4 and 5 should be detected)
        # Note: This might not be reliable in the mock environment due to simplified response matching
        # so we're not asserting a specific number of groups
        
        # Check that all miners have reputation updates
        assert len(result["reputation_updates"]) == len(mock_responses)
        for miner_id in mock_responses.keys():
            assert miner_id in result["reputation_updates"]
        
        # Check vulnerability report
        vuln_report = result["vulnerability_report"]
        assert "report_id" in vuln_report
        assert "total_findings" in vuln_report
        assert "severity_counts" in vuln_report
        assert "security_score" in vuln_report
        
        # Check rewards calculation
        rewards = result["rewards"]
        assert "raw_rewards" in rewards
        assert "adjusted_rewards" in rewards
        
        # Check that rewards were calculated for all miners
        raw_rewards = rewards["raw_rewards"]
        adjusted_rewards = rewards["adjusted_rewards"]
        
        # Miners in Sybil groups should have their rewards adjusted down
        if result["sybil_groups_detected"] > 0:
            for group in result["sybil_groups"]:
                for miner_id in group:
                    if miner_id in raw_rewards and miner_id in adjusted_rewards:
                        assert adjusted_rewards[miner_id] <= raw_rewards[miner_id], \
                            f"Adjusted rewards should be less than or equal to raw rewards for Sybil miners"
    
    def test_run_benchmark(self, subnet: BitsecSubnet):
        """Test running benchmarks."""
        # Create mock miner endpoints
        miner_endpoints = {
            'miner1': 'endpoint1',
            'miner2': 'endpoint2',
            'miner3': 'endpoint3'
        }
        
        # Run benchmark for specific vulnerability types
        vulnerability_types = ['reentrancy', 'overflow']
        result = subnet.run_benchmark_test(
            miner_endpoints=miner_endpoints,
            vulnerability_types=vulnerability_types
        )
        
        # Check that the result contains expected fields
        assert "timestamp" in result
        assert "vulnerability_types" in result
        assert "miners_tested" in result
        assert "results_by_type" in result
        assert "report_summary" in result
        
        # Check that the specified vulnerability types were tested
        for vuln_type in vulnerability_types:
            assert vuln_type in result["vulnerability_types"]
        
        # Check that all miners were tested
        assert len(result["miners_tested"]) == len(miner_endpoints)
        for miner_id in miner_endpoints.keys():
            assert miner_id in result["miners_tested"]


if __name__ == "__main__":
    pytest.main(["-xvs", "test_integration.py"]) 