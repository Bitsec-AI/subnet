"""
Sybil attack detection and prevention for the Bitsec subnet.

This module provides tools to detect and prevent Sybil attacks where a group of
miners might try to collude to manipulate the network and reward distribution.
"""

import numpy as np
import logging
from typing import Dict, List, Set, Tuple, Optional, Any
import time
from datetime import datetime, timedelta
import networkx as nx
from collections import defaultdict
import json
import os
from pathlib import Path

class SybilDetection:
    """
    System for detecting potential Sybil attacks on the network.
    
    The system uses multiple indicators to identify potential coordinated behavior among miners:
    1. Response similarity analysis
    2. Temporal response patterns
    3. On-chain wallet analysis
    4. Network pattern analysis
    5. Statistical outlier detection
    """
    
    def __init__(self, 
                 storage_path: Optional[str] = None,
                 similarity_threshold: float = 0.85,
                 temporal_window: int = 50,
                 consecutive_matches_threshold: int = 5,
                 ip_history_size: int = 100):
        """
        Initialize the Sybil detection system.
        
        Args:
            storage_path: Path to store Sybil detection data
            similarity_threshold: Threshold to consider responses as suspiciously similar
            temporal_window: Number of responses to analyze for temporal patterns
            consecutive_matches_threshold: Number of consecutive similar responses to trigger alert
            ip_history_size: Size of IP address history to maintain per miner
        """
        # Configuration parameters
        self.similarity_threshold = similarity_threshold
        self.temporal_window = temporal_window
        self.consecutive_matches_threshold = consecutive_matches_threshold
        self.ip_history_size = ip_history_size
        
        # Data storage
        if storage_path:
            self.storage_path = Path(storage_path)
        else:
            self.storage_path = Path(os.path.expanduser("~/.bitsec/sybil"))
        
        self.storage_path.mkdir(parents=True, exist_ok=True)
        
        # Data structures
        self.miner_response_history: Dict[str, List[Any]] = defaultdict(list)
        self.miner_temporal_data: Dict[str, List[datetime]] = defaultdict(list)
        self.miner_ip_addresses: Dict[str, List[str]] = defaultdict(list)
        self.wallet_to_miners: Dict[str, Set[str]] = defaultdict(set)
        self.miner_to_wallet: Dict[str, str] = {}
        self.similarity_graph = nx.Graph()
        self.sybil_groups: List[Set[str]] = []
        self.penalized_miners: Set[str] = set()
        
        # Load existing data
        self._load_detection_data()
        
        # Set up logging
        self.logger = logging.getLogger("bitsec.sybil_detection")
    
    def register_miner(self, miner_id: str, wallet_address: str, ip_address: Optional[str] = None) -> None:
        """
        Register a new miner and associate with wallet address.
        
        Args:
            miner_id: Unique identifier for the miner
            wallet_address: The blockchain wallet address associated with the miner
            ip_address: The IP address of the miner (if available)
        """
        # Associate miner with wallet
        self.wallet_to_miners[wallet_address].add(miner_id)
        self.miner_to_wallet[miner_id] = wallet_address
        
        # Initialize data structures for this miner
        if miner_id not in self.miner_response_history:
            self.miner_response_history[miner_id] = []
        
        if miner_id not in self.miner_temporal_data:
            self.miner_temporal_data[miner_id] = []
        
        # Add IP address if provided
        if ip_address:
            self._update_ip_address(miner_id, ip_address)
        
        # Add node to similarity graph
        if not self.similarity_graph.has_node(miner_id):
            self.similarity_graph.add_node(miner_id)
        
        self.logger.info(f"Registered miner {miner_id} with wallet {wallet_address}")
    
    def record_response(self, 
                        miner_id: str, 
                        response: Any, 
                        timestamp: Optional[datetime] = None,
                        ip_address: Optional[str] = None) -> None:
        """
        Record a miner's response for later Sybil detection analysis.
        
        Args:
            miner_id: Unique identifier for the miner
            response: The miner's response to a query
            timestamp: Time when the response was received (defaults to now)
            ip_address: IP address from which the response came (if available)
        """
        current_time = timestamp or datetime.now()
        
        # Update miner response history
        self.miner_response_history[miner_id].append(response)
        if len(self.miner_response_history[miner_id]) > self.temporal_window:
            self.miner_response_history[miner_id] = self.miner_response_history[miner_id][-self.temporal_window:]
        
        # Update temporal data
        self.miner_temporal_data[miner_id].append(current_time)
        if len(self.miner_temporal_data[miner_id]) > self.temporal_window:
            self.miner_temporal_data[miner_id] = self.miner_temporal_data[miner_id][-self.temporal_window:]
        
        # Update IP address if provided
        if ip_address:
            self._update_ip_address(miner_id, ip_address)
    
    def analyze_responses(self, query_id: str, responses: Dict[str, Any]) -> List[Set[str]]:
        """
        Analyze a batch of responses to detect potential Sybil attacks.
        
        Args:
            query_id: Identifier for the query that generated these responses
            responses: Dictionary mapping miner IDs to their responses
            
        Returns:
            List of sets of miner IDs that appear to be coordinating
        """
        self.logger.info(f"Analyzing {len(responses)} responses for query {query_id}")
        
        # Perform similarity analysis between pairs of responses
        for miner1_id, response1 in responses.items():
            for miner2_id, response2 in responses.items():
                if miner1_id != miner2_id:
                    similarity = self._calculate_response_similarity(response1, response2)
                    
                    # If responses are suspiciously similar, update the similarity graph
                    if similarity > self.similarity_threshold:
                        self.logger.debug(f"High similarity ({similarity}) between {miner1_id} and {miner2_id}")
                        
                        # Add or update edge weight in the similarity graph
                        if self.similarity_graph.has_edge(miner1_id, miner2_id):
                            # Increase weight of existing edge
                            current_weight = self.similarity_graph[miner1_id][miner2_id].get('weight', 1)
                            self.similarity_graph[miner1_id][miner2_id]['weight'] = current_weight + 1
                        else:
                            # Create new edge with weight 1
                            self.similarity_graph.add_edge(miner1_id, miner2_id, weight=1)
        
        # Look for clusters in the similarity graph
        self._identify_sybil_groups()
        
        # Update detection data
        self._save_detection_data()
        
        return self.sybil_groups
    
    def _calculate_response_similarity(self, response1: Any, response2: Any) -> float:
        """
        Calculate similarity between two responses.
        
        This is a simplified version. For real implementation, consider:
        - Comparing vulnerability findings (locations, types, etc.)
        - Using NLP techniques to compare textual parts of responses
        - Using domain-specific similarity metrics
        
        Args:
            response1: First miner's response
            response2: Second miner's response
            
        Returns:
            Similarity score between 0 and 1
        """
        # Basic implementation using Jaccard similarity
        # This should be expanded based on the actual response structure
        
        try:
            # Extract vulnerabilities from responses
            if hasattr(response1, 'vulnerabilities') and hasattr(response2, 'vulnerabilities'):
                vuln1 = set([(v.type, v.line_number, v.severity) for v in response1.vulnerabilities])
                vuln2 = set([(v.type, v.line_number, v.severity) for v in response2.vulnerabilities])
                
                # Calculate Jaccard similarity
                if not vuln1 and not vuln2:
                    return 0.5  # Both empty, moderate similarity
                
                intersection = len(vuln1.intersection(vuln2))
                union = len(vuln1.union(vuln2))
                
                return intersection / union if union > 0 else 0.0
            
            # Fallback for when format is unknown
            return 0.5
            
        except Exception as e:
            self.logger.error(f"Error calculating response similarity: {e}")
            return 0.0
    
    def _identify_sybil_groups(self) -> None:
        """
        Identify groups of miners that may be part of a Sybil attack.
        
        This uses graph community detection algorithms to find clusters
        of miners with highly similar responses.
        """
        # Clear previous results
        self.sybil_groups = []
        
        # Filter the graph to only include edges with sufficient weight
        filtered_graph = nx.Graph()
        
        for u, v, data in self.similarity_graph.edges(data=True):
            weight = data.get('weight', 0)
            if weight >= self.consecutive_matches_threshold:
                filtered_graph.add_edge(u, v, weight=weight)
        
        # Find communities in the filtered graph
        if filtered_graph.number_of_edges() > 0:
            # Use Louvain community detection algorithm
            try:
                communities = nx.community.louvain_communities(filtered_graph)
                
                # Filter to only include communities with more than one miner
                potential_sybil_groups = [comm for comm in communities if len(comm) > 1]
                
                # Further analyze each potential group
                for group in potential_sybil_groups:
                    # Check if miners in the group share a wallet
                    wallets = {self.miner_to_wallet.get(miner_id) for miner_id in group if miner_id in self.miner_to_wallet}
                    
                    # If all miners share a single wallet, this is expected behavior
                    if len(wallets) == 1:
                        continue
                    
                    # Check for temporal coordination
                    if self._check_temporal_coordination(group):
                        self.sybil_groups.append(group)
                        self.logger.warning(f"Detected potential Sybil group: {group}")
            
            except Exception as e:
                self.logger.error(f"Error in community detection: {e}")
    
    def _check_temporal_coordination(self, miner_group: Set[str]) -> bool:
        """
        Check if a group of miners shows coordinated timing patterns.
        
        Args:
            miner_group: Set of miner IDs to check
            
        Returns:
            True if temporal coordination is detected
        """
        # Get timestamps for each miner in the group
        all_timestamps = {}
        
        for miner_id in miner_group:
            if miner_id in self.miner_temporal_data:
                all_timestamps[miner_id] = self.miner_temporal_data[miner_id]
        
        # Skip if we don't have enough data
        if len(all_timestamps) < 2:
            return False
        
        # Calculate the mean time difference between consecutive responses for each miner
        time_patterns = {}
        
        for miner_id, timestamps in all_timestamps.items():
            if len(timestamps) < 3:
                continue
                
            # Calculate differences between consecutive timestamps
            diffs = [(timestamps[i+1] - timestamps[i]).total_seconds() 
                     for i in range(len(timestamps)-1)]
            
            if diffs:
                time_patterns[miner_id] = np.mean(diffs)
        
        # Skip if we don't have enough patterns
        if len(time_patterns) < 2:
            return False
        
        # Check if time patterns are suspiciously similar
        values = list(time_patterns.values())
        mean_pattern = np.mean(values)
        std_pattern = np.std(values)
        
        # If standard deviation is very small relative to the mean,
        # this suggests coordinated timing
        if std_pattern > 0 and mean_pattern > 0:
            coordination_score = std_pattern / mean_pattern
            return coordination_score < 0.1  # Threshold for suspicious coordination
        
        return False
    
    def _update_ip_address(self, miner_id: str, ip_address: str) -> None:
        """
        Update the IP address history for a miner.
        
        Args:
            miner_id: Unique identifier for the miner
            ip_address: The IP address to record
        """
        # Add to the list, maintaining history limit
        if ip_address not in self.miner_ip_addresses[miner_id]:
            self.miner_ip_addresses[miner_id].append(ip_address)
            
        if len(self.miner_ip_addresses[miner_id]) > self.ip_history_size:
            self.miner_ip_addresses[miner_id] = self.miner_ip_addresses[miner_id][-self.ip_history_size:]
    
    def adjust_rewards(self, rewards: Dict[str, float]) -> Dict[str, float]:
        """
        Adjust rewards based on Sybil detection.
        
        Applies penalties to miners that appear to be part of Sybil attacks.
        
        Args:
            rewards: Dictionary mapping miner IDs to their calculated rewards
            
        Returns:
            Adjusted rewards after applying Sybil penalties
        """
        # Collect all miners in detected Sybil groups
        sybil_miners = set()
        for group in self.sybil_groups:
            sybil_miners.update(group)
        
        # Update the set of penalized miners
        self.penalized_miners = sybil_miners
        
        # Apply penalties to rewards
        adjusted_rewards = rewards.copy()
        
        if sybil_miners:
            # Calculate penalty factor for each Sybil miner
            # More severe for larger groups
            for miner_id in sybil_miners:
                if miner_id in adjusted_rewards:
                    # Find which group this miner belongs to
                    group_size = 0
                    for group in self.sybil_groups:
                        if miner_id in group:
                            group_size = len(group)
                            break
                    
                    # Calculate penalty - more severe for larger groups
                    penalty_factor = max(0.1, 1.0 - (0.1 * group_size))
                    
                    # Apply penalty
                    adjusted_rewards[miner_id] *= penalty_factor
            
            self.logger.info(f"Applied Sybil penalties to {len(sybil_miners)} miners")
        
        return adjusted_rewards
    
    def get_sybil_groups(self) -> List[Set[str]]:
        """
        Get the currently detected Sybil groups.
        
        Returns:
            List of sets of miner IDs that appear to be coordinating
        """
        return self.sybil_groups
    
    def get_sybil_report(self) -> Dict[str, Any]:
        """
        Generate a comprehensive report on Sybil detection.
        
        Returns:
            Dictionary containing Sybil detection report data
        """
        # Collect all miners in detected Sybil groups
        sybil_miners = set()
        for group in self.sybil_groups:
            sybil_miners.update(group)
        
        # Generate report
        report = {
            "timestamp": datetime.now().isoformat(),
            "sybil_groups_count": len(self.sybil_groups),
            "sybil_miners_count": len(sybil_miners),
            "sybil_groups": [list(group) for group in self.sybil_groups],
            "penalized_miners": list(self.penalized_miners),
        }
        
        return report
    
    def _save_detection_data(self) -> None:
        """Save Sybil detection data to disk."""
        # Convert graph to serializable format
        graph_data = {
            "nodes": list(self.similarity_graph.nodes()),
            "edges": [(u, v, data.get("weight", 1)) 
                      for u, v, data in self.similarity_graph.edges(data=True)]
        }
        
        data = {
            "sybil_groups": [list(group) for group in self.sybil_groups],
            "penalized_miners": list(self.penalized_miners),
            "similarity_graph": graph_data,
            "wallet_to_miners": {wallet: list(miners) 
                                for wallet, miners in self.wallet_to_miners.items()},
            "miner_to_wallet": self.miner_to_wallet,
        }
        
        try:
            with open(self.storage_path / "sybil_detection.json", "w") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            self.logger.error(f"Failed to save Sybil detection data: {e}")
    
    def _load_detection_data(self) -> None:
        """Load Sybil detection data from disk."""
        try:
            if (self.storage_path / "sybil_detection.json").exists():
                with open(self.storage_path / "sybil_detection.json", "r") as f:
                    data = json.load(f)
                
                # Load Sybil groups
                self.sybil_groups = [set(group) for group in data.get("sybil_groups", [])]
                
                # Load penalized miners
                self.penalized_miners = set(data.get("penalized_miners", []))
                
                # Load wallet mappings
                self.wallet_to_miners = {
                    wallet: set(miners) 
                    for wallet, miners in data.get("wallet_to_miners", {}).items()
                }
                
                self.miner_to_wallet = data.get("miner_to_wallet", {})
                
                # Rebuild the similarity graph
                graph_data = data.get("similarity_graph", {"nodes": [], "edges": []})
                
                # Add nodes
                for node in graph_data["nodes"]:
                    self.similarity_graph.add_node(node)
                
                # Add edges with weights
                for u, v, weight in graph_data["edges"]:
                    self.similarity_graph.add_edge(u, v, weight=weight)
                
        except Exception as e:
            self.logger.error(f"Failed to load Sybil detection data: {e}")

class SybilProtection:
    """
    System for protecting against Sybil attacks on the network.
    
    This class implements various countermeasures to minimize the effectiveness of Sybil attacks:
    1. Dynamic registration requirements
    2. Proof of work/stake challenges
    3. Registration rate limiting
    4. Wallet diversity requirements
    """
    
    def __init__(self,
                 min_stake: float = 0.1,
                 max_miners_per_wallet: int = 5,
                 registration_cooldown: int = 3600,  # 1 hour in seconds
                 proof_of_work_difficulty: int = 3):
        """
        Initialize the Sybil protection system.
        
        Args:
            min_stake: Minimum stake required per miner
            max_miners_per_wallet: Maximum miners allowed per wallet
            registration_cooldown: Cooldown period between registrations (seconds)
            proof_of_work_difficulty: Difficulty level for PoW challenges
        """
        self.min_stake = min_stake
        self.max_miners_per_wallet = max_miners_per_wallet
        self.registration_cooldown = registration_cooldown
        self.proof_of_work_difficulty = proof_of_work_difficulty
        
        # Data structures
        self.wallet_miners: Dict[str, Set[str]] = defaultdict(set)
        self.miner_registration_times: Dict[str, datetime] = {}
        self.wallet_registration_times: Dict[str, List[datetime]] = defaultdict(list)
        
        # Set up logging
        self.logger = logging.getLogger("bitsec.sybil_protection")
    
    def can_register_miner(self, 
                          wallet_address: str, 
                          miner_id: str, 
                          stake_amount: float) -> Tuple[bool, str]:
        """
        Check if a miner can be registered under a wallet.
        
        Args:
            wallet_address: The blockchain wallet address for registration
            miner_id: Unique identifier for the new miner
            stake_amount: Amount of stake provided for this miner
            
        Returns:
            Tuple of (allowed, reason) where allowed is a boolean and
            reason is a string explanation
        """
        current_time = datetime.now()
        
        # Check minimum stake requirement
        if stake_amount < self.min_stake:
            return False, f"Insufficient stake: {stake_amount} < {self.min_stake}"
        
        # Check miners per wallet limit
        if (wallet_address in self.wallet_miners and 
            len(self.wallet_miners[wallet_address]) >= self.max_miners_per_wallet):
            return False, f"Wallet has reached the maximum of {self.max_miners_per_wallet} miners"
        
        # Check wallet registration cooldown
        recent_registrations = [
            t for t in self.wallet_registration_times[wallet_address]
            if (current_time - t).total_seconds() < self.registration_cooldown
        ]
        
        if recent_registrations:
            last_registration = max(recent_registrations)
            cooldown_remaining = self.registration_cooldown - (current_time - last_registration).total_seconds()
            
            if cooldown_remaining > 0:
                return False, f"Registration cooldown: wait {int(cooldown_remaining)} seconds"
        
        # All checks passed
        return True, "Registration allowed"
    
    def register_miner(self, 
                      wallet_address: str, 
                      miner_id: str, 
                      stake_amount: float) -> Tuple[bool, str]:
        """
        Register a new miner under a wallet.
        
        Args:
            wallet_address: The blockchain wallet address for registration
            miner_id: Unique identifier for the new miner
            stake_amount: Amount of stake provided for this miner
            
        Returns:
            Tuple of (success, message) where success is a boolean and
            message is a string explanation
        """
        # Check if registration is allowed
        allowed, reason = self.can_register_miner(wallet_address, miner_id, stake_amount)
        
        if not allowed:
            return False, reason
        
        # Record registration
        current_time = datetime.now()
        self.wallet_miners[wallet_address].add(miner_id)
        self.miner_registration_times[miner_id] = current_time
        self.wallet_registration_times[wallet_address].append(current_time)
        
        # Clean up old registration times
        self._cleanup_registration_times()
        
        self.logger.info(f"Registered miner {miner_id} under wallet {wallet_address}")
        return True, "Miner registered successfully"
    
    def unregister_miner(self, miner_id: str, wallet_address: str) -> Tuple[bool, str]:
        """
        Unregister a miner.
        
        Args:
            miner_id: Unique identifier for the miner to unregister
            wallet_address: The blockchain wallet address that owns the miner
            
        Returns:
            Tuple of (success, message) where success is a boolean and
            message is a string explanation
        """
        # Check if the miner exists and belongs to the wallet
        if (miner_id not in self.miner_registration_times or 
            wallet_address not in self.wallet_miners or
            miner_id not in self.wallet_miners[wallet_address]):
            return False, "Miner not found or does not belong to the specified wallet"
        
        # Remove miner
        self.wallet_miners[wallet_address].remove(miner_id)
        if not self.wallet_miners[wallet_address]:
            del self.wallet_miners[wallet_address]
            
        del self.miner_registration_times[miner_id]
        
        self.logger.info(f"Unregistered miner {miner_id} from wallet {wallet_address}")
        return True, "Miner unregistered successfully"
    
    def _cleanup_registration_times(self) -> None:
        """Clean up old registration time records."""
        current_time = datetime.now()
        cutoff_time = current_time - timedelta(seconds=self.registration_cooldown * 2)
        
        for wallet, times in list(self.wallet_registration_times.items()):
            # Keep only recent registrations
            self.wallet_registration_times[wallet] = [
                t for t in times if t > cutoff_time
            ]
            
            # Remove empty entries
            if not self.wallet_registration_times[wallet]:
                del self.wallet_registration_times[wallet]
    
    def generate_pow_challenge(self, wallet_address: str) -> Dict[str, Any]:
        """
        Generate a proof-of-work challenge for new registrations.
        
        Args:
            wallet_address: The blockchain wallet address requesting registration
            
        Returns:
            Dictionary containing the challenge details
        """
        # A simple challenge - find a nonce that, when hashed with the wallet address,
        # produces a hash with a certain number of leading zeros
        import hashlib
        import random
        
        challenge = {
            "type": "proof_of_work",
            "wallet_address": wallet_address,
            "timestamp": time.time(),
            "random_seed": random.randint(0, 1000000),
            "difficulty": self.proof_of_work_difficulty,
            "target": "0" * self.proof_of_work_difficulty  # Target is N leading zeros
        }
        
        return challenge
    
    def verify_pow_solution(self, challenge: Dict[str, Any], nonce: str) -> bool:
        """
        Verify a solution to a proof-of-work challenge.
        
        Args:
            challenge: The challenge dictionary
            nonce: The proposed solution
            
        Returns:
            True if the solution is valid
        """
        import hashlib
        
        # Recreate the hash
        challenge_string = f"{challenge['wallet_address']}{challenge['timestamp']}{challenge['random_seed']}{nonce}"
        solution_hash = hashlib.sha256(challenge_string.encode()).hexdigest()
        
        # Check if hash meets the difficulty requirement
        return solution_hash.startswith(challenge["target"])
    
    def get_registration_info(self, wallet_address: str) -> Dict[str, Any]:
        """
        Get registration information for a wallet.
        
        Args:
            wallet_address: The blockchain wallet address
            
        Returns:
            Dictionary containing registration information
        """
        current_time = datetime.now()
        
        miners = list(self.wallet_miners.get(wallet_address, set()))
        recent_registrations = [
            t for t in self.wallet_registration_times.get(wallet_address, [])
            if (current_time - t).total_seconds() < self.registration_cooldown * 2
        ]
        
        return {
            "wallet_address": wallet_address,
            "registered_miners_count": len(miners),
            "registered_miners": miners,
            "max_miners_allowed": self.max_miners_per_wallet,
            "recent_registrations": [t.isoformat() for t in recent_registrations],
            "cooldown_active": bool(recent_registrations)
        } 