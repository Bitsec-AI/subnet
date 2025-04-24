"""
Reputation-based scoring system for evaluating miner performance in vulnerability detection.

This module implements an advanced reputation system that tracks miner performance over time
and calculates scores based on multiple factors to inform reward distribution.
"""

import numpy as np
import pandas as pd
import logging
from typing import Dict, List, Optional, Tuple, Set, Union
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import json
import os
from pathlib import Path

@dataclass
class VulnerabilityScore:
    """
    Data class for scoring a vulnerability detection.
    
    Attributes:
        severity: Severity level of the vulnerability (0-10)
        complexity: Complexity of finding the vulnerability (0-10)
        uniqueness: How rare this type of finding is among miners (0-10)
        confirmation: Number of miners who found the same vulnerability
        is_false_positive: Whether the detection was a false positive
    """
    severity: float = 5.0
    complexity: float = 5.0
    uniqueness: float = 5.0
    confirmation: int = 1
    is_false_positive: bool = False

@dataclass
class MinerReputation:
    """
    Data class for tracking a miner's reputation over time.
    
    Attributes:
        miner_id: Unique identifier for the miner
        total_submissions: Total number of submissions by this miner
        correct_findings: Number of correct vulnerability detections
        false_positives: Number of false positive detections
        unique_findings: Number of unique vulnerabilities found first by this miner
        avg_severity: Average severity of vulnerabilities found
        recent_scores: List of recent reputation scores
        last_updated: Timestamp of the last update
    """
    miner_id: str
    total_submissions: int = 0
    correct_findings: int = 0
    false_positives: int = 0
    unique_findings: int = 0
    avg_severity: float = 0.0
    recent_scores: List[float] = field(default_factory=list)
    historical_scores: Dict[str, float] = field(default_factory=dict)
    last_updated: datetime = field(default_factory=datetime.now)
    
    @property
    def accuracy(self) -> float:
        """Calculate the miner's accuracy rate."""
        if self.total_submissions == 0:
            return 0.0
        return self.correct_findings / self.total_submissions if self.total_submissions > 0 else 0
    
    @property
    def false_positive_rate(self) -> float:
        """Calculate the miner's false positive rate."""
        if self.total_submissions == 0:
            return 0.0
        return self.false_positives / self.total_submissions if self.total_submissions > 0 else 0
    
    @property
    def current_score(self) -> float:
        """Get the current reputation score."""
        if not self.recent_scores:
            return 0.0
        return self.recent_scores[-1]

class ReputationSystem:
    """
    System for tracking and calculating miner reputation scores.
    
    This class manages the reputation of all miners in the network,
    updating scores based on their performance and using these scores
    to inform the reward distribution mechanism.
    """
    
    def __init__(self, 
                 storage_path: Optional[str] = None,
                 accuracy_weight: float = 0.4,
                 consistency_weight: float = 0.2,
                 uniqueness_weight: float = 0.3,
                 severity_weight: float = 0.1,
                 history_window: int = 100,
                 decay_factor: float = 0.95):
        """
        Initialize the reputation system.
        
        Args:
            storage_path: Path to store reputation data
            accuracy_weight: Weight for accuracy in score calculation
            consistency_weight: Weight for consistency in score calculation
            uniqueness_weight: Weight for finding unique vulnerabilities
            severity_weight: Weight for finding severe vulnerabilities
            history_window: Number of recent submissions to consider
            decay_factor: Factor for time-based score decay
        """
        self.miners: Dict[str, MinerReputation] = {}
        self.accuracy_weight = accuracy_weight
        self.consistency_weight = consistency_weight
        self.uniqueness_weight = uniqueness_weight
        self.severity_weight = severity_weight
        self.history_window = history_window
        self.decay_factor = decay_factor
        
        # Set up storage
        if storage_path:
            self.storage_path = Path(storage_path)
        else:
            self.storage_path = Path(os.path.expanduser("~/.bitsec/reputation"))
        
        self.storage_path.mkdir(parents=True, exist_ok=True)
        self._load_reputation_data()
        
        # Set up logging
        self.logger = logging.getLogger("bitsec.reputation")
    
    def register_miner(self, miner_id: str) -> None:
        """
        Register a new miner in the reputation system.
        
        Args:
            miner_id: Unique identifier for the miner
        """
        if miner_id not in self.miners:
            self.miners[miner_id] = MinerReputation(miner_id=miner_id)
            self.logger.info(f"Registered new miner: {miner_id}")
    
    def update_reputation(self, 
                          miner_id: str, 
                          vulnerability_scores: List[VulnerabilityScore],
                          timestamp: Optional[datetime] = None) -> float:
        """
        Update a miner's reputation based on their most recent submission.
        
        Args:
            miner_id: Unique identifier for the miner
            vulnerability_scores: Scores for each vulnerability found
            timestamp: Time of the submission (defaults to now)
            
        Returns:
            The updated reputation score
        """
        if miner_id not in self.miners:
            self.register_miner(miner_id)
        
        miner = self.miners[miner_id]
        current_time = timestamp or datetime.now()
        
        # Update submission counts
        miner.total_submissions += 1
        
        # Calculate scores for this submission
        correct_count = 0
        false_positive_count = 0
        total_severity = 0.0
        
        for vuln_score in vulnerability_scores:
            if not vuln_score.is_false_positive:
                correct_count += 1
                total_severity += vuln_score.severity
                
                # If this vulnerability is highly unique, count it as a unique finding
                if vuln_score.uniqueness > 8.0:
                    miner.unique_findings += 1
            else:
                false_positive_count += 1
        
        # Update miner stats
        miner.correct_findings += correct_count
        miner.false_positives += false_positive_count
        
        # Update average severity
        if correct_count > 0:
            new_avg_severity = total_severity / correct_count
            miner.avg_severity = ((miner.avg_severity * (miner.correct_findings - correct_count)) + 
                                  total_severity) / miner.correct_findings
        
        # Calculate score components
        accuracy_score = self._calculate_accuracy_score(miner)
        consistency_score = self._calculate_consistency_score(miner)
        uniqueness_score = self._calculate_uniqueness_score(miner)
        severity_score = self._calculate_severity_score(miner)
        
        # Calculate overall score
        score = (
            self.accuracy_weight * accuracy_score +
            self.consistency_weight * consistency_score +
            self.uniqueness_weight * uniqueness_score +
            self.severity_weight * severity_score
        )
        
        # Apply time decay to older scores
        if miner.recent_scores:
            miner.recent_scores = [s * self.decay_factor for s in miner.recent_scores]
        
        # Add new score to history
        miner.recent_scores.append(score)
        
        # Keep only the most recent scores within the history window
        if len(miner.recent_scores) > self.history_window:
            miner.recent_scores = miner.recent_scores[-self.history_window:]
        
        # Add timestamp to historical record
        date_str = current_time.strftime("%Y-%m-%d")
        miner.historical_scores[date_str] = score
        
        # Update last updated timestamp
        miner.last_updated = current_time
        
        # Save reputation data
        self._save_reputation_data()
        
        return score
    
    def _calculate_accuracy_score(self, miner: MinerReputation) -> float:
        """Calculate score component based on detection accuracy."""
        if miner.total_submissions < 5:
            # For new miners with few submissions, give benefit of doubt
            return 0.7
        
        # Penalize for false positives, reward for correct findings
        false_positive_penalty = min(0.5, miner.false_positive_rate)
        return max(0, miner.accuracy - false_positive_penalty)
    
    def _calculate_consistency_score(self, miner: MinerReputation) -> float:
        """Calculate score component based on consistency of submissions."""
        if len(miner.recent_scores) < 2:
            return 0.5
        
        # Look at variance in recent scores to measure consistency
        if len(miner.recent_scores) >= 5:
            variance = np.var(miner.recent_scores[-5:])
            return max(0, 1.0 - min(1.0, variance * 2))
        else:
            return 0.5
    
    def _calculate_uniqueness_score(self, miner: MinerReputation) -> float:
        """Calculate score component based on finding unique vulnerabilities."""
        if miner.total_submissions == 0:
            return 0.0
        
        unique_ratio = miner.unique_findings / max(1, miner.correct_findings)
        return min(1.0, unique_ratio * 1.5)  # Boost unique findings
    
    def _calculate_severity_score(self, miner: MinerReputation) -> float:
        """Calculate score component based on severity of findings."""
        return min(1.0, miner.avg_severity / 10.0)
    
    def get_miner_score(self, miner_id: str) -> float:
        """
        Get the current reputation score for a miner.
        
        Args:
            miner_id: Unique identifier for the miner
            
        Returns:
            The current reputation score, or 0 if miner not found
        """
        if miner_id not in self.miners:
            return 0.0
        
        miner = self.miners[miner_id]
        return miner.current_score
    
    def get_all_scores(self) -> Dict[str, float]:
        """
        Get current scores for all miners.
        
        Returns:
            Dictionary mapping miner IDs to their current scores
        """
        return {miner_id: miner.current_score for miner_id, miner in self.miners.items()}
    
    def calculate_rewards(self, 
                         total_reward: float, 
                         participation_threshold: float = 0.1) -> Dict[str, float]:
        """
        Calculate rewards distribution based on reputation scores.
        
        Args:
            total_reward: Total reward amount to distribute
            participation_threshold: Minimum score to receive rewards
            
        Returns:
            Dictionary mapping miner IDs to their reward amounts
        """
        # Get scores for all miners
        scores = self.get_all_scores()
        
        # Filter out miners below participation threshold
        eligible_miners = {
            miner_id: score for miner_id, score in scores.items() 
            if score >= participation_threshold
        }
        
        if not eligible_miners:
            self.logger.warning("No miners eligible for rewards")
            return {}
        
        # Calculate total score sum
        total_score = sum(eligible_miners.values())
        
        # Calculate rewards proportional to scores
        if total_score > 0:
            rewards = {
                miner_id: (score / total_score) * total_reward
                for miner_id, score in eligible_miners.items()
            }
        else:
            # Equal distribution if all scores are 0
            equal_share = total_reward / len(eligible_miners)
            rewards = {miner_id: equal_share for miner_id in eligible_miners}
        
        return rewards
    
    def _save_reputation_data(self) -> None:
        """Save reputation data to disk."""
        data = {
            miner_id: {
                "total_submissions": miner.total_submissions,
                "correct_findings": miner.correct_findings,
                "false_positives": miner.false_positives,
                "unique_findings": miner.unique_findings,
                "avg_severity": miner.avg_severity,
                "recent_scores": miner.recent_scores,
                "historical_scores": miner.historical_scores,
                "last_updated": miner.last_updated.isoformat()
            }
            for miner_id, miner in self.miners.items()
        }
        
        try:
            with open(self.storage_path / "reputation.json", "w") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            self.logger.error(f"Failed to save reputation data: {e}")
    
    def _load_reputation_data(self) -> None:
        """Load reputation data from disk."""
        try:
            if (self.storage_path / "reputation.json").exists():
                with open(self.storage_path / "reputation.json", "r") as f:
                    data = json.load(f)
                
                for miner_id, miner_data in data.items():
                    miner = MinerReputation(
                        miner_id=miner_id,
                        total_submissions=miner_data.get("total_submissions", 0),
                        correct_findings=miner_data.get("correct_findings", 0),
                        false_positives=miner_data.get("false_positives", 0),
                        unique_findings=miner_data.get("unique_findings", 0),
                        avg_severity=miner_data.get("avg_severity", 0.0),
                        recent_scores=miner_data.get("recent_scores", []),
                        historical_scores=miner_data.get("historical_scores", {}),
                        last_updated=datetime.fromisoformat(miner_data.get("last_updated", datetime.now().isoformat()))
                    )
                    self.miners[miner_id] = miner
        except Exception as e:
            self.logger.error(f"Failed to load reputation data: {e}") 