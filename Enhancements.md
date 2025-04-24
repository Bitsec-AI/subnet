# Bitsec Subnet Enhancement

## Overview

This repository contains enhanced architecture for the Bitsec subnet, which leverages blockchain and AI technologies for secure, performant, and decentralized vulnerability detection in smart contracts and code. The enhancements focus on improving the subnet's incentive mechanism, Sybil resistance, report generation, and benchmarking.

## Architecture Enhancements

### 1. Reputation-Based Scoring System

A sophisticated reputation system tracks miner performance over time and rewards miners based on:
- Detection accuracy and precision
- Consistency of results
- Uniqueness of findings (discovering vulnerabilities others miss)
- Severity of detected vulnerabilities

This system ensures fair reward distribution and incentivizes miners to provide high-quality analysis rather than superficial or erroneous detections.

### 2. Advanced Sybil Resistance

The subnet now includes robust defenses against Sybil attacks through:
- Dynamic analysis of response patterns
- Temporal coordination detection (identifying synchronized submissions)
- Graph-based community detection for identifying collusion
- Wallet diversity requirements and registration limits
- Stake-weighted penalties for detected Sybil groups

These mechanisms ensure that a coordinated group of miners cannot manipulate the network or monopolize rewards.

### 3. Comprehensive Vulnerability Reporting

Enhanced vulnerability reporting provides:
- Consensus-based aggregation of findings from multiple miners
- Detailed vulnerability categorization with severity scoring
- Rich HTML reports with visualization of findings
- Miner contribution metrics for transparency
- Security scoring for assessed code

This system provides actionable intelligence from collective miner outputs, creating a more valuable service for end-users.

### 4. Benchmarking System for Different Vulnerability Types

A standardized benchmarking system allows:
- Evaluation of miner performance across different vulnerability types
- Standardized test suites for common vulnerabilities
- Comparative performance metrics (precision, recall, F1 score)
- Performance visualization for different vulnerability categories
- Time-based performance tracking

This component helps miners improve their detection capabilities and gives subnet validators insights into miner specializations.

## Implementation Details

The enhanced subnet consists of several interconnected components:

1. **Reputation System (`bitsec/reputation.py`)**
   - Tracks miner performance metrics
   - Calculates weighted scores based on multiple factors
   - Distributes rewards proportionally to reputation scores

2. **Sybil Detection & Protection (`bitsec/security/sybil_detection.py`)**
   - Analyzes response patterns to detect coordination
   - Implements wallet diversity requirements
   - Applies penalties to detected Sybil groups

3. **Vulnerability Report Generator (`bitsec/reporting/vulnerability_report.py`)**
   - Consolidates findings from multiple miners
   - Applies consensus mechanisms to filter false positives
   - Generates comprehensive HTML reports with visualizations

4. **Vulnerability Benchmark System (`bitsec/benchmarking/vulnerability_benchmark.py`)**
   - Standardized test cases for different vulnerability types
   - Performance metrics for different vulnerability categories
   - Comparative analysis of miner strengths and weaknesses

5. **Integration Module (`bitsec/integration.py`)**
   - Combines all components into a cohesive system
   - Manages miner registration and response processing
   - Provides unified API for subnet operations

## Getting Started

### Prerequisites

- Python 3.8+
- Bittensor SDK
- Required dependencies (install via `pip install -r requirements.txt`)

### Installation

```bash
# Clone the repository
git clone https://github.com/Bitsec-AI/subnet.git
cd subnet

# Install dependencies
pip install -r requirements.txt

# Install the package
pip install -e .
```

### Running Tests

```bash
# Run the test suite
pytest
```

### Running a Miner

```bash
python neurons/miner.py --wallet.name <your-wallet-name> --wallet.hotkey <your-hotkey-name>
```

### Running a Validator

```bash
python neurons/validator.py --wallet.name <your-wallet-name> --wallet.hotkey <your-hotkey-name>
```

## Benefits of Enhanced Architecture

1. **Fairer Reward Distribution**
   - Miners are rewarded based on the quality of their work, not just participation
   - Specialized expertise in specific vulnerability types is properly rewarded

2. **Increased Sybil Resistance**
   - Multiple layers of detection make coordinated attacks harder
   - Economic disincentives for Sybil attackers

3. **Higher Quality Results**
   - Consensus mechanisms filter out false positives
   - Comprehensive reports provide actionable information

4. **Benchmark-Driven Improvement**
   - Miners can focus on improving detection for specific vulnerability types
   - Subnet as a whole improves through targeted benchmarking

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
