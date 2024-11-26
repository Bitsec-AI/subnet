// fixed version. imported 11-25-24
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@chainlink/contracts/src/v0.8/vrf/VRFConsumerBase.sol";
import "@openzeppelin/contracts/utils/math/Math.sol";

contract TheRun is ReentrancyGuard, Ownable, VRFConsumerBase {
    using Math for uint256;

    uint256 private balance;
    uint256 private payoutId;
    uint256 private lastPayout;
    uint256 private winningPot;
    uint256 private constant MIN_MULTIPLIER = 1100; // 110%
    uint256 private constant MIN_DEPOSIT = 500 * 10**15; // 0.5 ether
    uint256 private constant MAX_DEPOSIT = 20 ether;
  
    uint256 private fees;
    uint256 private feeFrac = 20; // 2%
    uint256 private constant POT_FRAC = 30; // 3%

    bytes32 internal keyHash;
    uint256 internal fee;
    uint256 public randomResult;

    struct Player {
        address payable addr;
        uint256 payout;
        bool paid;
    }

    Player[] private players;

    event Participated(address indexed player, uint256 deposit, uint256 payout);
    event PayoutMade(address indexed player, uint256 amount);
    event WinningPotWon(address indexed winner, uint256 amount);
    event FeesCollected(uint256 amount);

    constructor(address _vrfCoordinator, address _linkToken, bytes32 _keyHash, uint256 _fee) 
        VRFConsumerBase(_vrfCoordinator, _linkToken)
        Ownable(msg.sender)
    {
        keyHash = _keyHash;
        fee = _fee;
    }

    receive() external payable {
        participate();
    }

    function participate() public payable nonReentrant {
        require(msg.value >= MIN_DEPOSIT, "Deposit too small");
        uint256 deposit = msg.value;
        if (deposit > MAX_DEPOSIT) {
            payable(msg.sender).transfer(deposit - MAX_DEPOSIT);
            deposit = MAX_DEPOSIT;
        }

        uint256 totalMultiplier = MIN_MULTIPLIER;
        if (balance < 1 ether && players.length > 1) {
            totalMultiplier += 100;
        }
        if (players.length % 10 == 0 && players.length > 1) {
            totalMultiplier += 100;
        }

        uint256 payout = deposit * totalMultiplier / 1000;
        players.push(Player(payable(msg.sender), payout, false));

        winningPot += deposit * POT_FRAC / 1000;
        fees += deposit * feeFrac / 1000;
        balance += deposit * (1000 - feeFrac - POT_FRAC) / 1000;

        emit Participated(msg.sender, deposit, payout);

        if (deposit > 1 ether && deposit > players[payoutId].payout) {
            requestRandomness(keyHash, fee);
        }

        processPayouts();
    }

    function processPayouts() private {
        while (payoutId < players.length && balance >= players[payoutId].payout) {
            Player storage player = players[payoutId];
            uint256 payoutAmount = player.payout;
            
            balance -= payoutAmount;
            player.paid = true;
            
            (bool success, ) = player.addr.call{value: payoutAmount}("");
            require(success, "Transfer failed");
            
            emit PayoutMade(player.addr, payoutAmount);
            
            lastPayout = payoutAmount;
            payoutId += 1;
        }
    }

    function fulfillRandomness(bytes32, uint256 randomness) internal override {
        randomResult = randomness % 100 + 1;
        if (randomResult % 10 == 0) {
            Player storage player = players[players.length - 1];
            uint256 winAmount = winningPot;
            winningPot = 0;
            (bool success, ) = player.addr.call{value: winAmount}("");
            require(success, "Winner transfer failed");
            emit WinningPotWon(player.addr, winAmount);
        }
    }

    function collectAllFees() external onlyOwner {
        require(fees > 0, "No fees to collect");
        uint256 amountToSend = fees;
        fees = 0;
        feeFrac = feeFrac > 1 ? feeFrac - 1 : 0;
        (bool success, ) = owner().call{value: amountToSend}("");
        require(success, "Fee transfer failed");
        emit FeesCollected(amountToSend);
    }

    function getAndReduceFeesByFraction(uint256 p) external onlyOwner {
        require(p > 0 && p <= 1000, "Invalid fraction");
        uint256 amountToSend = fees * p / 1000;
        fees -= amountToSend;
        if (fees == 0) {
            feeFrac = feeFrac > 1 ? feeFrac - 1 : 0;
        }
        (bool success, ) = owner().call{value: amountToSend}("");
        require(success, "Fee transfer failed");
        emit FeesCollected(amountToSend);
    }

    function watchBalance() public view returns (uint256) {
        return balance;
    }

    function watchBalanceInEther() public view returns (uint256) {
        return balance / 1 ether;
    }

    function nextPayout() public view returns (uint256) {
        return payoutId < players.length ? players[payoutId].payout : 0;
    }

    function watchFees() public view returns (uint256) {
        return fees;
    }

    function watchWinningPot() public view returns (uint256) {
        return winningPot;
    }

    function watchLastPayout() public view returns (uint256) {
        return lastPayout;
    }

    function totalOfPlayers() public view returns (uint256) {
        return players.length;
    }

    function playerInfo(uint256 id) public view returns (address, uint256, bool) {
        require(id < players.length, "Invalid player id");
        Player storage player = players[id];
        return (player.addr, player.payout, player.paid);
    }

    function payoutQueueSize() public view returns (uint256) {
        return players.length - payoutId;
    }
}