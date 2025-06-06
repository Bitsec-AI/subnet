/**
 *Submitted for verification at Etherscan.io on 2020-11-06
 */

/**
 *Submitted for verification at Etherscan.io on 2020-06-03
 */

/*
   ____            __   __        __   _
  / __/__ __ ___  / /_ / /  ___  / /_ (_)__ __
 _\ \ / // // _ \/ __// _ \/ -_)/ __// / \ \ /
/___/ \_, //_//_/\__//_//_/\__/ \__//_/ /_\_\
     /___/

* Staking Rewards for Balancer SNX/USDC Liquidity Providers 0x815f8ef4863451f4faf34fbc860034812e7377d9
* 
* Synthetix: StakingRewards.sol
*
* Latest source (may be newer): https://github.com/Synthetixio/synthetix/blob/master/contracts/StakingRewards.sol
* Docs: https://docs.synthetix.io/contracts/StakingRewards
*
* Contract Dependencies: 
*	- Owned
*	- ReentrancyGuard
*	- RewardsDistributionRecipient
*	- TokenWrapper
* Libraries: 
*	- Address
*	- Math
*	- SafeERC20
*	- SafeMath
*
* MIT License
* ===========
*
* Copyright (c) 2020 Synthetix
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in all
* copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
*/

/* ===============================================
 * Flattened with Solidifier by Coinage
 *
 * https://solidifier.coina.ge
 * ===============================================
 */

pragma solidity ^0.5.0;

/**
 * @dev Standard math utilities missing in the Solidity language.
 */
library Math {
    /**
     * @dev Returns the largest of two numbers.
     */
    function max(uint256 a, uint256 b) internal pure returns (uint256) {
        return a >= b ? a : b;
    }

    /**
     * @dev Returns the smallest of two numbers.
     */
    function min(uint256 a, uint256 b) internal pure returns (uint256) {
        return a < b ? a : b;
    }

    /**
     * @dev Returns the average of two numbers. The result is rounded towards
     * zero.
     */
    function average(uint256 a, uint256 b) internal pure returns (uint256) {
        // (a + b) / 2 can overflow, so we distribute
        return (a / 2) + (b / 2) + (((a % 2) + (b % 2)) / 2);
    }
}

/**
 * @dev Wrappers over Solidity's arithmetic operations with added overflow
 * checks.
 *
 * Arithmetic operations in Solidity wrap on overflow. This can easily result
 * in bugs, because programmers usually assume that an overflow raises an
 * error, which is the standard behavior in high level programming languages.
 * `SafeMath` restores this intuition by reverting the transaction when an
 * operation overflows.
 *
 * Using this library instead of the unchecked operations eliminates an entire
 * class of bugs, so it's recommended to use it always.
 */
library SafeMath {
    /**
     * @dev Returns the addition of two unsigned integers, reverting on
     * overflow.
     *
     * Counterpart to Solidity's `+` operator.
     *
     * Requirements:
     * - Addition cannot overflow.
     */
    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a + b;
        require(c >= a, "SafeMath: addition overflow");

        return c;
    }

    /**
     * @dev Returns the subtraction of two unsigned integers, reverting on
     * overflow (when the result is negative).
     *
     * Counterpart to Solidity's `-` operator.
     *
     * Requirements:
     * - Subtraction cannot overflow.
     */
    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
        require(b <= a, "SafeMath: subtraction overflow");
        uint256 c = a - b;

        return c;
    }

    /**
     * @dev Returns the multiplication of two unsigned integers, reverting on
     * overflow.
     *
     * Counterpart to Solidity's `*` operator.
     *
     * Requirements:
     * - Multiplication cannot overflow.
     */
    function mul(uint256 a, uint256 b) internal pure returns (uint256) {
        // Gas optimization: this is cheaper than requiring 'a' not being zero, but the
        // benefit is lost if 'b' is also tested.
        // See: https://github.com/OpenZeppelin/openzeppelin-solidity/pull/522
        if (a == 0) {
            return 0;
        }

        uint256 c = a * b;
        require(c / a == b, "SafeMath: multiplication overflow");

        return c;
    }

    /**
     * @dev Returns the integer division of two unsigned integers. Reverts on
     * division by zero. The result is rounded towards zero.
     *
     * Counterpart to Solidity's `/` operator. Note: this function uses a
     * `revert` opcode (which leaves remaining gas untouched) while Solidity
     * uses an invalid opcode to revert (consuming all remaining gas).
     *
     * Requirements:
     * - The divisor cannot be zero.
     */
    function div(uint256 a, uint256 b) internal pure returns (uint256) {
        // Solidity only automatically asserts when dividing by 0
        require(b > 0, "SafeMath: division by zero");
        uint256 c = a / b;
        // assert(a == b * c + a % b); // There is no case in which this doesn't hold

        return c;
    }

    /**
     * @dev Returns the remainder of dividing two unsigned integers. (unsigned integer modulo),
     * Reverts when dividing by zero.
     *
     * Counterpart to Solidity's `%` operator. This function uses a `revert`
     * opcode (which leaves remaining gas untouched) while Solidity uses an
     * invalid opcode to revert (consuming all remaining gas).
     *
     * Requirements:
     * - The divisor cannot be zero.
     */
    function mod(uint256 a, uint256 b) internal pure returns (uint256) {
        require(b != 0, "SafeMath: modulo by zero");
        return a % b;
    }
}

/**
 * @dev Contract module that helps prevent reentrant calls to a function.
 *
 * Inheriting from `ReentrancyGuard` will make the `nonReentrant` modifier
 * available, which can be aplied to functions to make sure there are no nested
 * (reentrant) calls to them.
 *
 * Note that because there is a single `nonReentrant` guard, functions marked as
 * `nonReentrant` may not call one another. This can be worked around by making
 * those functions `private`, and then adding `external` `nonReentrant` entry
 * points to them.
 */
contract ReentrancyGuard {
    /// @dev counter to allow mutex lock with only one SSTORE operation
    uint256 private _guardCounter;

    constructor() internal {
        // The counter starts at one to prevent changing it from zero to a non-zero
        // value, which is a more expensive operation.
        _guardCounter = 1;
    }

    /**
     * @dev Prevents a contract from calling itself, directly or indirectly.
     * Calling a `nonReentrant` function from another `nonReentrant`
     * function is not supported. It is possible to prevent this from happening
     * by making the `nonReentrant` function external, and make it call a
     * `private` function that does the actual work.
     */
    modifier nonReentrant() {
        _guardCounter += 1;
        uint256 localCounter = _guardCounter;
        _;
        require(
            localCounter == _guardCounter,
            "ReentrancyGuard: reentrant call"
        );
    }
}

interface IERC20 {
    // ERC20 Optional Views
    function name() external view returns (string memory);

    function symbol() external view returns (string memory);

    function decimals() external view returns (uint8);

    // Views
    function totalSupply() external view returns (uint256);

    function balanceOf(address owner) external view returns (uint256);

    function allowance(address owner, address spender)
        external
        view
        returns (uint256);

    // Mutative functions
    function transfer(address to, uint256 value) external returns (bool);

    function approve(address spender, uint256 value) external returns (bool);

    function transferFrom(
        address from,
        address to,
        uint256 value
    ) external returns (bool);

    // Events
    event Transfer(address indexed from, address indexed to, uint256 value);

    event Approval(
        address indexed owner,
        address indexed spender,
        uint256 value
    );
}

interface IMakerPriceFeed {
    function read() external view returns (bytes32);
}

/**
 * @dev Collection of functions related to the address type,
 */
library Address {
    /**
     * @dev Returns true if `account` is a contract.
     *
     * This test is non-exhaustive, and there may be false-negatives: during the
     * execution of a contract's constructor, its address will be reported as
     * not containing a contract.
     *
     * > It is unsafe to assume that an address for which this function returns
     * false is an externally-owned account (EOA) and not a contract.
     */
    function isContract(address account) internal view returns (bool) {
        // This method relies in extcodesize, which returns 0 for contracts in
        // construction, since the code is only stored at the end of the
        // constructor execution.

        uint256 size;
        // solhint-disable-next-line no-inline-assembly
        assembly {
            size := extcodesize(account)
        }
        return size > 0;
    }
}

library SafeERC20 {
    using SafeMath for uint256;
    using Address for address;

    function safeTransfer(
        IERC20 token,
        address to,
        uint256 value
    ) internal {
        callOptionalReturn(
            token,
            abi.encodeWithSelector(token.transfer.selector, to, value)
        );
    }

    function safeTransferFrom(
        IERC20 token,
        address from,
        address to,
        uint256 value
    ) internal {
        callOptionalReturn(
            token,
            abi.encodeWithSelector(token.transferFrom.selector, from, to, value)
        );
    }

    function safeApprove(
        IERC20 token,
        address spender,
        uint256 value
    ) internal {
        // safeApprove should only be called when setting an initial allowance,
        // or when resetting it to zero. To increase and decrease it, use
        // 'safeIncreaseAllowance' and 'safeDecreaseAllowance'
        // solhint-disable-next-line max-line-length
        require(
            (value == 0) || (token.allowance(address(this), spender) == 0),
            "SafeERC20: approve from non-zero to non-zero allowance"
        );
        callOptionalReturn(
            token,
            abi.encodeWithSelector(token.approve.selector, spender, value)
        );
    }

    function safeIncreaseAllowance(
        IERC20 token,
        address spender,
        uint256 value
    ) internal {
        uint256 newAllowance =
            token.allowance(address(this), spender).add(value);
        callOptionalReturn(
            token,
            abi.encodeWithSelector(
                token.approve.selector,
                spender,
                newAllowance
            )
        );
    }

    function safeDecreaseAllowance(
        IERC20 token,
        address spender,
        uint256 value
    ) internal {
        uint256 newAllowance =
            token.allowance(address(this), spender).sub(value);
        callOptionalReturn(
            token,
            abi.encodeWithSelector(
                token.approve.selector,
                spender,
                newAllowance
            )
        );
    }

    /**
     * @dev Imitates a Solidity high-level call (i.e. a regular function call to a contract), relaxing the requirement
     * on the return value: the return value is optional (but if data is returned, it must not be false).
     * @param token The token targeted by the call.
     * @param data The call data (encoded using abi.encode or one of its variants).
     */
    function callOptionalReturn(IERC20 token, bytes memory data) private {
        // We need to perform a low level call here, to bypass Solidity's return data size checking mechanism, since
        // we're implementing it ourselves.

        // A Solidity high level call has three parts:
        //  1. The target address is checked to verify it contains contract code
        //  2. The call itself is made, and success asserted
        //  3. The return value is decoded, which in turn checks the size of the returned data.
        // solhint-disable-next-line max-line-length
        require(address(token).isContract(), "SafeERC20: call to non-contract");

        // solhint-disable-next-line avoid-low-level-calls
        (bool success, bytes memory returndata) = address(token).call(data);
        require(success, "SafeERC20: low-level call failed");

        if (returndata.length > 0) {
            // Return data is optional
            // solhint-disable-next-line max-line-length
            require(
                abi.decode(returndata, (bool)),
                "SafeERC20: ERC20 operation did not succeed"
            );
        }
    }
}

// https://docs.synthetix.io/contracts/Owned
contract Owned {
    address public owner;
    address public nominatedOwner;

    constructor(address _owner) public {
        require(_owner != address(0), "Owner address cannot be 0");
        owner = _owner;
        emit OwnerChanged(address(0), _owner);
    }

    function nominateNewOwner(address _owner) external onlyOwner {
        nominatedOwner = _owner;
        emit OwnerNominated(_owner);
    }

    function acceptOwnership() external {
        require(
            msg.sender == nominatedOwner,
            "You must be nominated before you can accept ownership"
        );
        emit OwnerChanged(owner, nominatedOwner);
        owner = nominatedOwner;
        nominatedOwner = address(0);
    }

    modifier onlyOwner {
        require(
            msg.sender == owner,
            "Only the contract owner may perform this action"
        );
        _;
    }

    event OwnerNominated(address newOwner);
    event OwnerChanged(address oldOwner, address newOwner);
}

// Inheritance

// https://docs.synthetix.io/contracts/RewardsDistributionRecipient
contract RewardsDistributionRecipient is Owned {
    address public rewardsDistribution;

    function notifyRewardAmount(uint256 reward) external;

    modifier onlyRewardsDistribution() {
        require(
            msg.sender == rewardsDistribution,
            "Caller is not RewardsDistribution contract"
        );
        _;
    }

    function setRewardsDistribution(address _rewardsDistribution)
        external
        onlyOwner
    {
        rewardsDistribution = _rewardsDistribution;
    }
}

contract TokenWrapper is ReentrancyGuard {
    using SafeMath for uint256;
    using SafeERC20 for IERC20;

    IERC20 public stakingToken;

    uint256 private _totalSupply;
    mapping(address => uint256) private _balances;

    constructor(address _stakingToken) public {
        stakingToken = IERC20(_stakingToken);
    }

    function totalSupply() public view returns (uint256) {
        return _totalSupply;
    }

    function balanceOf(address account) public view returns (uint256) {
        return _balances[account];
    }

    function stake(uint256 amount) public nonReentrant {
        _totalSupply = _totalSupply.add(amount);
        _balances[msg.sender] = _balances[msg.sender].add(amount);
        stakingToken.safeTransferFrom(msg.sender, address(this), amount);
    }

    function withdraw(uint256 amount) public nonReentrant {
        _totalSupply = _totalSupply.sub(amount);
        _balances[msg.sender] = _balances[msg.sender].sub(amount);
        stakingToken.safeTransfer(msg.sender, amount);
    }
}

// This contract was taking directly from a synthetix reward program.
// Any adjustments will have an altered comment

contract StakingRewards is TokenWrapper, RewardsDistributionRecipient {
    IERC20 public rewardsToken;

    uint256 public duration; // Altered : allows for variable participation windows
    uint256 public periodFinish = 0;
    uint256 public rewardRate = 0;
    uint256 public lastUpdateTime;
    uint256 public rewardPerTokenStored;
    mapping(address => uint256) public userRewardPerTokenPaid;
    mapping(address => uint256) public rewards;

    event RewardAdded(uint256 reward);
    event Staked(address indexed user, uint256 amount);
    event Withdrawn(address indexed user, uint256 amount);
    event RewardPaid(address indexed user, uint256 reward);

    constructor(
        address _owner,
        address _rewardsToken,
        address _stakingToken,
        uint256 _duration
    ) public TokenWrapper(_stakingToken) Owned(_owner) {
        duration = _duration; // Altered : allows for variable participation windows
        rewardsToken = IERC20(_rewardsToken);
    }

    modifier updateReward(address account) {
        rewardPerTokenStored = rewardPerToken();
        lastUpdateTime = lastTimeRewardApplicable();
        if (account != address(0)) {
            rewards[account] = earned(account);
            userRewardPerTokenPaid[account] = rewardPerTokenStored;
        }
        _;
    }

    function lastTimeRewardApplicable() public view returns (uint256) {
        return Math.min(block.timestamp, periodFinish);
    }

    function rewardPerToken() public view returns (uint256) {
        if (totalSupply() == 0) {
            return rewardPerTokenStored;
        }
        return
            rewardPerTokenStored.add(
                lastTimeRewardApplicable()
                    .sub(lastUpdateTime)
                    .mul(rewardRate)
                    .mul(1e18)
                    .div(totalSupply())
            );
    }

    function earned(address account) public view returns (uint256) {
        return
            balanceOf(account)
                .mul(rewardPerToken().sub(userRewardPerTokenPaid[account]))
                .div(1e18)
                .add(rewards[account]);
    }

    // stake visibility is public as overriding LPTokenWrapper's stake() function
    function stake(uint256 amount) public updateReward(msg.sender) {
        require(amount > 0, "Cannot stake 0");
        super.stake(amount);
        emit Staked(msg.sender, amount);
    }

    function withdraw(uint256 amount) public updateReward(msg.sender) {
        require(amount > 0, "Cannot withdraw 0");
        super.withdraw(amount);
        emit Withdrawn(msg.sender, amount);
    }

    function exit() external {
        withdraw(balanceOf(msg.sender));
        getReward();
    }

    function getReward() public updateReward(msg.sender) {
        uint256 reward = earned(msg.sender);
        if (reward > 0) {
            rewards[msg.sender] = 0;
            rewardsToken.safeTransfer(msg.sender, reward);
            emit RewardPaid(msg.sender, reward);
        }
    }

    function notifyRewardAmount(uint256 reward)
        external
        onlyRewardsDistribution
        updateReward(address(0))
    {
        if (block.timestamp >= periodFinish) {
            rewardRate = reward.div(duration); // altered to allow variable durations
        } else {
            uint256 remaining = periodFinish.sub(block.timestamp);
            uint256 leftover = remaining.mul(rewardRate);
            rewardRate = reward.add(leftover).div(duration); // altered to allow variable durations
        }
        lastUpdateTime = block.timestamp;
        periodFinish = block.timestamp.add(duration); // altered to allow variable durations
        emit RewardAdded(reward);
    }
}

contract EthereumStakingRewardsScript is StakingRewards {
    constructor()
        public
        StakingRewards(
            0xF7396C708Ad9127B6684b7fd690083158d2ebdE5, // _owner = TeamToastMultsig
            0x6B175474E89094C44Da98b954EedeAC495271d0F, // _rewardsToken = DAI
            0xcD1d5fF929E2B69BBD351CF31057E9a70eC76291, // _stakingToken = FRYETHUniswapLPToken,
            30 days
        ) // _duration = 30 days
    {}
}

contract EthereumUnifiedStakingRewardsScript is StakingRewards {
    constructor()
        public
        StakingRewards(
            0xF7396C708Ad9127B6684b7fd690083158d2ebdE5, // _owner = TeamToastMultsig
            0x6B175474E89094C44Da98b954EedeAC495271d0F, // _rewardsToken = DAI
            0x04a1f9f9fE8910A27972E15d5Da3Bf79075fEfbb, // _stakingToken = FRY-DAI-dEth Balancer liquidity,
            30 days
        ) // _duration = 30 days
    {}
}

contract BSCStakingRewardsScript is StakingRewards {
    constructor()
        public
        StakingRewards(
            0xF7396C708Ad9127B6684b7fd690083158d2ebdE5, // _owner = team toast address
            0x1AF3F329e8BE154074D8769D1FFa4eE058B1DBc3, // _rewardsToken = DAI
            0xe71C65Eb18faB7c8DD99598973fd8FA18570fb01, // _stakingToken = FRYBNBCakeLPToken,
            30 days
        ) // _duration = 30 days
    {}
}

contract MaticStakingRewardsScript is StakingRewards {
    constructor()
        public
        StakingRewards(
            0xF7396C708Ad9127B6684b7fd690083158d2ebdE5, // _owner = TeamToastMultsig
            0x8f3Cf7ad23Cd3CaDbD9735AFf958023239c6A063, // _rewardsToken = DAI (on matic)
            0x661A67Cb1773669604Ebb95aac63fF31e0F7dc25, // _stakingToken = FRYMATICUniswapLPToken,
            30 days
        ) // _duration = 30 days
    {}
}

contract IUniswap {
    function getReserves()
        public
        view
        returns (
            uint112 _reserve0,
            uint112 _reserve1,
            uint32 _blockTimestampLast
        );
}

contract QueryBalancerDAIPoolScript 
{
    using SafeMath for uint256;

    constructor() public {}

    // assumes a Balancer XYZ_ETH pair, where XYZ is reserve0
    function getData(
        StakingRewards _rewards,
        // --- Leaving these here so that the contract interface need not change ---
        uint _rewardsRefReserve,
        IUniswap _pricePair,
        uint _pricePairRefReserve,
        // -- end of comment ---
        address _staker
    )
        public
        view
        returns (
            uint _availableBalance,
            uint _stakedBalance,
            uint _allowedBalance,
            uint _earned,
            uint _totalStakedValue,
            uint _APY,
            uint _rewardRate,
            uint _timestamp // rewards per second
        )
    {
        _availableBalance = _rewards.stakingToken().balanceOf(_staker);
        _stakedBalance = _rewards.balanceOf(_staker);
        _allowedBalance = _rewards
            .stakingToken()
            .allowance(_staker,address(_rewards));
        _earned = _rewards.earned(_staker);
        _rewardRate = _rewards.rewardRate();
        _timestamp = now;
            
        _totalStakedValue = getStakedValue(_rewards);

        _APY = _totalStakedValue == 0 ? 
            0 :
            _rewardRate
                .mul(365 days)
                .mul(10**18)
                .div(_totalStakedValue); /* */

        _rewardRate = _rewards.totalSupply() == 0 ?
            0 :
            _rewardRate
                .mul(_stakedBalance)
                .div(_rewards.totalSupply());
    }
    
    function getStakedValue(StakingRewards _rewards)
        public
        view
        returns (uint _totalStakedValue)
    {
        // goal:
        // 1. return the amount of DAI staked via the pool multiplied by 3
        // logic:
        // *get the DAI in the pool
        // *get the pool tokens staked
        // *mul DAI in pool by % of pool tokens staked mul by 3

        uint daiInPool = 
            IERC20(0x6B175474E89094C44Da98b954EedeAC495271d0F)
            .balanceOf(address(_rewards.rewardsToken));
        _totalStakedValue = 
            IERC20(address(_rewards.rewardsToken))
            .totalSupply()
            .mul(10**18) // 10^18 for precision
            .div(_rewards.totalSupply())
            .mul(daiInPool)
            .mul(3) // because the DAI is one 3rd of the pool 
            .div(10**18); // remove the excessive 10^18 precision
    }
}

contract QueryScript {
    using SafeMath for uint256;

    constructor() public {}

    // assumes a Uniswap XYZ_ETH pair, where XYZ is reserve0
    function getData(
        StakingRewards _rewards,
        uint _rewardsRefReserve,
        IUniswap _pricePair,
        uint _pricePairRefReserve,
        address _staker
    )
        public
        view
        returns (
            uint _availableBalance,
            uint _stakedBalance,
            uint _allowedBalance,
            uint _earned,
            uint _totalStakedValue,
            uint _APY,
            uint _rewardRate,
            uint _timestamp // rewards per second
        )
    {
        _availableBalance = _rewards.stakingToken().balanceOf(_staker);
        _stakedBalance = _rewards.balanceOf(_staker);
        _allowedBalance = _rewards
            .stakingToken()
            .allowance(_staker,address(_rewards));
        _earned = _rewards.earned(_staker);
        _rewardRate = _rewards.rewardRate();
        _timestamp = now;
            
        _totalStakedValue = getStakedValue(_rewards, _rewardsRefReserve, _pricePair, _pricePairRefReserve);

        _APY = _totalStakedValue == 0 ? 
            0 :
            _rewardRate
                .mul(365 days)
                .mul(10**18)
                .div(_totalStakedValue); /* */

        _rewardRate = _rewards.totalSupply() == 0 ?
            0 :
            _rewardRate
                .mul(_stakedBalance)
                .div(_rewards.totalSupply());
    }
    
    function getStakedValue(
            StakingRewards _rewards, 
            uint _rewardsRefReserve, 
            IUniswap _pricePair, 
            uint _pricePairRefReserve)
        public
        view
        returns (uint _totalStakedValue)
    {
        IUniswap stakingToken = IUniswap(address(_rewards.stakingToken()));
        
        uint fryPrice = getTokenPairPrice(_pricePair, _pricePairRefReserve)
            .mul(10**18)
            .div(getTokenPairPrice(stakingToken, _rewardsRefReserve));
            
        _totalStakedValue = fryPrice
            .mul(getReserve(stakingToken, _rewardsRefReserve));
            
        _totalStakedValue = _totalStakedValue 
            .mul(10**18) // add precision before dividing
            .div(_rewards.stakingToken().totalSupply())
            .mul(_rewards.totalSupply())
            .div(10**18) // remove precision after dividing
            .div(10**18) // remove prevision from fryPrice 
            .mul(2); // mul by two to get the value of both sides of the pair
    }
    
    function getBiggerReserve(IUniswap _tokenPair)
        public
        view
        returns (uint _reserve)
    {
        (uint reserve0, uint reserve1, ) = _tokenPair.getReserves();
        _reserve = Math.max(reserve0, reserve1);
    }
    
    function getReserve(IUniswap _tokenPair, uint _reserve)
        public
        view
        returns (uint _reserveAmount)
    {
        (uint reserve0, uint reserve1, ) = _tokenPair.getReserves();
        _reserveAmount = _reserve == 0 ?
            reserve0 : 
            reserve1;
    }
    

    function getTokenPairPrice(IUniswap _tokenPair, uint reserve)
        public
        view
        returns (uint _price)
    {
        (uint reserve0, uint reserve1, ) = _tokenPair.getReserves();
        _price = reserve == 0 ?
            reserve0.mul(10**18).div(reserve1) :
            reserve1.mul(10**18).div(reserve0);
    }
}