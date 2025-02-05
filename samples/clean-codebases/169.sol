pragma solidity 0.5.17;

interface GAMER {

    function gamersScalingFactor() external view returns (uint256);

    function balanceOfUnderlying(address amount) external returns(uint256);

    function mint(address to, uint256 amount) external;

}

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

        return (a / 2) + (b / 2) + ((a % 2 + b % 2) / 2);

    }

}

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

        return sub(a, b, "SafeMath: subtraction overflow");

    }



    /**

     * @dev Returns the subtraction of two unsigned integers, reverting with custom message on

     * overflow (when the result is negative).

     *

     * Counterpart to Solidity's `-` operator.

     *

     * Requirements:

     * - Subtraction cannot overflow.

     *

     * _Available since v2.4.0._

     */

    function sub(uint256 a, uint256 b, string memory errorMessage) internal pure returns (uint256) {

        require(b <= a, errorMessage);

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

        // See: https://github.com/OpenZeppelin/openzeppelin-contracts/pull/522

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

        return div(a, b, "SafeMath: division by zero");

    }



    /**

     * @dev Returns the integer division of two unsigned integers. Reverts with custom message on

     * division by zero. The result is rounded towards zero.

     *

     * Counterpart to Solidity's `/` operator. Note: this function uses a

     * `revert` opcode (which leaves remaining gas untouched) while Solidity

     * uses an invalid opcode to revert (consuming all remaining gas).

     *

     * Requirements:

     * - The divisor cannot be zero.

     *

     * _Available since v2.4.0._

     */

    function div(uint256 a, uint256 b, string memory errorMessage) internal pure returns (uint256) {

        // Solidity only automatically asserts when dividing by 0

        require(b > 0, errorMessage);

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

        return mod(a, b, "SafeMath: modulo by zero");

    }



    /**

     * @dev Returns the remainder of dividing two unsigned integers. (unsigned integer modulo),

     * Reverts with custom message when dividing by zero.

     *

     * Counterpart to Solidity's `%` operator. This function uses a `revert`

     * opcode (which leaves remaining gas untouched) while Solidity uses an

     * invalid opcode to revert (consuming all remaining gas).

     *

     * Requirements:

     * - The divisor cannot be zero.

     *

     * _Available since v2.4.0._

     */

    function mod(uint256 a, uint256 b, string memory errorMessage) internal pure returns (uint256) {

        require(b != 0, errorMessage);

        return a % b;

    }

}

contract Context {

    // Empty internal constructor, to prevent people from mistakenly deploying

    // an instance of this contract, which should be used via inheritance.

    constructor () internal { }

    // solhint-disable-previous-line no-empty-blocks



    function _msgSender() internal view returns (address payable) {

        return msg.sender;

    }



    function _msgData() internal view returns (bytes memory) {

        this; // silence state mutability warning without generating bytecode - see https://github.com/ethereum/solidity/issues/2691

        return msg.data;

    }

}

contract Ownable is Context {

    address private _owner;



    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);



    /**

     * @dev Initializes the contract setting the deployer as the initial owner.

     */

    constructor () internal {

        _owner = _msgSender();

        emit OwnershipTransferred(address(0), _owner);

    }



    /**

     * @dev Returns the address of the current owner.

     */

    function owner() public view returns (address) {

        return _owner;

    }



    /**

     * @dev Throws if called by any account other than the owner.

     */

    modifier onlyOwner() {

        require(isOwner(), "Ownable: caller is not the owner");

        _;

    }



    /**

     * @dev Returns true if the caller is the current owner.

     */

    function isOwner() public view returns (bool) {

        return _msgSender() == _owner;

    }



    /**

     * @dev Leaves the contract without owner. It will not be possible to call

     * `onlyOwner` functions anymore. Can only be called by the current owner.

     *

     * NOTE: Renouncing ownership will leave the contract without an owner,

     * thereby removing any functionality that is only available to the owner.

     */

    function renounceOwnership() public onlyOwner {

        emit OwnershipTransferred(_owner, address(0));

        _owner = address(0);

    }



    /**

     * @dev Transfers ownership of the contract to a new account (`newOwner`).

     * Can only be called by the current owner.

     */

    function transferOwnership(address newOwner) public onlyOwner {

        _transferOwnership(newOwner);

    }



    /**

     * @dev Transfers ownership of the contract to a new account (`newOwner`).

     */

    function _transferOwnership(address newOwner) internal {

        require(newOwner != address(0), "Ownable: new owner is the zero address");

        emit OwnershipTransferred(_owner, newOwner);

        _owner = newOwner;

    }

}

interface IERC20 {

    /**

     * @dev Returns the amount of tokens in existence.

     */

    function totalSupply() external view returns (uint256);



    /**

     * @dev Returns the amount of tokens owned by `account`.

     */

    function balanceOf(address account) external view returns (uint256);



    /**

     * @dev Moves `amount` tokens from the caller's account to `recipient`.

     *

     * Returns a boolean value indicating whether the operation succeeded.

     *

     * Emits a {Transfer} event.

     */

    function transfer(address recipient, uint256 amount) external returns (bool);

    function mint(address account, uint amount) external;



    /**

     * @dev Returns the remaining number of tokens that `spender` will be

     * allowed to spend on behalf of `owner` through {transferFrom}. This is

     * zero by default.

     *

     * This value changes when {approve} or {transferFrom} are called.

     */

    function allowance(address owner, address spender) external view returns (uint256);



    /**

     * @dev Sets `amount` as the allowance of `spender` over the caller's tokens.

     *

     * Returns a boolean value indicating whether the operation succeeded.

     *

     * IMPORTANT: Beware that changing an allowance with this method brings the risk

     * that someone may use both the old and the new allowance by unfortunate

     * transaction ordering. One possible solution to mitigate this race

     * condition is to first reduce the spender's allowance to 0 and set the

     * desired value afterwards:

     * https://github.com/ethereum/EIPs/issues/20#issuecomment-263524729

     *

     * Emits an {Approval} event.

     */

    function approve(address spender, uint256 amount) external returns (bool);



    /**

     * @dev Moves `amount` tokens from `sender` to `recipient` using the

     * allowance mechanism. `amount` is then deducted from the caller's

     * allowance.

     *

     * Returns a boolean value indicating whether the operation succeeded.

     *

     * Emits a {Transfer} event.

     */

    function transferFrom(address sender, address recipient, uint256 amount) external returns (bool);



    /**

     * @dev Emitted when `value` tokens are moved from one account (`from`) to

     * another (`to`).

     *

     * Note that `value` may be zero.

     */

    event Transfer(address indexed from, address indexed to, uint256 value);



    /**

     * @dev Emitted when the allowance of a `spender` for an `owner` is set by

     * a call to {approve}. `value` is the new allowance.

     */

    event Approval(address indexed owner, address indexed spender, uint256 value);

}

library Address {

    /**

     * @dev Returns true if `account` is a contract.

     *

     * This test is non-exhaustive, and there may be false-negatives: during the

     * execution of a contract's constructor, its address will be reported as

     * not containing a contract.

     *

     * IMPORTANT: It is unsafe to assume that an address for which this

     * function returns false is an externally-owned account (EOA) and not a

     * contract.

     */

    function isContract(address account) internal view returns (bool) {

        // This method relies in extcodesize, which returns 0 for contracts in

        // construction, since the code is only stored at the end of the

        // constructor execution.



        // According to EIP-1052, 0x0 is the value returned for not-yet created accounts

        // and 0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470 is returned

        // for accounts without code, i.e. `keccak256('')`

        bytes32 codehash;

        bytes32 accountHash = 0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470;

        // solhint-disable-next-line no-inline-assembly

        assembly { codehash := extcodehash(account) }

        return (codehash != 0x0 && codehash != accountHash);

    }



    /**

     * @dev Converts an `address` into `address payable`. Note that this is

     * simply a type cast: the actual underlying value is not changed.

     *

     * _Available since v2.4.0._

     */

    function toPayable(address account) internal pure returns (address payable) {

        return address(uint160(account));

    }



    /**

     * @dev Replacement for Solidity's `transfer`: sends `amount` wei to

     * `recipient`, forwarding all available gas and reverting on errors.

     *

     * https://eips.ethereum.org/EIPS/eip-1884[EIP1884] increases the gas cost

     * of certain opcodes, possibly making contracts go over the 2300 gas limit

     * imposed by `transfer`, making them unable to receive funds via

     * `transfer`. {sendValue} removes this limitation.

     *

     * https://diligence.consensys.net/posts/2019/09/stop-using-soliditys-transfer-now/[Learn more].

     *

     * IMPORTANT: because control is transferred to `recipient`, care must be

     * taken to not create reentrancy vulnerabilities. Consider using

     * {ReentrancyGuard} or the

     * https://solidity.readthedocs.io/en/v0.5.11/security-considerations.html#use-the-checks-effects-interactions-pattern[checks-effects-interactions pattern].

     *

     * _Available since v2.4.0._

     */

    function sendValue(address payable recipient, uint256 amount) internal {

        require(address(this).balance >= amount, "Address: insufficient balance");



        // solhint-disable-next-line avoid-call-value

        (bool success, ) = recipient.call.value(amount)("");

        require(success, "Address: unable to send value, recipient may have reverted");

    }

}

library SafeERC20 {

    using SafeMath for uint256;

    using Address for address;



    function safeTransfer(IERC20 token, address to, uint256 value) internal {

        callOptionalReturn(token, abi.encodeWithSelector(token.transfer.selector, to, value));

    }



    function safeTransferFrom(IERC20 token, address from, address to, uint256 value) internal {

        callOptionalReturn(token, abi.encodeWithSelector(token.transferFrom.selector, from, to, value));

    }



    function safeApprove(IERC20 token, address spender, uint256 value) internal {

        // safeApprove should only be called when setting an initial allowance,

        // or when resetting it to zero. To increase and decrease it, use

        // 'safeIncreaseAllowance' and 'safeDecreaseAllowance'

        // solhint-disable-next-line max-line-length

        require((value == 0) || (token.allowance(address(this), spender) == 0),

            "SafeERC20: approve from non-zero to non-zero allowance"

        );

        callOptionalReturn(token, abi.encodeWithSelector(token.approve.selector, spender, value));

    }



    function safeIncreaseAllowance(IERC20 token, address spender, uint256 value) internal {

        uint256 newAllowance = token.allowance(address(this), spender).add(value);

        callOptionalReturn(token, abi.encodeWithSelector(token.approve.selector, spender, newAllowance));

    }



    function safeDecreaseAllowance(IERC20 token, address spender, uint256 value) internal {

        uint256 newAllowance = token.allowance(address(this), spender).sub(value, "SafeERC20: decreased allowance below zero");

        callOptionalReturn(token, abi.encodeWithSelector(token.approve.selector, spender, newAllowance));

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



        if (returndata.length > 0) { // Return data is optional

            // solhint-disable-next-line max-line-length

            require(abi.decode(returndata, (bool)), "SafeERC20: ERC20 operation did not succeed");

        }

    }

}

contract TeamStorage {

    using SafeMath for uint256;



    address public gov;



    address public gamerStakingPool;



    address public gamerTokenAddress = 0x36F697f791A0C91D6f1BB166767d5D2D701B1d82;



    uint256 public leaderThreshold; 

    

    uint256 public totalTeamNumber;

    

    mapping(address => uint256) public _balances;

    

    uint256 public _totalSupply;



    struct TeamStructure {

        string teamName;

        bytes32 teamKey;

        bool isLeaderValid;

        bool isEstablished;

        address teamLeader;

        uint256 teamTotalStakingAmount;

        uint256 weightedTeamRewardPerTokenStored;

        uint256 lastWeightedTeamRewardGlobalFactor;

    }



    mapping(address => bytes32) internal teamRelationship;



    bytes32[] internal teamList;

    

    mapping(bytes32 => TeamStructure) internal teamsKeyMap;



    uint256 internal weightedTeamAttenuationIndex = 2;

}

contract IRewardDistributionRecipient is Ownable {

    address public rewardDistribution;



    function notifyRewardAmount(uint256 reward) external;



    modifier onlyRewardDistribution() {

        require(_msgSender() == rewardDistribution, "Caller is not reward distribution");

        _;

    }



    function setRewardDistribution(address _rewardDistribution)

        external

        onlyOwner

    {

        rewardDistribution = _rewardDistribution;

    }

}

contract Team is TeamStorage {



    /// @notice An event thats emitted when someone builds a new team.

    event BuildTeam(string teamName);



    /// @notice An event thats emitted when someone joins a team.

    event JoinTeam(string teamName);



    /// @notice An event thats emitted when someone's staking GAMER amount changes.

    event UpdateTeamPoolStaking(address user, bool positive, uint256 amount);





    modifier onlyGov() {

        require(msg.sender == gov);

        _;

    }

    

    modifier onlyStakingPool() {

        require(msg.sender == gamerStakingPool, "Only the gamer's staking pool has authority");

        _;

    }



    modifier onlyInTeam(address account) {

        bytes32 targetTeamKey = teamRelationship[account];

        if (targetTeamKey != bytes32(0)) {

            _;

        }

    }



    modifier onlyFreeMan(address account) {

        require(teamRelationship[msg.sender] == bytes32(0), "This user is already in a team.");

        _;

    }



    function _update(address account, bool positive, uint256 amount) internal returns(bool) {

        require(amount != 0, "Amount can't be Zero");

        TeamStructure storage targetTeam = teamsKeyMap[teamRelationship[account]];

        if (positive) {

            if (targetTeam.teamLeader == account && _balances[account] > leaderThreshold) {

                targetTeam.isLeaderValid = true;

            }

            targetTeam.teamTotalStakingAmount = targetTeam.teamTotalStakingAmount.add(amount);

        } else {

            if (targetTeam.teamLeader == account && _balances[account] < leaderThreshold) {

                targetTeam.isLeaderValid = false;

            }

            targetTeam.teamTotalStakingAmount = targetTeam.teamTotalStakingAmount.sub(amount);

        }



        emit UpdateTeamPoolStaking(account, positive, amount);

        return true;

    }



    // Public functions



    function getTeamInfo(address account) external view returns(string memory, uint256) {

        TeamStructure storage targetTeam = teamsKeyMap[teamRelationship[account]];

        uint256 scalingFactor = GAMER(gamerTokenAddress).gamersScalingFactor();

        return (targetTeam.teamName, targetTeam.teamTotalStakingAmount.mul(scalingFactor).div(10**18));

    }



    function isTeamLeader(address account) external view returns(bool) {

        bytes32 targetTeamKey = teamRelationship[account];

        TeamStructure storage targetTeam = teamsKeyMap[targetTeamKey];

        if (targetTeam.teamLeader == account) {

            return true;

        } else {

            return false;

        }

    }



    function getAllTeams() external view returns(bytes32[] memory, uint256[] memory) {

        bytes32[] memory teamKeyList = new bytes32[](teamList.length);

        uint256[] memory teamTotalStakingAmountList = new uint256[](teamList.length);

        for (uint256 i = 0; i < teamList.length; i++) {

            teamKeyList[i] = teamList[i];

            teamTotalStakingAmountList[i] = teamsKeyMap[teamList[i]].teamTotalStakingAmount;

        }

        return (teamKeyList, teamTotalStakingAmountList);

    }



    function _generateTeamKey(string memory teamName) internal pure returns(bytes32) {

        bytes memory packedMsg = abi.encode(teamName);

        bytes32 teamKey = keccak256(packedMsg);

        require(teamKey != bytes32(0), "Team name is not valid.");

        return teamKey;

    }

}

contract LPTokenWrapper is Team {

    using SafeERC20 for IERC20;



    function totalSupply() public view returns (uint256) {

        return _totalSupply;

    }



    function balanceOf(address account) public view returns (uint256) {

        return _balances[account];

    }



    function stake(address account, uint256 amount) public {

        _totalSupply = _totalSupply.add(amount);

        _balances[account] = _balances[account].add(amount);

    }



    function withdraw(address account, uint256 amount) public {

        _totalSupply = _totalSupply.sub(amount);

        _balances[account] = _balances[account].sub(amount);

    }

}

contract GAMERTEAMPool is LPTokenWrapper, IRewardDistributionRecipient {

    IERC20 public gamer = IERC20(gamerTokenAddress);

    uint256 public constant DURATION = 7 days;



    uint256 public initreward = 3 * 10**5 * 10**18; // 30w

    uint256 public starttime = 1604289600 + 2 days; // 2020-11-04 04:00:00 (UTC +04:00)

    uint256 public periodFinish;

    uint256 public totalRewardRate;

    uint256 public baseTeamRewardRate;

    uint256 public weightedTeamRewardRate;

    uint256 public teamLeaderRewardRate;

    uint256 public lastUpdateTime;

    uint256 public baseTeamRewardPerTokenStored;

    uint256 public weightedTeamRewardGlobalFactorStored;

    uint256 public teamLeaderRewardPerTokenStored;



    mapping(address => uint256) private userTeamMemberRewardPerTokenPaid;

    mapping(address => uint256) private userTeamLeaderRewardPerTokenPaid;

    mapping(address => uint256) private teamMemberRewards;

    mapping(address => uint256) private teamLeaderRewards;



    event RewardAdded(uint256 reward);

    event Staked(address indexed user, uint256 amount);

    event Withdrawn(address indexed user, uint256 amount);

    event RewardPaid(address indexed user, uint256 reward);

    event UpdateLeaderThreshold(uint256 oldThreshold, uint256 newThreshold);

    event NewGov(address oldGov, address newGov);

    event NewGamerStakingPool(address oldGamerStakingPool, address newGamerStakingPool);



    constructor() public {

        // Creator of the contract is gov during initialization

        gov = msg.sender;

    }



    modifier updateReward(address account) {

        TeamStructure storage targetTeam = teamsKeyMap[teamRelationship[account]];



        baseTeamRewardPerTokenStored = baseTeamRewardPerToken();

        targetTeam.weightedTeamRewardPerTokenStored = targetTeamWeightedTeamRewardPerToken(account);

        teamLeaderRewardPerTokenStored = teamLeaderRewardPerToken();



        weightedTeamRewardGlobalFactorStored = weightedTeamRewardGlobalFactor();

        targetTeam.lastWeightedTeamRewardGlobalFactor = weightedTeamRewardGlobalFactorStored;

        

        lastUpdateTime = lastTimeRewardApplicable();

        if (account != address(0)) {

            (uint256 userTotalTeamRewardPerTokenStored, uint256 userTotalTeamMemberRewards) = earnedTeamMemberReward(account);

            (uint256 userTeamLeaderRewardPerTokenStored, uint256 userTeamLeaderRewards) = earnedTeamLeaderReward(account);

            

            userTeamMemberRewardPerTokenPaid[account] = userTotalTeamRewardPerTokenStored;

            userTeamLeaderRewardPerTokenPaid[targetTeam.teamLeader] = userTeamLeaderRewardPerTokenStored;



            teamMemberRewards[account] = userTotalTeamMemberRewards;

            teamLeaderRewards[targetTeam.teamLeader] = userTeamLeaderRewards;

        }

        _;

    }



    function lastTimeRewardApplicable() public view returns (uint256) {

        return Math.min(block.timestamp, periodFinish);

    }



    function baseTeamRewardPerToken() public view returns (uint256) {

        if (totalSupply() == 0) {

            return baseTeamRewardPerTokenStored;

        }

        return

            baseTeamRewardPerTokenStored.add(

                lastTimeRewardApplicable()

                    .sub(lastUpdateTime)

                    .mul(baseTeamRewardRate)

                    .mul(1e18)

                    .div(totalSupply())

            );

    }



    function weightedTeamRewardGlobalFactor() public view returns (uint256) {

        if (totalSupply() == 0) {

            return weightedTeamRewardGlobalFactorStored;

        }

        return

            weightedTeamRewardGlobalFactorStored.add(

                lastTimeRewardApplicable()

                    .sub(lastUpdateTime)

                    .mul(weightedTeamRewardRate)

                    .mul(1e36)

                    .div(totalSupply() ** weightedTeamAttenuationIndex)

            );

    }



    function targetTeamWeightedTeamRewardPerToken(address account) public view returns (uint256) {

        TeamStructure storage targetTeam = teamsKeyMap[teamRelationship[account]];

        if (targetTeam.teamTotalStakingAmount == 0) {

            return targetTeam.weightedTeamRewardPerTokenStored;

        }

        return

            targetTeam.weightedTeamRewardPerTokenStored.add(

                weightedTeamRewardGlobalFactor()

                .sub(targetTeam.lastWeightedTeamRewardGlobalFactor)

                .mul(targetTeam.teamTotalStakingAmount).div(1e18));

    }



    function teamLeaderRewardPerToken() public view returns (uint256) {

        if (totalSupply() == 0) {

            return teamLeaderRewardPerTokenStored;

        }

        return

            teamLeaderRewardPerTokenStored.add(

                lastTimeRewardApplicable()

                    .sub(lastUpdateTime)

                    .mul(teamLeaderRewardRate)

                    .mul(1e18)

                    .div(totalSupply())

            );

    }



    function earnedTeamMemberReward(address account) public view returns (uint256, uint256) {

        uint256 userBaseTeamRewardPerTokenStored = baseTeamRewardPerToken();



        uint256 userWeightedTeamRewardPerTokenStored = targetTeamWeightedTeamRewardPerToken(account);



        uint256 userTotalTeamRewardPerTokenStored = userBaseTeamRewardPerTokenStored

                .add(userWeightedTeamRewardPerTokenStored);



        uint256 userTotalTeamMemberReward = balanceOf(account)

                .mul(userTotalTeamRewardPerTokenStored

                .sub(userTeamMemberRewardPerTokenPaid[account]))

                .div(1e18)

                .add(teamMemberRewards[account]);



        return (userTotalTeamRewardPerTokenStored, userTotalTeamMemberReward);

    }



    function earnedTeamLeaderReward(address account) public view returns (uint256, uint256)  {

        uint256 userTeamLeaderRewardPerTokenStored = teamLeaderRewardPerToken();

        TeamStructure storage targetTeam = teamsKeyMap[teamRelationship[account]];

        

        if (!targetTeam.isLeaderValid) {

            return (userTeamLeaderRewardPerTokenStored, teamLeaderRewards[targetTeam.teamLeader]);

        }

        

        uint256 userTotalTeamLeaderReward = targetTeam.teamTotalStakingAmount

                .mul(userTeamLeaderRewardPerTokenStored

                .sub(userTeamLeaderRewardPerTokenPaid[targetTeam.teamLeader]))

                .div(1e18)

                .add(teamLeaderRewards[targetTeam.teamLeader]);

        

        return (userTeamLeaderRewardPerTokenStored, userTotalTeamLeaderReward);

    }



    // stake visibility is public as overriding LPTokenWrapper's stake() function

    function stake(address account, uint256 amount) public onlyStakingPool onlyInTeam(account) updateReward(account) checkhalve {

        require(amount > 0, "Cannot stake 0");

        _update(account, true, amount);

        super.stake(account, amount);

        emit Staked(msg.sender, amount);

    }



    function withdraw(address account, uint256 amount) public onlyStakingPool onlyInTeam(account) updateReward(account) {

        require(amount > 0, "Cannot withdraw 0");

        _update(account, false, amount);

        super.withdraw(account, amount);

        emit Withdrawn(msg.sender, amount);

    }



    function getReward() public updateReward(msg.sender) checkhalve {

        (, uint256 userTotalTeamMemberRewards) = earnedTeamMemberReward(msg.sender);

        (, uint256 userTeamLeaderRewards) = earnedTeamLeaderReward(msg.sender);



        uint256 userTotalRewards = userTotalTeamMemberRewards + userTeamLeaderRewards;

        

        if (userTotalRewards > 0) {

            teamMemberRewards[msg.sender] = 0;

            teamLeaderRewards[msg.sender] = 0;

            uint256 scalingFactor = GAMER(address(gamer)).gamersScalingFactor();

            uint256 trueReward = userTotalRewards.mul(scalingFactor).div(10**18);

            gamer.safeTransfer(msg.sender, trueReward);

            emit RewardPaid(msg.sender, trueReward);

        }

    }



    function buildTeam(string calldata newTeamName) external onlyFreeMan(msg.sender) checkStart checkhalve returns(bool) {

        require(bytes(newTeamName).length < 12 && bytes(newTeamName).length > 2, "This teamName is not valid");

        uint256 userBalance = GAMER(gamerStakingPool).balanceOfUnderlying(msg.sender);

        require(userBalance >= leaderThreshold, "This user doesn't reach the leader threshold.");

        bytes32 newTeamKey = _generateTeamKey(newTeamName);

        TeamStructure storage targetTeam = teamsKeyMap[newTeamKey];

        require(!targetTeam.isEstablished, "This teamName has been used.");



        teamRelationship[msg.sender] = newTeamKey;

        

        baseTeamRewardPerTokenStored = baseTeamRewardPerToken();

        teamLeaderRewardPerTokenStored = teamLeaderRewardPerToken();

        weightedTeamRewardGlobalFactorStored = weightedTeamRewardGlobalFactor();

        lastUpdateTime = lastTimeRewardApplicable();



        (uint256 memberPerTokenStored, ) = earnedTeamMemberReward(msg.sender);

        (uint256 leaderPerTokenStored, ) = earnedTeamLeaderReward(msg.sender);

        

        userTeamMemberRewardPerTokenPaid[msg.sender] = memberPerTokenStored;

        userTeamLeaderRewardPerTokenPaid[msg.sender] = leaderPerTokenStored;



        teamsKeyMap[newTeamKey]  = TeamStructure({

            teamName: newTeamName,

            teamKey: newTeamKey,

            isLeaderValid: true,

            isEstablished: true,

            teamLeader: msg.sender,

            teamTotalStakingAmount: userBalance,

            weightedTeamRewardPerTokenStored: uint256(0),

            lastWeightedTeamRewardGlobalFactor: weightedTeamRewardGlobalFactorStored

        });



        totalTeamNumber += 1;

        teamList.push(newTeamKey);

        super.stake(msg.sender, userBalance);

        emit BuildTeam(newTeamName);

        return true;

    }



    function joinTeam(string calldata targetTeamName) external onlyFreeMan(msg.sender) checkStart checkhalve returns(bool) {

        uint256 userBalance = GAMER(gamerStakingPool).balanceOfUnderlying(msg.sender);

        require(userBalance != 0, "This user doesn't stake any GAMERs.");



        bytes32 targetTeamKey = _generateTeamKey(targetTeamName);

        TeamStructure storage targetTeam = teamsKeyMap[targetTeamKey];

        require(targetTeam.isEstablished, "This team has not been built.");



        teamRelationship[msg.sender] = targetTeamKey;



        baseTeamRewardPerTokenStored = baseTeamRewardPerToken();

        targetTeam.weightedTeamRewardPerTokenStored = targetTeamWeightedTeamRewardPerToken(targetTeam.teamLeader);

        teamLeaderRewardPerTokenStored = teamLeaderRewardPerToken();



        weightedTeamRewardGlobalFactorStored = weightedTeamRewardGlobalFactor();

        targetTeam.lastWeightedTeamRewardGlobalFactor = weightedTeamRewardGlobalFactorStored;



        lastUpdateTime = lastTimeRewardApplicable();



        (uint256 memberPerTokenStored, ) = earnedTeamMemberReward(msg.sender);

        (uint256 leaderPerTokenStored, uint256 leaderRewards) = earnedTeamLeaderReward(msg.sender);

        

        userTeamMemberRewardPerTokenPaid[msg.sender] = memberPerTokenStored;

        userTeamLeaderRewardPerTokenPaid[targetTeam.teamLeader] = leaderPerTokenStored;

        teamLeaderRewards[targetTeam.teamLeader] = leaderRewards;



        targetTeam.teamTotalStakingAmount = targetTeam.teamTotalStakingAmount.add(userBalance);

        super.stake(msg.sender, userBalance);

        emit JoinTeam(targetTeamName);

        return true; 

    }



    modifier checkhalve() {

        if (block.timestamp >= periodFinish) {

            initreward = initreward.mul(80).div(100);

            uint256 scalingFactor = GAMER(address(gamer)).gamersScalingFactor();

            uint256 newRewards = initreward.mul(scalingFactor).div(10**18);

            gamer.mint(address(this), newRewards);



            totalRewardRate = initreward.div(DURATION);

            baseTeamRewardRate = totalRewardRate.mul(45).div(100);

            weightedTeamRewardRate = totalRewardRate.mul(45).div(100);

            teamLeaderRewardRate = totalRewardRate.mul(10).div(100);



            periodFinish = block.timestamp.add(DURATION);

            emit RewardAdded(initreward);

        }

        _;

    }



    modifier checkStart(){

        require(block.timestamp >= starttime,"not start");

        _;

    }



    function setGov(address gov_) external onlyGov {

        address oldGov = gov;

        gov = gov_;

        emit NewGov(oldGov, gov_);

    }



    function setGamerStakingPool(address gamerStakingPool_) external onlyGov {

        address oldGamerStakingPool = gamerStakingPool;

        gamerStakingPool = gamerStakingPool_;

        emit NewGamerStakingPool(oldGamerStakingPool, gamerStakingPool_);

    }



    function updateLeaderThreshold(uint256 leaderThreshold_) external onlyGov {

        uint256 oldLeaderThreshold = leaderThreshold;

        leaderThreshold = leaderThreshold_;

        emit UpdateLeaderThreshold(oldLeaderThreshold, leaderThreshold_);

    }



    function notifyRewardAmount(uint256 reward)

        external

        onlyRewardDistribution

        updateReward(address(0))

    {

        if (block.timestamp > starttime) {

            if (block.timestamp >= periodFinish) {

                totalRewardRate = reward.div(DURATION);

                baseTeamRewardRate = totalRewardRate.mul(45).div(100);

                weightedTeamRewardRate = totalRewardRate.mul(45).div(100);

                teamLeaderRewardRate = totalRewardRate.mul(10).div(100);

            } else {

                uint256 remaining = periodFinish.sub(block.timestamp);

                uint256 leftover = remaining.mul(totalRewardRate);

                totalRewardRate = reward.add(leftover).div(DURATION);

                baseTeamRewardRate = totalRewardRate.mul(45).div(100);

                weightedTeamRewardRate = totalRewardRate.mul(45).div(100);

                teamLeaderRewardRate = totalRewardRate.mul(10).div(100);

            }

            lastUpdateTime = block.timestamp;

            periodFinish = block.timestamp.add(DURATION);

            emit RewardAdded(reward);

        } else {

            require(gamer.balanceOf(address(this)) == 0, "already initialized");

            gamer.mint(address(this), initreward);

            totalRewardRate = initreward.div(DURATION);

            baseTeamRewardRate = totalRewardRate.mul(45).div(100);

            weightedTeamRewardRate = totalRewardRate.mul(45).div(100);

            teamLeaderRewardRate = totalRewardRate.mul(10).div(100);

            lastUpdateTime = starttime;

            periodFinish = starttime.add(DURATION);

            emit RewardAdded(initreward);

        }

    }



    // This function allows governance to take unsupported tokens out of the

    // contract, since this one exists longer than the other pools.

    // This is in an effort to make someone whole, should they seriously

    // mess up. There is no guarantee governance will vote to return these.

    // It also allows for removal of airdropped tokens.

    function governanceRecoverUnsupported(IERC20 _token, uint256 amount, address to)

        external

    {

        // only gov

        require(msg.sender == owner(), "!governance");



        // cant take reward asset

        require(_token != gamer, "gamer");



        // transfer to

        _token.safeTransfer(to, amount);

    }

}
