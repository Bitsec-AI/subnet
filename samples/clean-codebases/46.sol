pragma solidity 0.5.17;

interface IUniswapV2Pair {

    event Approval(address indexed owner, address indexed spender, uint value);

    event Transfer(address indexed from, address indexed to, uint value);



    function name() external pure returns (string memory);

    function symbol() external pure returns (string memory);

    function decimals() external pure returns (uint8);

    function totalSupply() external view returns (uint);

    function balanceOf(address owner) external view returns (uint);

    function allowance(address owner, address spender) external view returns (uint);



    function approve(address spender, uint value) external returns (bool);

    function transfer(address to, uint value) external returns (bool);

    function transferFrom(address from, address to, uint value) external returns (bool);



    function DOMAIN_SEPARATOR() external view returns (bytes32);

    function PERMIT_TYPEHASH() external pure returns (bytes32);

    function nonces(address owner) external view returns (uint);



    function permit(address owner, address spender, uint value, uint deadline, uint8 v, bytes32 r, bytes32 s) external;



    event Mint(address indexed sender, uint amount0, uint amount1);

    event Burn(address indexed sender, uint amount0, uint amount1, address indexed to);

    event Swap(

        address indexed sender,

        uint amount0In,

        uint amount1In,

        uint amount0Out,

        uint amount1Out,

        address indexed to

    );

    event Sync(uint112 reserve0, uint112 reserve1);



    function MINIMUM_LIQUIDITY() external pure returns (uint);

    function factory() external view returns (address);

    function token0() external view returns (address);

    function token1() external view returns (address);

    function getReserves() external view returns (uint112 reserve0, uint112 reserve1, uint32 blockTimestampLast);

    function price0CumulativeLast() external view returns (uint);

    function price1CumulativeLast() external view returns (uint);

    function kLast() external view returns (uint);



    function mint(address to) external returns (uint liquidity);

    function burn(address to) external returns (uint amount0, uint amount1);

    function swap(uint amount0Out, uint amount1Out, address to, bytes calldata data) external;

    function skim(address to) external;

    function sync() external;



    function initialize(address, address) external;

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

contract LPTokenWrapper {

    using SafeMath for uint256;

    using SafeERC20 for IERC20;



    IERC20 public wrappedToken;



    uint256 public _totalSupply;

    mapping(address => uint256) public _balances;



    constructor(IERC20 _wrappedToken) public {

        wrappedToken = _wrappedToken;

    }



    function totalSupply() public view returns (uint256) {

        return _totalSupply;

    }



    function balanceOf(address account) public view returns (uint256) {

        return _balances[account];

    }



    function stake(uint256 amount) public {

        _totalSupply = _totalSupply.add(amount);

        _balances[msg.sender] = _balances[msg.sender].add(amount);

        wrappedToken.safeTransferFrom(msg.sender, address(this), amount);

    }



    function withdraw(uint256 amount) public {

        _totalSupply = _totalSupply.sub(amount);

        _balances[msg.sender] = _balances[msg.sender].sub(amount);

        wrappedToken.safeTransfer(msg.sender, amount);

    }

}

interface HAM {

    function hamsScalingFactor() external returns (uint256);

    function mint(address to, uint256 amount) external;

}

contract Farm is LPTokenWrapper, IRewardDistributionRecipient {

    IERC20 public ham;

    uint256 public duration;

    uint256 public startTime;



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

        IERC20 _ham,

        IERC20 _wrappedToken

    ) LPTokenWrapper(_wrappedToken) public {

        ham = _ham;

    }



    function initialize(uint256 _startTime, uint256 _duration) public onlyOwner {

        require(startTime == 0, "already initialized");

        startTime = _startTime;

        duration = _duration;

    }



    modifier checkStart() {

        require(startTime > 0,"not initialized");

        require(block.timestamp >= startTime,"not start");

        _;

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

    function stake(uint256 amount) public updateReward(msg.sender) checkStart {

        require(amount > 0, "Cannot stake 0");

        super.stake(amount);

        emit Staked(msg.sender, amount);

    }



    function withdraw(uint256 amount) public updateReward(msg.sender) checkStart {

        require(amount > 0, "Cannot withdraw 0");

        super.withdraw(amount);

        emit Withdrawn(msg.sender, amount);

    }



    function exit() external {

        if (balanceOf(msg.sender) > 0) {

            withdraw(balanceOf(msg.sender));

        }

        getReward();

    }



    function getReward() public updateReward(msg.sender) checkStart {

        uint256 reward = earned(msg.sender);

        if (reward > 0) {

            rewards[msg.sender] = 0;

            uint256 scalingFactor = HAM(address(ham)).hamsScalingFactor();

            uint256 trueReward = reward.mul(scalingFactor).div(10**18);

            ham.safeTransfer(msg.sender, trueReward);

            emit RewardPaid(msg.sender, trueReward);

        }

    }



    function notifyRewardAmount(uint256 reward)

        public

        onlyRewardDistribution

        updateReward(address(0))

    {

        if (block.timestamp > startTime) {

          if (block.timestamp >= periodFinish) {

              rewardRate = reward.div(duration);

          } else {

              uint256 remaining = periodFinish.sub(block.timestamp);

              uint256 leftover = remaining.mul(rewardRate);

              rewardRate = reward.add(leftover).div(duration);

          }

          lastUpdateTime = block.timestamp;

          periodFinish = block.timestamp.add(duration);

          emit RewardAdded(reward);

        } else {

          rewardRate = reward.div(duration);

          lastUpdateTime = startTime;

          periodFinish = startTime.add(duration);

          emit RewardAdded(reward);

        }

    }

}

interface IUniswapV2Router02 {

    function factory() external pure returns (address);

    function WETH() external pure returns (address);



    function addLiquidity(

        address tokenA,

        address tokenB,

        uint amountADesired,

        uint amountBDesired,

        uint amountAMin,

        uint amountBMin,

        address to,

        uint deadline

    ) external returns (uint amountA, uint amountB, uint liquidity);

    function addLiquidityETH(

        address token,

        uint amountTokenDesired,

        uint amountTokenMin,

        uint amountETHMin,

        address to,

        uint deadline

    ) external payable returns (uint amountToken, uint amountETH, uint liquidity);

    function removeLiquidity(

        address tokenA,

        address tokenB,

        uint liquidity,

        uint amountAMin,

        uint amountBMin,

        address to,

        uint deadline

    ) external returns (uint amountA, uint amountB);

    function removeLiquidityETH(

        address token,

        uint liquidity,

        uint amountTokenMin,

        uint amountETHMin,

        address to,

        uint deadline

    ) external returns (uint amountToken, uint amountETH);

    function removeLiquidityWithPermit(

        address tokenA,

        address tokenB,

        uint liquidity,

        uint amountAMin,

        uint amountBMin,

        address to,

        uint deadline,

        bool approveMax, uint8 v, bytes32 r, bytes32 s

    ) external returns (uint amountA, uint amountB);

    function removeLiquidityETHWithPermit(

        address token,

        uint liquidity,

        uint amountTokenMin,

        uint amountETHMin,

        address to,

        uint deadline,

        bool approveMax, uint8 v, bytes32 r, bytes32 s

    ) external returns (uint amountToken, uint amountETH);

    function swapExactTokensForTokens(

        uint amountIn,

        uint amountOutMin,

        address[] calldata path,

        address to,

        uint deadline

    ) external returns (uint[] memory amounts);

    function swapTokensForExactTokens(

        uint amountOut,

        uint amountInMax,

        address[] calldata path,

        address to,

        uint deadline

    ) external returns (uint[] memory amounts);

    function swapExactETHForTokens(uint amountOutMin, address[] calldata path, address to, uint deadline)

        external

        payable

        returns (uint[] memory amounts);

    function swapTokensForExactETH(uint amountOut, uint amountInMax, address[] calldata path, address to, uint deadline)

        external

        returns (uint[] memory amounts);

    function swapExactTokensForETH(uint amountIn, uint amountOutMin, address[] calldata path, address to, uint deadline)

        external

        returns (uint[] memory amounts);

    function swapETHForExactTokens(uint amountOut, address[] calldata path, address to, uint deadline)

        external

        payable

        returns (uint[] memory amounts);



    function quote(uint amountA, uint reserveA, uint reserveB) external pure returns (uint amountB);

    function getAmountOut(uint amountIn, uint reserveIn, uint reserveOut) external pure returns (uint amountOut);

    function getAmountIn(uint amountOut, uint reserveIn, uint reserveOut) external pure returns (uint amountIn);

    function getAmountsOut(uint amountIn, address[] calldata path) external view returns (uint[] memory amounts);

    function getAmountsIn(uint amountOut, address[] calldata path) external view returns (uint[] memory amounts);



    function removeLiquidityETHSupportingFeeOnTransferTokens(

        address token,

        uint liquidity,

        uint amountTokenMin,

        uint amountETHMin,

        address to,

        uint deadline

    ) external returns (uint amountETH);

    function removeLiquidityETHWithPermitSupportingFeeOnTransferTokens(

        address token,

        uint liquidity,

        uint amountTokenMin,

        uint amountETHMin,

        address to,

        uint deadline,

        bool approveMax, uint8 v, bytes32 r, bytes32 s

    ) external returns (uint amountETH);



    function swapExactTokensForTokensSupportingFeeOnTransferTokens(

        uint amountIn,

        uint amountOutMin,

        address[] calldata path,

        address to,

        uint deadline

    ) external;

    function swapExactETHForTokensSupportingFeeOnTransferTokens(

        uint amountOutMin,

        address[] calldata path,

        address to,

        uint deadline

    ) external payable;

    function swapExactTokensForETHSupportingFeeOnTransferTokens(

        uint amountIn,

        uint amountOutMin,

        address[] calldata path,

        address to,

        uint deadline

    ) external;

}

contract Dam is Farm {

    using SafeMath for uint256;

    using SafeERC20 for IERC20;



    mapping(address => bool) public acceptedPairs;

    IERC20[] public unwrappedTokens;

    mapping(address => mapping(address => uint256)) public unwrappedBalances;

    IUniswapV2Router02 public uniswapRouter;



    event Staked(address indexed user, address uniswapPair, uint256 amount);

    event Withdrawn(address indexed user, address token, uint256 amount);



    constructor(

        IERC20 _ham,

        IUniswapV2Pair[] memory _acceptedPairs,

        IUniswapV2Router02 _uniswapRouter

    ) Farm(_ham, IERC20(address(0))) public {

        uniswapRouter = _uniswapRouter;

        wrappedToken = IERC20(_uniswapRouter.WETH());

        for (uint i = 0; i<_acceptedPairs.length; i++) {

            address token0 = _acceptedPairs[i].token0();

            address token1 = _acceptedPairs[i].token1();

            require(

                token0 == address(wrappedToken) || token1 == address(wrappedToken),

                "pairs must be against weth"

            );

            acceptedPairs[address(_acceptedPairs[i])] = true;

            unwrappedTokens.push(token0 == address(wrappedToken) ? IERC20(token1) : IERC20(token0));

        }

    }



    function stakeAndUnwrap(IUniswapV2Pair pair, uint256 amount) public updateReward(msg.sender) checkStart {

        require(amount > 0, "can't stake 0");

        require(acceptedPairs[address(pair)], "token not accepted");

        IERC20(address(pair)).safeTransferFrom(msg.sender, address(this), amount);

        require(pair.approve(address(uniswapRouter), amount), 'failed approve');



        address otherToken = pair.token0();

        if (otherToken == address(wrappedToken)) {

            otherToken = pair.token1();

        }



        (uint256 amountOther, uint256 amountWrapped) = uniswapRouter.removeLiquidity(otherToken, address(wrappedToken), amount, 0, 0, address(this), block.timestamp);



        _balances[msg.sender] = _balances[msg.sender].add(amountWrapped);

        _totalSupply = _totalSupply.add(amount);

        unwrappedBalances[otherToken][msg.sender] = unwrappedBalances[otherToken][msg.sender].add(amountOther);



        emit Staked(msg.sender, amountWrapped);

    }



    function stake(uint256 amount) public {

        revert("cant stake without unwrapping");

    }



    function withdraw(uint256 amount) public {

        revert("cant withdraw, use exit");

    }



	// gtfo

    function exit() external updateReward(msg.sender) checkStart {

		uint256 amount = balanceOf(msg.sender);

        super.withdraw(amount);

        emit Withdrawn(msg.sender, address(wrappedToken), amount);

        for (uint i = 0; i<unwrappedTokens.length; i++) {

			address ti = address(unwrappedTokens[i]);

            if (unwrappedBalances[ti][msg.sender] > 0) {

                uint256 toSend = unwrappedBalances[ti][msg.sender];

                unwrappedBalances[ti][msg.sender] = 0;

                unwrappedTokens[i].safeTransfer(msg.sender, toSend);

            }

        }

        getReward();

    }

}
