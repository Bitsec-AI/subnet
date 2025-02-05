pragma solidity 0.7.1;

library Address {


    /**


     * @dev Returns true if `account` is a contract.


     *


     * [IMPORTANT]


     * ====


     * It is unsafe to assume that an address for which this function returns


     * false is an externally-owned account (EOA) and not a contract.


     *


     * Among others, `isContract` will return false for the following


     * types of addresses:


     *


     *  - an externally-owned account


     *  - a contract in construction


     *  - an address where a contract will be created


     *  - an address where a contract lived, but was destroyed


     * ====


     */


    function isContract(address account) internal view returns (bool) {


        // According to EIP-1052, 0x0 is the value returned for not-yet created accounts


        // and 0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470 is returned


        // for accounts without code, i.e. `keccak256('')`


        bytes32 codehash;


        bytes32 accountHash = 0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470;


        // solhint-disable-next-line no-inline-assembly


        assembly { codehash := extcodehash(account) }


        return (codehash != accountHash && codehash != 0x0);


    }





    /**


     * @dev Performs a Solidity function call using a low level `call`. A


     * plain`call` is an unsafe replacement for a function call: use this


     * function instead.


     *


     * If `target` reverts with a revert reason, it is bubbled up by this


     * function (like regular Solidity function calls).


     *


     * Returns the raw returned data. To convert to the expected return value,


     * use https://solidity.readthedocs.io/en/latest/units-and-global-variables.html?highlight=abi.decode#abi-encoding-and-decoding-functions[`abi.decode`].


     *


     * Requirements:


     *


     * - `target` must be a contract.


     * - calling `target` with `data` must not revert.


     *


     * _Available since v3.1._


     */


    function functionCall(address target, bytes memory data) internal returns (bytes memory) {


        return functionCall(target, data, "Address: low-level call failed");


    }





    /**


     * @dev Same as {xref-Address-functionCall-address-bytes-}[`functionCall`], but with


     * `errorMessage` as a fallback revert reason when `target` reverts.


     *


     * _Available since v3.1._


     */


    function functionCall(address target, bytes memory data, string memory errorMessage) internal returns (bytes memory) {


        return _functionCallWithValue(target, data, 0, errorMessage);


    }





    function _functionCallWithValue(address target, bytes memory data, uint256 weiValue, string memory errorMessage) private returns (bytes memory) {


        require(isContract(target), "Address: call to non-contract");





        // solhint-disable-next-line avoid-low-level-calls


        (bool success, bytes memory returndata) = target.call{ value: weiValue }(data);


        if (success) {


            return returndata;


        } else {


            // Look for revert reason and bubble it up if present


            if (returndata.length > 0) {


                // The easiest way to bubble the revert reason is using memory via assembly





                // solhint-disable-next-line no-inline-assembly


                assembly {


                    let returndata_size := mload(returndata)


                    revert(add(32, returndata), returndata_size)


                }


            } else {


                revert(errorMessage);


            }


        }


    }


}

abstract contract Context {


    function _msgSender() internal view virtual returns (address payable) {


        return msg.sender;


    }


}

interface IERC20 {





    function allowance(address account, address spender) external view returns (uint256);





    function approve(address spender, uint256 rawAmount) external returns (bool);





    function balanceOf(address account) external view returns (uint256);





    function totalSupply() external view returns (uint256);





    function transfer(address recipient, uint256 amount) external returns (bool);





    function transferFrom(address sender, address recipient, uint256 amount) external returns (bool);


}

interface IHPFToken {


    function mint(address dst, uint rawAmount) external;


    function transfer(address dst, uint rawAmount) external returns (bool);


    function balanceOf(address account) external view returns (uint);


    function totalSupply() external view returns (uint);


}

abstract contract Ownable is Context {


    address private _owner;





    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);





    /**


     * @dev Initializes the contract setting the deployer as the initial owner.


     */


    constructor () {


        address msgSender = _msgSender();


        _owner = msgSender;


        emit OwnershipTransferred(address(0), msgSender);


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


        require(_owner == _msgSender(), "Ownable: caller is not the owner");


        _;


    }





    /**


     * @dev Leaves the contract without owner. It will not be possible to call


     * `onlyOwner` functions anymore. Can only be called by the current owner.


     *


     * NOTE: Renouncing ownership will leave the contract without an owner,


     * thereby removing any functionality that is only available to the owner.


     */


    function renounceOwnership() public virtual onlyOwner {


        emit OwnershipTransferred(_owner, address(0));


        _owner = address(0);


    }





    /**


     * @dev Transfers ownership of the contract to a new account (`newOwner`).


     * Can only be called by the current owner.


     */


    function transferOwnership(address newOwner) public virtual onlyOwner {


        require(newOwner != address(0), "Ownable: new owner is the zero address");


        emit OwnershipTransferred(_owner, newOwner);


        _owner = newOwner;


    }


}

library SafeERC20 {


    using SafeMath for uint256;


    using Address for address;





    function safeTransfer(IERC20 token, address to, uint256 value) internal {


        _callOptionalReturn(token, abi.encodeWithSelector(token.transfer.selector, to, value));


    }





    function safeTransferFrom(IERC20 token, address from, address to, uint256 value) internal {


        _callOptionalReturn(token, abi.encodeWithSelector(token.transferFrom.selector, from, to, value));


    }





    /**


     * @dev Imitates a Solidity high-level call (i.e. a regular function call to a contract), relaxing the requirement


     * on the return value: the return value is optional (but if data is returned, it must not be false).


     * @param token The token targeted by the call.


     * @param data The call data (encoded using abi.encode or one of its variants).


     */


    function _callOptionalReturn(IERC20 token, bytes memory data) private {


        // We need to perform a low level call here, to bypass Solidity's return data size checking mechanism, since


        // we're implementing it ourselves. We use {Address.functionCall} to perform this call, which verifies that


        // the target address contains contract code and also asserts for success in the low-level call.





        bytes memory returndata = address(token).functionCall(data, "SafeERC20: low-level call failed");


        if (returndata.length > 0) { // Return data is optional


            // solhint-disable-next-line max-line-length


            require(abi.decode(returndata, (bool)), "SafeERC20: ERC20 operation did not succeed");


        }


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


     *


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


     *


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


     *


     * - Subtraction cannot overflow.


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


     *


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


     *


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


     *


     * - The divisor cannot be zero.


     */


    function div(uint256 a, uint256 b, string memory errorMessage) internal pure returns (uint256) {


        require(b > 0, errorMessage);


        uint256 c = a / b;


        // assert(a == b * c + a % b); // There is no case in which this doesn't hold





        return c;


    }





}

contract HappyFarm is Ownable {


    using SafeMath for uint256;


    using SafeERC20 for IERC20;





    // Info of each user.


    struct UserInfo {


        uint256 amount;     // How many LP tokens the user has provided.


        uint256 rewardDebt; // Reward debt. See explanation below.


        //


        // We do some fancy math here. Basically, any point in time, the amount of HPFs


        // entitled to a user but is pending to be distributed is:


        //


        //   pending reward = (user.amount * pool.accHPFPerShare) - user.rewardDebt


        //


        // Whenever a user deposits or withdraws LP tokens to a pool. Here's what happens:


        //   1. The pool's `accHPFPerShare` (and `lastRewardBlock`) gets updated.


        //   2. User receives the pending reward sent to his/her address.


        //   3. User's `amount` gets updated.


        //   4. User's `rewardDebt` gets updated.


    }





    // Info of each pool.


    struct PoolInfo {


        IERC20 lpToken;           // Address of LP token contract.


        uint256 allocPoint;       // How many allocation points assigned to this pool. HPFs to distribute per block.


        uint256 lastRewardBlock;  // Last block number that HPFs distribution occurs.


        uint256 accHPFPerShare; // Accumulated HPFs per share, times 1e12. See below.


    }





    // The HPF TOKEN!


    IHPFToken public HPF;


    // Dev address.


    address public devaddr;


    // Block number when bonus HPF period ends.


    uint256 public bonusEndBlock;


    // HPF tokens created per block.


    uint256 public HPFPerBlock;


    // Bonus muliplier for early HPF makers.


    uint256 public constant BONUS_MULTIPLIER = 12;


    // The governance contract;


    address public governance;





    // Info of each pool.


    PoolInfo[] public poolInfo;


    // Info of each user that stakes LP tokens.


    mapping (uint256 => mapping (address => UserInfo)) public userInfo;


    // Total allocation poitns. Must be the sum of all allocation points in all pools.


    uint256 public totalAllocPoint = 0;


    // The block number when HPF mining starts.


    uint256 public startBlock;


    // The block number when HPF mining ends.


    uint256 public endBlock;





    // The block number when dev can receive it's fee (1 year vesting)


    // Date and time (GMT): 1 year after deploy


    uint256 public devFeeUnlockTime;


    // If dev has requested its fee


    bool public devFeeDelivered;





    event Deposit(address indexed user, uint256 indexed pid, uint256 amount);


    event Withdraw(address indexed user, uint256 indexed pid, uint256 amount);


    event EmergencyWithdraw(address indexed user, uint256 indexed pid, uint256 amount);





    constructor(


        IHPFToken _token,


        address _devaddr,


        uint256 _HPFPerBlock, // 100000000000000000000


        uint256 _startBlock, // 10902300 , https://etherscan.io/block/countdown/10902300


        uint256 _bonusEndBlock, //10930000, https://etherscan.io/block/countdown/10930000


        uint256 _endBlock //11240000 (around 50 days of farming), https://etherscan.io/block/countdown/11240000


    ) {


        HPF = _token;


        devaddr = _devaddr;


        HPFPerBlock = _HPFPerBlock;


        bonusEndBlock = _bonusEndBlock;


        startBlock = _startBlock;


        endBlock = _endBlock;


        devFeeUnlockTime = block.timestamp + 365 * 1 days;


    }





    function poolLength() external view returns (uint256) {


        return poolInfo.length;


    }








    modifier onlyOwnerOrGovernance() {


        require(owner() == _msgSender() || governance == _msgSender(), "Caller is not the owner, neither governance");


        _;


    }





    // Add a new lp to the pool. Can only be called by the owner.


    // XXX DO NOT add the same LP token more than once. Rewards will be messed up if you do.


    function add(uint256 _allocPoint, IERC20 _lpToken, bool _withUpdate) public onlyOwnerOrGovernance {


        if (_withUpdate) {


            massUpdatePools();


        }


        uint256 lastRewardBlock = block.number > startBlock ? block.number : startBlock;


        totalAllocPoint = totalAllocPoint.add(_allocPoint);


        poolInfo.push(PoolInfo({


        lpToken: _lpToken,


        allocPoint: _allocPoint,


        lastRewardBlock: lastRewardBlock,


        accHPFPerShare: 0


        }));


    }





    // Update the given pool's HPF allocation point. Can only be called by the owner or governance contract.


    function updateAllocPoint(uint256 _pid, uint256 _allocPoint, bool _withUpdate) public onlyOwnerOrGovernance {


        if (_withUpdate) {


            massUpdatePools();


        }


        totalAllocPoint = totalAllocPoint.sub(poolInfo[_pid].allocPoint).add(_allocPoint);


        poolInfo[_pid].allocPoint = _allocPoint;


    }





    // Set governance contract. Can only be called by the owner or governance contract.


    function setGovernance(address _governance, bytes memory _setupData) public onlyOwnerOrGovernance {


        governance = _governance;


        (bool success,) = governance.call(_setupData);


        require(success, "setGovernance: failed");


    }





    // Return reward multiplier over the given _from to _to block.


    function getMultiplier(uint256 _from, uint256 _to) public view returns (uint256) {





        //HPF minting ocurrs only until endBLock


        if(_to > endBlock){


            _to = endBlock;


        }





        if (_to <= bonusEndBlock) {


            return _to.sub(_from).mul(BONUS_MULTIPLIER);


        } else if (_from >= bonusEndBlock) {


            return _to.sub(_from);


        } else {


            return bonusEndBlock.sub(_from).mul(BONUS_MULTIPLIER).add(


                _to.sub(bonusEndBlock)


            );


        }


    }





    // View function to see pending HPFs on frontend.


    function pendingHPF(uint256 _pid, address _user) external view returns (uint256) {


        PoolInfo storage pool = poolInfo[_pid];


        UserInfo storage user = userInfo[_pid][_user];


        uint256 accHPFPerShare = pool.accHPFPerShare;


        uint256 lpSupply = pool.lpToken.balanceOf(address(this));


        if (block.number > pool.lastRewardBlock && lpSupply != 0) {


            uint256 multiplier = getMultiplier(pool.lastRewardBlock, block.number);


            uint256 HPFReward = multiplier.mul(HPFPerBlock).mul(pool.allocPoint).div(totalAllocPoint);


            accHPFPerShare = accHPFPerShare.add(HPFReward.mul(1e12).div(lpSupply));


        }


        return user.amount.mul(accHPFPerShare).div(1e12).sub(user.rewardDebt);


    }





    // Update reward vairables for all pools. Be careful of gas spending!


    function massUpdatePools() public {


        uint256 length = poolInfo.length;


        for (uint256 pid = 0; pid < length; ++pid) {


            updatePool(pid);


        }


    }





    // Update reward variables of the given pool to be up-to-date.


    function updatePool(uint256 _pid) public {


        PoolInfo storage pool = poolInfo[_pid];


        if (block.number <= pool.lastRewardBlock) {


            return;


        }


        uint256 lpSupply = pool.lpToken.balanceOf(address(this));


        if (lpSupply == 0) {


            pool.lastRewardBlock = block.number;


            return;


        }


        uint256 multiplier = getMultiplier(pool.lastRewardBlock, block.number);


        uint256 HPFReward = multiplier.mul(HPFPerBlock).mul(pool.allocPoint).div(totalAllocPoint);


        // Dev will have it's 0.5% fee after 1 year, this not necessary


        //HPF.mint(devaddr, HPFReward.div(100));


        HPF.mint(address(this), HPFReward);


        pool.accHPFPerShare = pool.accHPFPerShare.add(HPFReward.mul(1e12).div(lpSupply));


        pool.lastRewardBlock = block.number;


    }





    // Deposit LP tokens to HappyFarm for HPF allocation.


    // You can harvest by calling deposit(_pid,0)





    function deposit(uint256 _pid, uint256 _amount) public {


        PoolInfo storage pool = poolInfo[_pid];


        UserInfo storage user = userInfo[_pid][msg.sender];


        updatePool(_pid);


        if (user.amount > 0) {


            uint256 pending = user.amount.mul(pool.accHPFPerShare).div(1e12).sub(user.rewardDebt);


            safeHPFTransfer(msg.sender, pending);


        }


        pool.lpToken.safeTransferFrom(address(msg.sender), address(this), _amount);


        user.amount = user.amount.add(_amount);


        user.rewardDebt = user.amount.mul(pool.accHPFPerShare).div(1e12);


        emit Deposit(msg.sender, _pid, _amount);


    }





    // Withdraw LP tokens from HappyFarm.


    function withdraw(uint256 _pid, uint256 _amount) public {


        PoolInfo storage pool = poolInfo[_pid];


        UserInfo storage user = userInfo[_pid][msg.sender];


        require(user.amount >= _amount, "withdraw: not enough");


        updatePool(_pid);


        uint256 pending = user.amount.mul(pool.accHPFPerShare).div(1e12).sub(user.rewardDebt);


        safeHPFTransfer(msg.sender, pending);


        user.amount = user.amount.sub(_amount);


        user.rewardDebt = user.amount.mul(pool.accHPFPerShare).div(1e12);


        pool.lpToken.safeTransfer(address(msg.sender), _amount);


        emit Withdraw(msg.sender, _pid, _amount);


    }





    // Withdraw without caring about rewards. EMERGENCY ONLY.


    function emergencyWithdraw(uint256 _pid) public {


        PoolInfo storage pool = poolInfo[_pid];


        UserInfo storage user = userInfo[_pid][msg.sender];


        pool.lpToken.safeTransfer(address(msg.sender), user.amount);


        emit EmergencyWithdraw(msg.sender, _pid, user.amount);


        user.amount = 0;


        user.rewardDebt = 0;


    }





    // Safe HPF transfer function, just in case if rounding error causes pool to not have enough HPFs.


    function safeHPFTransfer(address _to, uint256 _amount) internal {


        uint256 HPFBal = HPF.balanceOf(address(this));


        if (_amount > HPFBal) {


            HPF.transfer(_to, HPFBal);


        } else {


            HPF.transfer(_to, _amount);


        }


    }





    // Update dev address by the previous dev.


    function dev(address _devaddr) public {


        require(msg.sender == devaddr, "dev: wut?");


        devaddr = _devaddr;


    }


    // give dev team its fee. This can ony be called after one year,


    // it's 0.5%





    function devFee() public {


        require(block.timestamp >= devFeeUnlockTime, "devFee: wait until unlock time");


        require(!devFeeDelivered, "devFee: can only be called once");


        HPF.mint(devaddr, HPF.totalSupply().div(200));


        devFeeDelivered=true;


    }


}
