pragma solidity 0.6.12;

abstract contract Context {

    function _msgSender() internal view virtual returns (address payable) {

        return msg.sender;

    }



    function _msgData() internal view virtual returns (bytes memory) {

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



    /**

     * @dev Returns the remainder of dividing two unsigned integers. (unsigned integer modulo),

     * Reverts when dividing by zero.

     *

     * Counterpart to Solidity's `%` operator. This function uses a `revert`

     * opcode (which leaves remaining gas untouched) while Solidity uses an

     * invalid opcode to revert (consuming all remaining gas).

     *

     * Requirements:

     *

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

     *

     * - The divisor cannot be zero.

     */

    function mod(uint256 a, uint256 b, string memory errorMessage) internal pure returns (uint256) {

        require(b != 0, errorMessage);

        return a % b;

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

     * @dev Deprecated. This function has issues similar to the ones found in

     * {IERC20-approve}, and its usage is discouraged.

     *

     * Whenever possible, use {safeIncreaseAllowance} and

     * {safeDecreaseAllowance} instead.

     */

    function safeApprove(IERC20 token, address spender, uint256 value) internal {

        // safeApprove should only be called when setting an initial allowance,

        // or when resetting it to zero. To increase and decrease it, use

        // 'safeIncreaseAllowance' and 'safeDecreaseAllowance'

        // solhint-disable-next-line max-line-length

        require((value == 0) || (token.allowance(address(this), spender) == 0),

            "SafeERC20: approve from non-zero to non-zero allowance"

        );

        _callOptionalReturn(token, abi.encodeWithSelector(token.approve.selector, spender, value));

    }



    function safeIncreaseAllowance(IERC20 token, address spender, uint256 value) internal {

        uint256 newAllowance = token.allowance(address(this), spender).add(value);

        _callOptionalReturn(token, abi.encodeWithSelector(token.approve.selector, spender, newAllowance));

    }



    function safeDecreaseAllowance(IERC20 token, address spender, uint256 value) internal {

        uint256 newAllowance = token.allowance(address(this), spender).sub(value, "SafeERC20: decreased allowance below zero");

        _callOptionalReturn(token, abi.encodeWithSelector(token.approve.selector, spender, newAllowance));

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

        // This method relies in extcodesize, which returns 0 for contracts in

        // construction, since the code is only stored at the end of the

        // constructor execution.



        uint256 size;

        // solhint-disable-next-line no-inline-assembly

        assembly { size := extcodesize(account) }

        return size > 0;

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

     */

    function sendValue(address payable recipient, uint256 amount) internal {

        require(address(this).balance >= amount, "Address: insufficient balance");



        // solhint-disable-next-line avoid-low-level-calls, avoid-call-value

        (bool success, ) = recipient.call{ value: amount }("");

        require(success, "Address: unable to send value, recipient may have reverted");

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



    /**

     * @dev Same as {xref-Address-functionCall-address-bytes-}[`functionCall`],

     * but also transferring `value` wei to `target`.

     *

     * Requirements:

     *

     * - the calling contract must have an ETH balance of at least `value`.

     * - the called Solidity function must be `payable`.

     *

     * _Available since v3.1._

     */

    function functionCallWithValue(address target, bytes memory data, uint256 value) internal returns (bytes memory) {

        return functionCallWithValue(target, data, value, "Address: low-level call with value failed");

    }



    /**

     * @dev Same as {xref-Address-functionCallWithValue-address-bytes-uint256-}[`functionCallWithValue`], but

     * with `errorMessage` as a fallback revert reason when `target` reverts.

     *

     * _Available since v3.1._

     */

    function functionCallWithValue(address target, bytes memory data, uint256 value, string memory errorMessage) internal returns (bytes memory) {

        require(address(this).balance >= value, "Address: insufficient balance for call");

        return _functionCallWithValue(target, data, value, errorMessage);

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

interface IHegicStaking is IERC20 {

    function claimProfit() external returns (uint profit);

    function buy(uint amount) external;

    function sell(uint amount) external;

    function profitOf(address account) external view returns (uint profit);

}

interface IHegicStakingETH is IHegicStaking {

    function sendProfit() external payable;

}

interface IHegicStakingERC20 is IHegicStaking {

    function sendProfit(uint amount) external;

}

contract Migrations {

  address public owner = msg.sender;

  uint public last_completed_migration;



  modifier restricted() {

    require(

      msg.sender == owner,

      "This function is restricted to the contract's owner"

    );

    _;

  }



  function setCompleted(uint completed) public restricted {

    last_completed_migration = completed;

  }

}

contract ERC20 is Context, IERC20 {

    using SafeMath for uint256;

    using Address for address;



    mapping (address => uint256) private _balances;



    mapping (address => mapping (address => uint256)) private _allowances;



    uint256 private _totalSupply;



    string private _name;

    string private _symbol;

    uint8 private _decimals;



    /**

     * @dev Sets the values for {name} and {symbol}, initializes {decimals} with

     * a default value of 18.

     *

     * To select a different value for {decimals}, use {_setupDecimals}.

     *

     * All three of these values are immutable: they can only be set once during

     * construction.

     */

    constructor (string memory name, string memory symbol) public {

        _name = name;

        _symbol = symbol;

        _decimals = 18;

    }



    /**

     * @dev Returns the name of the token.

     */

    function name() public view returns (string memory) {

        return _name;

    }



    /**

     * @dev Returns the symbol of the token, usually a shorter version of the

     * name.

     */

    function symbol() public view returns (string memory) {

        return _symbol;

    }



    /**

     * @dev Returns the number of decimals used to get its user representation.

     * For example, if `decimals` equals `2`, a balance of `505` tokens should

     * be displayed to a user as `5,05` (`505 / 10 ** 2`).

     *

     * Tokens usually opt for a value of 18, imitating the relationship between

     * Ether and Wei. This is the value {ERC20} uses, unless {_setupDecimals} is

     * called.

     *

     * NOTE: This information is only used for _display_ purposes: it in

     * no way affects any of the arithmetic of the contract, including

     * {IERC20-balanceOf} and {IERC20-transfer}.

     */

    function decimals() public view returns (uint8) {

        return _decimals;

    }



    /**

     * @dev See {IERC20-totalSupply}.

     */

    function totalSupply() public view override returns (uint256) {

        return _totalSupply;

    }



    /**

     * @dev See {IERC20-balanceOf}.

     */

    function balanceOf(address account) public view override returns (uint256) {

        return _balances[account];

    }



    /**

     * @dev See {IERC20-transfer}.

     *

     * Requirements:

     *

     * - `recipient` cannot be the zero address.

     * - the caller must have a balance of at least `amount`.

     */

    function transfer(address recipient, uint256 amount) public virtual override returns (bool) {

        _transfer(_msgSender(), recipient, amount);

        return true;

    }



    /**

     * @dev See {IERC20-allowance}.

     */

    function allowance(address owner, address spender) public view virtual override returns (uint256) {

        return _allowances[owner][spender];

    }



    /**

     * @dev See {IERC20-approve}.

     *

     * Requirements:

     *

     * - `spender` cannot be the zero address.

     */

    function approve(address spender, uint256 amount) public virtual override returns (bool) {

        _approve(_msgSender(), spender, amount);

        return true;

    }



    /**

     * @dev See {IERC20-transferFrom}.

     *

     * Emits an {Approval} event indicating the updated allowance. This is not

     * required by the EIP. See the note at the beginning of {ERC20};

     *

     * Requirements:

     * - `sender` and `recipient` cannot be the zero address.

     * - `sender` must have a balance of at least `amount`.

     * - the caller must have allowance for ``sender``'s tokens of at least

     * `amount`.

     */

    function transferFrom(address sender, address recipient, uint256 amount) public virtual override returns (bool) {

        _transfer(sender, recipient, amount);

        _approve(sender, _msgSender(), _allowances[sender][_msgSender()].sub(amount, "ERC20: transfer amount exceeds allowance"));

        return true;

    }



    /**

     * @dev Atomically increases the allowance granted to `spender` by the caller.

     *

     * This is an alternative to {approve} that can be used as a mitigation for

     * problems described in {IERC20-approve}.

     *

     * Emits an {Approval} event indicating the updated allowance.

     *

     * Requirements:

     *

     * - `spender` cannot be the zero address.

     */

    function increaseAllowance(address spender, uint256 addedValue) public virtual returns (bool) {

        _approve(_msgSender(), spender, _allowances[_msgSender()][spender].add(addedValue));

        return true;

    }



    /**

     * @dev Atomically decreases the allowance granted to `spender` by the caller.

     *

     * This is an alternative to {approve} that can be used as a mitigation for

     * problems described in {IERC20-approve}.

     *

     * Emits an {Approval} event indicating the updated allowance.

     *

     * Requirements:

     *

     * - `spender` cannot be the zero address.

     * - `spender` must have allowance for the caller of at least

     * `subtractedValue`.

     */

    function decreaseAllowance(address spender, uint256 subtractedValue) public virtual returns (bool) {

        _approve(_msgSender(), spender, _allowances[_msgSender()][spender].sub(subtractedValue, "ERC20: decreased allowance below zero"));

        return true;

    }



    /**

     * @dev Moves tokens `amount` from `sender` to `recipient`.

     *

     * This is internal function is equivalent to {transfer}, and can be used to

     * e.g. implement automatic token fees, slashing mechanisms, etc.

     *

     * Emits a {Transfer} event.

     *

     * Requirements:

     *

     * - `sender` cannot be the zero address.

     * - `recipient` cannot be the zero address.

     * - `sender` must have a balance of at least `amount`.

     */

    function _transfer(address sender, address recipient, uint256 amount) internal virtual {

        require(sender != address(0), "ERC20: transfer from the zero address");

        require(recipient != address(0), "ERC20: transfer to the zero address");



        _beforeTokenTransfer(sender, recipient, amount);



        _balances[sender] = _balances[sender].sub(amount, "ERC20: transfer amount exceeds balance");

        _balances[recipient] = _balances[recipient].add(amount);

        emit Transfer(sender, recipient, amount);

    }



    /** @dev Creates `amount` tokens and assigns them to `account`, increasing

     * the total supply.

     *

     * Emits a {Transfer} event with `from` set to the zero address.

     *

     * Requirements

     *

     * - `to` cannot be the zero address.

     */

    function _mint(address account, uint256 amount) internal virtual {

        require(account != address(0), "ERC20: mint to the zero address");



        _beforeTokenTransfer(address(0), account, amount);



        _totalSupply = _totalSupply.add(amount);

        _balances[account] = _balances[account].add(amount);

        emit Transfer(address(0), account, amount);

    }



    /**

     * @dev Destroys `amount` tokens from `account`, reducing the

     * total supply.

     *

     * Emits a {Transfer} event with `to` set to the zero address.

     *

     * Requirements

     *

     * - `account` cannot be the zero address.

     * - `account` must have at least `amount` tokens.

     */

    function _burn(address account, uint256 amount) internal virtual {

        require(account != address(0), "ERC20: burn from the zero address");



        _beforeTokenTransfer(account, address(0), amount);



        _balances[account] = _balances[account].sub(amount, "ERC20: burn amount exceeds balance");

        _totalSupply = _totalSupply.sub(amount);

        emit Transfer(account, address(0), amount);

    }



    /**

     * @dev Sets `amount` as the allowance of `spender` over the `owner` s tokens.

     *

     * This internal function is equivalent to `approve`, and can be used to

     * e.g. set automatic allowances for certain subsystems, etc.

     *

     * Emits an {Approval} event.

     *

     * Requirements:

     *

     * - `owner` cannot be the zero address.

     * - `spender` cannot be the zero address.

     */

    function _approve(address owner, address spender, uint256 amount) internal virtual {

        require(owner != address(0), "ERC20: approve from the zero address");

        require(spender != address(0), "ERC20: approve to the zero address");



        _allowances[owner][spender] = amount;

        emit Approval(owner, spender, amount);

    }



    /**

     * @dev Sets {decimals} to a value other than the default one of 18.

     *

     * WARNING: This function should only be called from the constructor. Most

     * applications that interact with token contracts will not expect

     * {decimals} to ever change, and may work incorrectly if it does.

     */

    function _setupDecimals(uint8 decimals_) internal {

        _decimals = decimals_;

    }



    /**

     * @dev Hook that is called before any transfer of tokens. This includes

     * minting and burning.

     *

     * Calling conditions:

     *

     * - when `from` and `to` are both non-zero, `amount` of ``from``'s tokens

     * will be to transferred to `to`.

     * - when `from` is zero, `amount` tokens will be minted for `to`.

     * - when `to` is zero, `amount` of ``from``'s tokens will be burned.

     * - `from` and `to` are never both zero.

     *

     * To learn more about hooks, head to xref:ROOT:extending-contracts.adoc#using-hooks[Using Hooks].

     */

    function _beforeTokenTransfer(address from, address to, uint256 amount) internal virtual { }

}

abstract contract HegicPooledStaking is Ownable, ERC20{

    using SafeMath for uint;

    using SafeERC20 for IERC20;



    // HEGIC token

    IERC20 public immutable HEGIC;



    // Hegic Protocol Staking Contract 

    IHegicStaking public staking;



    // Parameters

    uint public LOCK_UP_PERIOD = 24 hours;

    uint public STAKING_LOT_PRICE = 888_000e18;

    uint public ACCURACY = 1e30;

    address payable public FALLBACK_RECIPIENT;

    address payable public FEE_RECIPIENT;

    uint public FEE;



    // Monitoring variables

    uint public numberOfStakingLots;

    uint public totalBalance;

    uint public lockedBalance;

    uint public totalProfitPerToken;

    bool public emergencyUnlockState;

    bool public depositsAllowed;



    // Staking lots mappings

    mapping(uint => mapping(address => uint)) stakingLotShares;

    mapping(uint => address[]) stakingLotOwners;

    mapping(uint => uint) stakingLotUnlockTime;

    mapping(uint => bool) stakingLotActive;

    mapping(uint => uint) startProfit;



    // Owners mappings

    mapping(address => uint[]) ownedStakingLots; 

    mapping(address => uint) savedProfit; 

    mapping(address => uint) lastProfit; 

    mapping(address => uint) ownerPerformanceFee;



    // Events

    event Deposit(address account, uint amount);

    event Withdraw(address account, uint amount);

    event AddLiquidity(address account, uint amount, uint lotId);

    event BuyLot(address account, uint lotId);

    event SellLot(address account, uint lotId);

    event PayProfit(address account, uint profit, uint fee);



    constructor(IERC20 _token, IHegicStaking _staking, string memory name, string memory symbol) public ERC20(name, symbol){

        HEGIC = _token;

        staking = _staking;

        totalBalance = 0;

        lockedBalance = 0;

        numberOfStakingLots = 0;

        totalProfitPerToken = 0;

        

        FALLBACK_RECIPIENT = msg.sender;

        FEE_RECIPIENT = msg.sender;

        FEE = 5;



        emergencyUnlockState = false;

        depositsAllowed = true;



        // Approving to Staking Lot Contract

        _token.approve(address(_staking), 888e30);

    }



    // Payable 

    receive() external payable {}



    /**

     * @notice Lets the owner deactivate lockUp period. This means that if set to true, 

     * staking lot owners will be able to exitFromStakingLot immediately. 

     * Reserved for emergency cases only (e.g. migration of liquidity).

     * OWNER WILL NOT BE ABLE TO WITHDRAW FUNDS; ONLY UNLOCK FUNDS FOR YOU TO WITHDRAW THEM.

     * @param _unlock true or false, default = false. If set to true, owners will be able to withdraw HEGIC

     * immediately

     */

    function emergencyUnlock(bool _unlock) external onlyOwner {

        emergencyUnlockState = _unlock;

    }



    /**

     * @notice Stops the ability to add new deposits

     * @param _allow If set to false, new deposits will be rejected

     */

    function allowDeposits(bool _allow) external onlyOwner {

        depositsAllowed = _allow;

    }



    /**

     * @notice Changes Fee paid to creator (only paid when taking profits)

     * @param _fee New fee

     */

    function changeFee(uint _fee) external onlyOwner {

        require(_fee >= 0, "Fee too low");

        require(_fee <= 8, "Fee too high");

        

        FEE = _fee;

    }



    /**

     * @notice Changes Fee Recipient address

     * @param _recipient New address

     */

    function changeFeeRecipient(address _recipient) external onlyOwner {

        FEE_RECIPIENT = payable(_recipient);

    }



     /**

     * @notice Changes Fallback Recipient address. This is only used in case of unexpected behavior

     * @param _recipient New address

     */

    function changeFallbackRecipient(address _recipient) external onlyOwner {

        FALLBACK_RECIPIENT = payable(_recipient);

    }



    /**

     * @notice Changes lock up period. This lock up period is used to lock funds in a staking for for at least some time

     * IMPORTANT: Changes only apply to new Staking Lots

     * @param _newLockUpPeriod New lock up period in seconds

     */

    function changeLockUpPeriod(uint _newLockUpPeriod) external onlyOwner {

        require(_newLockUpPeriod <= 2 weeks, "Lock up period too long");

        require(_newLockUpPeriod >= 24 hours, "Lock up period too short");

        LOCK_UP_PERIOD = _newLockUpPeriod;

    }



    /**

     * @notice Main EXTERNAL function. Deposits HEGIC for the next staking lot. 

     * If not enough, deposits will be stored until at least 888_000 HEGIC are available.

     * Then, the contract will buy a Hegic Staking Lot. 

     * Once a Staking Lot is bought, users have to wait LOCK_UP_PERIOD (default = 2 weeks) to withdraw funds.

     * @param _HEGICAmount Amount of HEGIC to deposit in next staking lot

     */

    function deposit(uint _HEGICAmount) external {

        require(_HEGICAmount > 0, "Amount too low");

        require(_HEGICAmount < STAKING_LOT_PRICE, "Amount too high, buy your own lot");

        require(depositsAllowed, "Deposits are not allowed at the moment");



        // set fee for that staking lot owner - this effectively sets the maximum FEE an owner can have

        // each time user deposits, this checks if current fee is higher or lower than previous fees

        // and updates it if it is lower

        if(ownerPerformanceFee[msg.sender] > FEE || balanceOf(msg.sender) == 0) 

            ownerPerformanceFee[msg.sender] = FEE;



        //receive deposit

        depositHegic(_HEGICAmount);



        // use new liquidity (either stores it for next purchase or purchases right away)

        useLiquidity(_HEGICAmount, msg.sender);



        emit Deposit(msg.sender, _HEGICAmount);

    }



    /**

     * @notice Internal function to transfer deposited HEGIC to the contract and mint sHEGIC (Staked HEGIC)

     * @param _HEGICAmount Amount of HEGIC to deposit // Amount of sHEGIC that will be minted

     */

    function depositHegic(uint _HEGICAmount) internal {

        totalBalance = totalBalance.add(_HEGICAmount); 



        _mint(msg.sender, _HEGICAmount);



        HEGIC.safeTransferFrom(msg.sender, address(this), _HEGICAmount);

    }



    /**

     * @notice Use certain amount of liquidity. Internal function in charge of buying a new lot if enough balance.

     * If there is not enough balance to buy a new lot, it will store the HEGIC

     * If available balance + _HEGICAmount is higher than STAKING_LOT_PRICE (888_000HEGIC), the remaining 

     * amount will be stored for the next staking lot purchase. This remaining amount can be withdrawed with no lock up period

     * 

     * @param _HEGICAmount Amount of HEGIC to be used 

     * @param _account Account that owns _HEGICAmount to which any purchase will be credited to

     */

    function useLiquidity(uint _HEGICAmount, address _account) internal {

        if(totalBalance.sub(lockedBalance) >= STAKING_LOT_PRICE){

            uint pendingAmount = totalBalance.sub(lockedBalance).sub(STAKING_LOT_PRICE);

            addToNextLot(_HEGICAmount.sub(pendingAmount), _account); 

            buyStakingLot();

            if(pendingAmount > 0) addToNextLot(pendingAmount, _account);

        } else {

            addToNextLot(_HEGICAmount, _account);

        }

    }



    /**

     * @notice Internal function in charge of buying a new Staking Lot from the Hegic Staking Contract

     * Also, it will set up the Lock up AND increase the number of staking lots

     */

    function buyStakingLot() internal {

        lockedBalance = lockedBalance.add(STAKING_LOT_PRICE);

        staking.buy(1);

        emit BuyLot(msg.sender, numberOfStakingLots);



        startProfit[numberOfStakingLots] = totalProfitPerToken;

        stakingLotUnlockTime[numberOfStakingLots] = now + LOCK_UP_PERIOD;

        stakingLotActive[numberOfStakingLots] = true;



        numberOfStakingLots = numberOfStakingLots + 1;

    }



        /**

     * @notice Internal function in charge of adding the _amount HEGIC to the next lot ledger.

     * User will be added as an owner of the lot and will be credited with _amount shares of that lot (total = 888_000 shares)

     * @param _amount Amount of HEGIC to be used 

     * @param _account Account to which _amount will be credited to

     */

    function addToNextLot(uint _amount, address _account) internal {

        if(stakingLotShares[numberOfStakingLots][_account] == 0) {

            ownedStakingLots[_account].push(numberOfStakingLots); // if first contribution in this lot: add to list

            stakingLotOwners[numberOfStakingLots].push(_account);

        }



        // add to shares in next Staking Lot

        stakingLotShares[numberOfStakingLots][_account] = stakingLotShares[numberOfStakingLots][_account].add(_amount);

        

        emit AddLiquidity(_account, _amount, numberOfStakingLots);

    }



    /**

     * @notice internal function that withdraws HEGIC deposited in exchange of sHEGIC

     * 

     * @param _amount Amount of sHEGIC to be burned // Amount of HEGIC to be received 

     */

    function exchangeStakedForReal(uint _amount) internal {

        totalBalance = totalBalance.sub(_amount);

        _burn(msg.sender, _amount);

        HEGIC.safeTransfer(msg.sender, _amount);



        emit Withdraw(msg.sender, _amount);

    }



    /**

     * @notice Main EXTERNAL function. This function is called to exit from a certain Staking Lot

     * Calling this function will result in the withdrawal of allocated HEGIC for msg.sender

     * Owners that are not withdrawing funds will be credited with shares of the next lot to be purchased

     * 

     * @param _slotId Amount of HEGIC to be used 

     */

    function exitFromStakingLot(uint _slotId) external {

        require(stakingLotShares[_slotId][msg.sender] > 0, "Not participating in this lot");

        require(_slotId <= numberOfStakingLots, "Staking lot not found");



        // if HEGIC not yet staked

        if(_slotId == numberOfStakingLots){

            uint shares = stakingLotShares[_slotId][msg.sender];

            stakingLotShares[_slotId][msg.sender] = 0;

            exchangeStakedForReal(shares);

        } else {

            require((stakingLotUnlockTime[_slotId] <= now) || emergencyUnlockState, "Staking Lot is still locked");

            // it is important to withdraw unused funds first to avoid re-ordering attack

            require(stakingLotShares[numberOfStakingLots][msg.sender] == 0, "Please withdraw your non-staked liquidity first");        

            

            // sell lot

            staking.sell(1);

            emit SellLot(msg.sender, _slotId);

            stakingLotActive[_slotId] = false;



            address[] memory slOwners = stakingLotOwners[_slotId];



            // I unlock and withdraw msg.sender funds to avoid using her funds in the for loop

            uint shares = stakingLotShares[_slotId][msg.sender]; 

            stakingLotShares[_slotId][msg.sender] = 0;

            exchangeStakedForReal(shares);

            lockedBalance -= shares;



            address owner;

            for(uint i = 0; i < slOwners.length; i++) {

                owner = slOwners[i];

                shares = stakingLotShares[_slotId][owner];

                stakingLotShares[_slotId][owner] = 0; // put back to 0 the participation in this lot



                // put liquidity into next staking lot OR pay staked Hegic back if msg.sender

                if(owner != msg.sender) {

                    lockedBalance -= shares;

                    saveProfit(owner);

                    useLiquidity(shares, owner);

                }

            }

        }

    }



    /**

     * @notice Virtual function. To be called to claim Profit from Hegic Staking Contracts.

     * It will update profit of current staking lot owners

     */

    function updateProfit() public virtual;



    /**

     * @notice EXTERNAL function. Calling this function will result in receiving profits accumulated

     * during the time the HEGIC were deposited

     * 

     */

    function claimProfit() external {

        uint profit = saveProfit(msg.sender);

        savedProfit[msg.sender] = 0;

        _transferProfit(profit, msg.sender, ownerPerformanceFee[msg.sender]);

        emit PayProfit(msg.sender, profit, ownerPerformanceFee[msg.sender]);

    }



    /**

     * @notice Support function. Calculates how much of the totalProfitPerToken is not to be paid to an account

     * This may be because it was already paid, it was earned before HEGIC were staked, ...

     * 

     * @param _account Amount of HEGIC to be used 

     */

    function getNotPayableProfit(address _account) public view returns (uint notPayableProfit) {

        if(ownedStakingLots[_account].length > 0){

            uint lastStakingLot = ownedStakingLots[_account][ownedStakingLots[_account].length-1];

            uint accountLastProfit = lastProfit[_account];



            if(accountLastProfit <= startProfit[lastStakingLot]) {

                // previous lastProfit * number of shares excluding last contribution (Last Staking Lot) + start Profit of Last Staking Lot

                uint lastTakenProfit = accountLastProfit.mul(balanceOf(_account).sub(stakingLotShares[lastStakingLot][_account]));

                uint initialNotPayableProfit = startProfit[lastStakingLot].mul(stakingLotShares[lastStakingLot][_account]);

                notPayableProfit = lastTakenProfit.add(initialNotPayableProfit);

            } else {

                notPayableProfit = accountLastProfit.mul(balanceOf(_account).sub(getUnlockedTokens(_account)));

            }

        }

    }



    /**

     * @notice Support function. Calculates how many of the deposited tokens are not currently staked

     * These are not producing profits

     * 

     * @param _account Amount of HEGIC to be used 

     */

    function getUnlockedTokens(address _account) public view returns (uint lockedTokens){

         if(ownedStakingLots[_account].length > 0) {

            uint lastStakingLot = ownedStakingLots[_account][ownedStakingLots[_account].length-1];

            if(lastStakingLot == numberOfStakingLots) lockedTokens = stakingLotShares[lastStakingLot][_account];

         }

    }



    /**

     * @notice Support function. Calculates how many of the deposited tokens are not currently staked

     * These are not producing profits and will not be accounted for profit calcs.

     * 

     * @param _account Account 

     */

    function getUnsaved(address _account) public view returns (uint profit) {

        uint accountBalance = balanceOf(_account);

        uint unlockedTokens = getUnlockedTokens(_account);

        uint tokens = accountBalance.sub(unlockedTokens);

        profit = 0;

        if(tokens > 0) 

            profit = totalProfitPerToken.mul(tokens).sub(getNotPayableProfit(_account)).div(ACCURACY);

    }



    /**

     * @notice Support function. Calculates how much profit would receive each token if the contract claimed

     * profit accumulated in Hegic's Staking Lot contracts

     * 

     * @param _account Account to do the calculation to

     */

    function getUnreceivedProfit(address _account) public view returns (uint unreceived){

        uint accountBalance = balanceOf(_account);

        uint unlockedTokens = getUnlockedTokens(_account);

        uint tokens = accountBalance.sub(unlockedTokens);

        uint profit = staking.profitOf(address(this));

        if(lockedBalance > 0)

            unreceived = profit.mul(ACCURACY).div(lockedBalance).mul(tokens).div(ACCURACY);

        else

            unreceived = 0;

    }



    /**

     * @notice EXTERNAL View function. Returns profit to be paid when claimed for _account

     * 

     * @param _account Account 

     */

    function profitOf(address _account) external view returns (uint profit) {

        uint unreceived = getUnreceivedProfit(_account);

        return savedProfit[_account].add(getUnsaved(_account)).add(unreceived);

    }



    /**

     * @notice Internal function that saves unpaid profit to keep accounting.

     * 

     * @param _account Account to save profit to

     */

    function saveProfit(address _account) internal returns (uint profit) {

        updateProfit();

        uint unsaved = getUnsaved(_account);

        lastProfit[_account] = totalProfitPerToken;

        profit = savedProfit[_account].add(unsaved);

        savedProfit[_account] = profit;

    }



    /**

     * @notice Support function. Relevant to the profit system. It will save state of profit before each 

     * token transfer (either deposit or withdrawal)

     * 

     * @param from Account sending tokens 

     * @param to Account receiving tokens

     */

    function _beforeTokenTransfer(address from, address to, uint256) internal override {

        if (from != address(0)) saveProfit(from);

        if (to != address(0)) saveProfit(to);

    }



    /**

     * @notice Virtual Internal function. It handles specific code to actually send the profits. 

     * 

     * @param _amount Profit (amount being transferred)

     * @param _account Account receiving profits

     * @param _fee Fee that is being paid to FEE_RECIPIENT (always less than 8%)

     */

    function _transferProfit(uint _amount, address _account, uint _fee) internal virtual;



    /**

     * @notice Public function returning the number of shares that an account holds per specific staking lot

     * 

     * @param _slotId Staking Lot Id

     * @param _account Account

     */

    function getStakingLotShares(uint _slotId, address _account) view public returns (uint) {

        return stakingLotShares[_slotId][_account];

    }



    /**

     * @notice Returns boolean telling if lot is still in lock up period or not

     * 

     * @param _slotId Staking Lot Id

     */

    function isInLockUpPeriod(uint _slotId) view public returns (bool) {

        return !((stakingLotUnlockTime[_slotId] <= now) || emergencyUnlockState);

    }



    /**

     * @notice Returns boolean telling if lot is active or not

     * 

     * @param _slotId Staking Lot Id

     */

    function isActive(uint _slotId) view public returns (bool) {

        return stakingLotActive[_slotId];

    }



    /**

     * @notice Returns list of staking lot owners

     * 

     * @param _slotId Staking Lot Id

     */

    function getLotOwners(uint _slotId) view public returns (address[] memory slOwners) {

        slOwners = stakingLotOwners[_slotId];

    }



    /**

     * @notice Returns performance fee for this specific owner

     * 

     * @param _account Account's address

     */

    function getOwnerPerformanceFee(address _account) view public returns (uint performanceFee) {

        performanceFee = ownerPerformanceFee[_account];

    }





}

contract HegicPooledStakingETH is HegicPooledStaking {



    constructor(IERC20 _token, IHegicStaking _staking) public HegicPooledStaking(_token, _staking, "ETH Staked HEGIC", "sHEGICETH") {

    }



    function _transferProfit(uint _amount, address _account, uint _fee) internal override{

        uint netProfit = _amount.mul(uint(100).sub(_fee)).div(100);

        payable(_account).transfer(netProfit);

        FEE_RECIPIENT.transfer(_amount.sub(netProfit));

    }



    function updateProfit() public override {

        uint profit = staking.profitOf(address(this));

        if(profit > 0) profit = staking.claimProfit();

        if(lockedBalance <= 0) FALLBACK_RECIPIENT.transfer(profit);

        else totalProfitPerToken = totalProfitPerToken.add(profit.mul(ACCURACY).div(lockedBalance));

    }

}

contract HegicPooledStakingWBTC is HegicPooledStaking {



    IERC20 public immutable underlying;



    constructor(IERC20 _token, IHegicStaking _staking, IERC20 _underlying) public 

        HegicPooledStaking(_token, _staking, "WBTC Staked HEGIC", "sHEGICWBTC") {

        underlying = _underlying;

    }



     /**

     * @notice Support internal function. Calling it will transfer _amount WBTC to _account. 

     * If FEE > 0, a FEE% commission will be paid to FEE_RECIPIENT

     * @param _amount Amount to transfer

     * @param _account Account that will receive profit

     */

    function _transferProfit(uint _amount, address _account, uint _fee) internal override {

        uint netProfit = _amount.mul(uint(100).sub(_fee)).div(100);

        underlying.safeTransfer(_account, netProfit);

        underlying.safeTransfer(FEE_RECIPIENT, _amount.sub(netProfit));

    }



    /**

     * @notice claims profit from Hegic's Staking Contrats and splits it among all currently staked tokens

     */

    function updateProfit() public override {

        uint profit = staking.profitOf(address(this));

        if(profit > 0){ 

            profit = staking.claimProfit();

            if(lockedBalance <= 0) underlying.safeTransfer(FALLBACK_RECIPIENT, profit);

            else totalProfitPerToken = totalProfitPerToken.add(profit.mul(ACCURACY).div(lockedBalance));

        }

    }

}

contract FakeHegicStakingETH is ERC20("Hegic ETH Staking Lot", "hlETH"), IHegicStakingETH {

    using SafeMath for uint;

    using SafeERC20 for IERC20;

    uint public LOT_PRICE = 888_000e18;

    IERC20 public token;



    uint public totalProfit;

    

    event Claim(address account, uint profit);



    constructor(IERC20 _token) public {

        totalProfit = 0;

        token = _token;

        _setupDecimals(0);

    }



    function sendProfit() external payable override {

        totalProfit = totalProfit.add(msg.value);

    }



    function claimProfit() external override returns (uint _profit) {

        _profit = totalProfit;

        require(_profit > 0, "Zero profit");

        emit Claim(msg.sender, _profit);   

        _transferProfit(_profit);

        totalProfit = totalProfit.sub(_profit);

    }



    function _transferProfit(uint _profit) internal {

        msg.sender.transfer(_profit);

    }



    function buy(uint _amount) external override {

        require(_amount > 0, "Amount is zero");

        _mint(msg.sender, _amount);

        token.safeTransferFrom(msg.sender, address(this), _amount.mul(LOT_PRICE));



    }



    function sell(uint _amount) external override {

        _burn(msg.sender, _amount);

        token.safeTransfer(msg.sender, _amount.mul(LOT_PRICE));

    }



    function profitOf(address) public view override returns (uint _totalProfit) {

        _totalProfit = totalProfit;

    }

}

contract FakeHegicStakingWBTC is ERC20("Hegic WBTC Staking Lot", "hlWBTC"), IHegicStakingERC20 {

    using SafeMath for uint;

    using SafeERC20 for IERC20;



    uint public totalProfit;

    IERC20 public immutable WBTC;

    IERC20 public token;



    uint public LOT_PRICE = 888_000e18;



    event Claim(address account, uint profit);



    constructor(IERC20 _wbtc, IERC20 _token) public {

        WBTC = _wbtc;

        token = _token;

        totalProfit = 0;

        _setupDecimals(0);



    }



    function sendProfit(uint _amount) external override {

        WBTC.safeTransferFrom(msg.sender, address(this), _amount);

        totalProfit = totalProfit.add(_amount);

    }



    function claimProfit() external override returns (uint _profit) {

        _profit = totalProfit;

        require(_profit > 0, "Zero profit");

        emit Claim(msg.sender, _profit);   

        _transferProfit(_profit);

        totalProfit = totalProfit.sub(_profit);

    }



    function _transferProfit(uint _profit) internal {

        WBTC.safeTransfer(msg.sender, _profit);

    }



    function buy(uint _amount) external override {

        require(_amount > 0, "Amount is zero");

        _mint(msg.sender, _amount);

        token.safeTransferFrom(msg.sender, address(this), _amount.mul(LOT_PRICE));

    }



    function sell(uint _amount) external override {

        _burn(msg.sender, _amount);

        token.safeTransfer(msg.sender, _amount.mul(LOT_PRICE));

    }



    function profitOf(address) public view override returns (uint _totalProfit) {

        _totalProfit = totalProfit;

    }

}

contract FakeWBTC is ERC20("FakeWBTC", "FAKE") {

    constructor() public {

        _setupDecimals(8);

    }



    function mintTo(address account, uint256 amount) public {

        _mint(account, amount);

    }



    function mint(uint256 amount) public {

        _mint(msg.sender, amount);

    }

}

contract FakeHEGIC is ERC20("FakeHEGIC", "FAKEH") {

    using SafeERC20 for ERC20;



    function mintTo(address account, uint256 amount) public {

        _mint(account, amount);

    }



    function mint(uint256 amount) public {

        _mint(msg.sender, amount);

    }

}
