pragma solidity 0.5.17;
pragma experimental ABIEncoderV2;

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

library Counters {

    using SafeMath for uint256;



    struct Counter {

        // This variable should never be directly accessed by users of the library: interactions must be restricted to

        // the library's function. As of Solidity v0.5.2, this cannot be enforced, though there is a proposal to add

        // this feature: see https://github.com/ethereum/solidity/issues/4637

        uint256 _value; // default: 0

    }



    function current(Counter storage counter) internal view returns (uint256) {

        return counter._value;

    }



    function increment(Counter storage counter) internal {

        // The {SafeMath} overflow check can be skipped here, see the comment at the top

        counter._value += 1;

    }



    function decrement(Counter storage counter) internal {

        counter._value = counter._value.sub(1);

    }

}

interface IERC165 {

    /**

     * @dev Returns true if this contract implements the interface defined by

     * `interfaceId`. See the corresponding

     * https://eips.ethereum.org/EIPS/eip-165#how-interfaces-are-identified[EIP section]

     * to learn more about how these ids are created.

     *

     * This function call must use less than 30 000 gas.

     */

    function supportsInterface(bytes4 interfaceId) external view returns (bool);

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

contract IERC721 is IERC165 {

    event Transfer(address indexed from, address indexed to, uint256 indexed tokenId);

    event Approval(address indexed owner, address indexed approved, uint256 indexed tokenId);

    event ApprovalForAll(address indexed owner, address indexed operator, bool approved);



    /**

     * @dev Returns the number of NFTs in `owner`'s account.

     */

    function balanceOf(address owner) public view returns (uint256 balance);



    /**

     * @dev Returns the owner of the NFT specified by `tokenId`.

     */

    function ownerOf(uint256 tokenId) public view returns (address owner);



    /**

     * @dev Transfers a specific NFT (`tokenId`) from one account (`from`) to

     * another (`to`).

     *

     *

     *

     * Requirements:

     * - `from`, `to` cannot be zero.

     * - `tokenId` must be owned by `from`.

     * - If the caller is not `from`, it must be have been allowed to move this

     * NFT by either {approve} or {setApprovalForAll}.

     */

    function safeTransferFrom(address from, address to, uint256 tokenId) public;

    /**

     * @dev Transfers a specific NFT (`tokenId`) from one account (`from`) to

     * another (`to`).

     *

     * Requirements:

     * - If the caller is not `from`, it must be approved to move this NFT by

     * either {approve} or {setApprovalForAll}.

     */

    function transferFrom(address from, address to, uint256 tokenId) public;

    function approve(address to, uint256 tokenId) public;

    function getApproved(uint256 tokenId) public view returns (address operator);



    function setApprovalForAll(address operator, bool _approved) public;

    function isApprovedForAll(address owner, address operator) public view returns (bool);





    function safeTransferFrom(address from, address to, uint256 tokenId, bytes memory data) public;

}

contract IERC721Metadata is IERC721 {

    function name() external view returns (string memory);

    function symbol() external view returns (string memory);

    function tokenURI(uint256 tokenId) external view returns (string memory);

}

contract IERC721Receiver {

    /**

     * @notice Handle the receipt of an NFT

     * @dev The ERC721 smart contract calls this function on the recipient

     * after a {IERC721-safeTransferFrom}. This function MUST return the function selector,

     * otherwise the caller will revert the transaction. The selector to be

     * returned can be obtained as `this.onERC721Received.selector`. This

     * function MAY throw to revert and reject the transfer.

     * Note: the ERC721 contract address is always the message sender.

     * @param operator The address which called `safeTransferFrom` function

     * @param from The address which previously owned the token

     * @param tokenId The NFT identifier which is being transferred

     * @param data Additional data with no specified format

     * @return bytes4 `bytes4(keccak256("onERC721Received(address,address,uint256,bytes)"))`

     */

    function onERC721Received(address operator, address from, uint256 tokenId, bytes memory data)

    public returns (bytes4);

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

contract ReentrancyGuard {

    bool private _notEntered;



    constructor () internal {

        // Storing an initial non-zero value makes deployment a bit more

        // expensive, but in exchange the refund on every call to nonReentrant

        // will be lower in amount. Since refunds are capped to a percetange of

        // the total transaction's gas, it is best to keep them low in cases

        // like this one, to increase the likelihood of the full refund coming

        // into effect.

        _notEntered = true;

    }



    /**

     * @dev Prevents a contract from calling itself, directly or indirectly.

     * Calling a `nonReentrant` function from another `nonReentrant`

     * function is not supported. It is possible to prevent this from happening

     * by making the `nonReentrant` function external, and make it call a

     * `private` function that does the actual work.

     */

    modifier nonReentrant() {

        // On the first call to nonReentrant, _notEntered will be true

        require(_notEntered, "ReentrancyGuard: reentrant call");



        // Any calls to nonReentrant after this point will fail

        _notEntered = false;



        _;



        // By storing the original value once again, a refund is triggered (see

        // https://eips.ethereum.org/EIPS/eip-2200)

        _notEntered = true;

    }

}

contract DInterest is ReentrancyGuard, Ownable {

    using SafeMath for uint256;

    using DecMath for uint256;

    using SafeERC20 for ERC20;

    using Address for address;



    // Constants

    uint256 internal constant PRECISION = 10**18;

    uint256 internal constant ONE = 10**18;



    // User deposit data

    // Each deposit has an ID used in the depositNFT, which is equal to its index in `deposits` plus 1

    struct Deposit {

        uint256 amount; // Amount of stablecoin deposited

        uint256 maturationTimestamp; // Unix timestamp after which the deposit may be withdrawn, in seconds

        uint256 interestOwed; // Deficit incurred to the pool at time of deposit

        uint256 initialMoneyMarketIncomeIndex; // Money market's income index at time of deposit

        bool active; // True if not yet withdrawn, false if withdrawn

        bool finalSurplusIsNegative;

        uint256 finalSurplusAmount; // Surplus remaining after withdrawal

        uint256 mintMPHAmount; // Amount of MPH minted to user

    }

    Deposit[] internal deposits;

    uint256 public latestFundedDepositID; // the ID of the most recently created deposit that was funded

    uint256 public unfundedUserDepositAmount; // the deposited stablecoin amount whose deficit hasn't been funded



    // Funding data

    // Each funding has an ID used in the fundingNFT, which is equal to its index in `fundingList` plus 1

    struct Funding {

        // deposits with fromDepositID < ID <= toDepositID are funded

        uint256 fromDepositID;

        uint256 toDepositID;

        uint256 recordedFundedDepositAmount;

        uint256 recordedMoneyMarketIncomeIndex;

    }

    Funding[] internal fundingList;



    // Params

    uint256 public MinDepositPeriod; // Minimum deposit period, in seconds

    uint256 public MaxDepositPeriod; // Maximum deposit period, in seconds

    uint256 public MinDepositAmount; // Minimum deposit amount for each deposit, in stablecoins

    uint256 public MaxDepositAmount; // Maximum deposit amount for each deposit, in stablecoins



    // Instance variables

    uint256 public totalDeposit;

    uint256 public totalInterestOwed;



    // External smart contracts

    IMoneyMarket public moneyMarket;

    ERC20 public stablecoin;

    IFeeModel public feeModel;

    IInterestModel public interestModel;

    IInterestOracle public interestOracle;

    NFT public depositNFT;

    NFT public fundingNFT;

    MPHMinter public mphMinter;



    // Events

    event EDeposit(

        address indexed sender,

        uint256 indexed depositID,

        uint256 amount,

        uint256 maturationTimestamp,

        uint256 interestAmount,

        uint256 mintMPHAmount

    );

    event EWithdraw(

        address indexed sender,

        uint256 indexed depositID,

        uint256 indexed fundingID,

        bool early,

        uint256 takeBackMPHAmount

    );

    event EFund(

        address indexed sender,

        uint256 indexed fundingID,

        uint256 deficitAmount,

        uint256 mintMPHAmount

    );

    event ESetParamAddress(

        address indexed sender,

        string indexed paramName,

        address newValue

    );

    event ESetParamUint(

        address indexed sender,

        string indexed paramName,

        uint256 newValue

    );



    struct DepositLimit {

        uint256 MinDepositPeriod;

        uint256 MaxDepositPeriod;

        uint256 MinDepositAmount;

        uint256 MaxDepositAmount;

    }



    constructor(

        DepositLimit memory _depositLimit,

        address _moneyMarket, // Address of IMoneyMarket that's used for generating interest (owner must be set to this DInterest contract)

        address _stablecoin, // Address of the stablecoin used to store funds

        address _feeModel, // Address of the FeeModel contract that determines how fees are charged

        address _interestModel, // Address of the InterestModel contract that determines how much interest to offer

        address _interestOracle, // Address of the InterestOracle contract that provides the average interest rate

        address _depositNFT, // Address of the NFT representing ownership of deposits (owner must be set to this DInterest contract)

        address _fundingNFT, // Address of the NFT representing ownership of fundings (owner must be set to this DInterest contract)

        address _mphMinter // Address of the contract for handling minting MPH to users

    ) public {

        // Verify input addresses

        require(

            _moneyMarket.isContract() &&

                _stablecoin.isContract() &&

                _feeModel.isContract() &&

                _interestModel.isContract() &&

                _interestOracle.isContract() &&

                _depositNFT.isContract() &&

                _fundingNFT.isContract() &&

                _mphMinter.isContract(),

            "DInterest: An input address is not a contract"

        );



        moneyMarket = IMoneyMarket(_moneyMarket);

        stablecoin = ERC20(_stablecoin);

        feeModel = IFeeModel(_feeModel);

        interestModel = IInterestModel(_interestModel);

        interestOracle = IInterestOracle(_interestOracle);

        depositNFT = NFT(_depositNFT);

        fundingNFT = NFT(_fundingNFT);

        mphMinter = MPHMinter(_mphMinter);



        // Ensure moneyMarket uses the same stablecoin

        require(

            moneyMarket.stablecoin() == _stablecoin,

            "DInterest: moneyMarket.stablecoin() != _stablecoin"

        );



        // Ensure interestOracle uses the same moneyMarket

        require(

            interestOracle.moneyMarket() == _moneyMarket,

            "DInterest: interestOracle.moneyMarket() != _moneyMarket"

        );



        // Verify input uint256 parameters

        require(

            _depositLimit.MaxDepositPeriod > 0 &&

                _depositLimit.MaxDepositAmount > 0,

            "DInterest: An input uint256 is 0"

        );

        require(

            _depositLimit.MinDepositPeriod <= _depositLimit.MaxDepositPeriod,

            "DInterest: Invalid DepositPeriod range"

        );

        require(

            _depositLimit.MinDepositAmount <= _depositLimit.MaxDepositAmount,

            "DInterest: Invalid DepositAmount range"

        );



        MinDepositPeriod = _depositLimit.MinDepositPeriod;

        MaxDepositPeriod = _depositLimit.MaxDepositPeriod;

        MinDepositAmount = _depositLimit.MinDepositAmount;

        MaxDepositAmount = _depositLimit.MaxDepositAmount;

        totalDeposit = 0;

    }



    /**

        Public actions

     */



    function deposit(uint256 amount, uint256 maturationTimestamp)

        external

        nonReentrant

    {

        _deposit(amount, maturationTimestamp);

    }



    function withdraw(uint256 depositID, uint256 fundingID)

        external

        nonReentrant

    {

        _withdraw(depositID, fundingID, false);

    }



    function earlyWithdraw(uint256 depositID, uint256 fundingID)

        external

        nonReentrant

    {

        _withdraw(depositID, fundingID, true);

    }



    function multiDeposit(

        uint256[] calldata amountList,

        uint256[] calldata maturationTimestampList

    ) external nonReentrant {

        require(

            amountList.length == maturationTimestampList.length,

            "DInterest: List lengths unequal"

        );

        for (uint256 i = 0; i < amountList.length; i = i.add(1)) {

            _deposit(amountList[i], maturationTimestampList[i]);

        }

    }



    function multiWithdraw(

        uint256[] calldata depositIDList,

        uint256[] calldata fundingIDList

    ) external nonReentrant {

        require(

            depositIDList.length == fundingIDList.length,

            "DInterest: List lengths unequal"

        );

        for (uint256 i = 0; i < depositIDList.length; i = i.add(1)) {

            _withdraw(depositIDList[i], fundingIDList[i], false);

        }

    }



    function multiEarlyWithdraw(

        uint256[] calldata depositIDList,

        uint256[] calldata fundingIDList

    ) external nonReentrant {

        require(

            depositIDList.length == fundingIDList.length,

            "DInterest: List lengths unequal"

        );

        for (uint256 i = 0; i < depositIDList.length; i = i.add(1)) {

            _withdraw(depositIDList[i], fundingIDList[i], true);

        }

    }



    /**

        Deficit funding

     */



    function fundAll() external nonReentrant {

        // Calculate current deficit

        (bool isNegative, uint256 deficit) = surplus();

        require(isNegative, "DInterest: No deficit available");

        require(

            !depositIsFunded(deposits.length),

            "DInterest: All deposits funded"

        );



        // Create funding struct

        uint256 incomeIndex = moneyMarket.incomeIndex();

        require(incomeIndex > 0, "DInterest: incomeIndex == 0");

        fundingList.push(

            Funding({

                fromDepositID: latestFundedDepositID,

                toDepositID: deposits.length,

                recordedFundedDepositAmount: unfundedUserDepositAmount,

                recordedMoneyMarketIncomeIndex: incomeIndex

            })

        );



        // Update relevant values

        latestFundedDepositID = deposits.length;

        unfundedUserDepositAmount = 0;



        _fund(deficit);

    }



    function fundMultiple(uint256 toDepositID) external nonReentrant {

        require(

            toDepositID > latestFundedDepositID,

            "DInterest: Deposits already funded"

        );

        require(

            toDepositID <= deposits.length,

            "DInterest: Invalid toDepositID"

        );



        (bool isNegative, uint256 surplus) = surplus();

        require(isNegative, "DInterest: No deficit available");



        uint256 totalDeficit = 0;

        uint256 totalSurplus = 0;

        uint256 totalDepositToFund = 0;

        // Deposits with ID [latestFundedDepositID+1, toDepositID] will be funded

        for (

            uint256 id = latestFundedDepositID.add(1);

            id <= toDepositID;

            id = id.add(1)

        ) {

            Deposit storage depositEntry = _getDeposit(id);

            if (depositEntry.active) {

                // Deposit still active, use current surplus

                (isNegative, surplus) = surplusOfDeposit(id);

            } else {

                // Deposit has been withdrawn, use recorded final surplus

                (isNegative, surplus) = (

                    depositEntry.finalSurplusIsNegative,

                    depositEntry.finalSurplusAmount

                );

            }



            if (isNegative) {

                // Add on deficit to total

                totalDeficit = totalDeficit.add(surplus);

            } else {

                // Has surplus

                totalSurplus = totalSurplus.add(surplus);

            }



            if (depositEntry.active) {

                totalDepositToFund = totalDepositToFund.add(

                    depositEntry.amount

                );

            }

        }

        if (totalSurplus >= totalDeficit) {

            // Deposits selected have a surplus as a whole, revert

            revert("DInterest: Selected deposits in surplus");

        } else {

            // Deduct surplus from totalDeficit

            totalDeficit = totalDeficit.sub(totalSurplus);

        }



        // Create funding struct

        uint256 incomeIndex = moneyMarket.incomeIndex();

        require(incomeIndex > 0, "DInterest: incomeIndex == 0");

        fundingList.push(

            Funding({

                fromDepositID: latestFundedDepositID,

                toDepositID: toDepositID,

                recordedFundedDepositAmount: totalDepositToFund,

                recordedMoneyMarketIncomeIndex: incomeIndex

            })

        );



        // Update relevant values

        latestFundedDepositID = toDepositID;

        unfundedUserDepositAmount = unfundedUserDepositAmount.sub(

            totalDepositToFund

        );



        _fund(totalDeficit);

    }



    /**

        Public getters

     */



    function calculateInterestAmount(

        uint256 depositAmount,

        uint256 depositPeriodInSeconds

    ) public returns (uint256 interestAmount) {

        (, uint256 moneyMarketInterestRatePerSecond) = interestOracle

            .updateAndQuery();

        (bool surplusIsNegative, uint256 surplusAmount) = surplus();



        return

            interestModel.calculateInterestAmount(

                depositAmount,

                depositPeriodInSeconds,

                moneyMarketInterestRatePerSecond,

                surplusIsNegative,

                surplusAmount

            );

    }



    function surplus() public returns (bool isNegative, uint256 surplusAmount) {

        uint256 totalValue = moneyMarket.totalValue();

        uint256 totalOwed = totalDeposit.add(totalInterestOwed);

        if (totalValue >= totalOwed) {

            // Locked value more than owed deposits, positive surplus

            isNegative = false;

            surplusAmount = totalValue.sub(totalOwed);

        } else {

            // Locked value less than owed deposits, negative surplus

            isNegative = true;

            surplusAmount = totalOwed.sub(totalValue);

        }

    }



    function surplusOfDeposit(uint256 depositID)

        public

        returns (bool isNegative, uint256 surplusAmount)

    {

        Deposit storage depositEntry = _getDeposit(depositID);

        uint256 currentMoneyMarketIncomeIndex = moneyMarket.incomeIndex();

        uint256 currentDepositValue = depositEntry

            .amount

            .mul(currentMoneyMarketIncomeIndex)

            .div(depositEntry.initialMoneyMarketIncomeIndex);

        uint256 owed = depositEntry.amount.add(depositEntry.interestOwed);

        if (currentDepositValue >= owed) {

            // Locked value more than owed deposits, positive surplus

            isNegative = false;

            surplusAmount = currentDepositValue.sub(owed);

        } else {

            // Locked value less than owed deposits, negative surplus

            isNegative = true;

            surplusAmount = owed.sub(currentDepositValue);

        }

    }



    function depositIsFunded(uint256 id) public view returns (bool) {

        return (id <= latestFundedDepositID);

    }



    function depositsLength() external view returns (uint256) {

        return deposits.length;

    }



    function fundingListLength() external view returns (uint256) {

        return fundingList.length;

    }



    function getDeposit(uint256 depositID)

        external

        view

        returns (Deposit memory)

    {

        return deposits[depositID.sub(1)];

    }



    function getFunding(uint256 fundingID)

        external

        view

        returns (Funding memory)

    {

        return fundingList[fundingID.sub(1)];

    }



    function moneyMarketIncomeIndex() external returns (uint256) {

        return moneyMarket.incomeIndex();

    }



    /**

        Param setters

     */

    function setFeeModel(address newValue) external onlyOwner {

        require(newValue.isContract(), "DInterest: not contract");

        feeModel = IFeeModel(newValue);

        emit ESetParamAddress(msg.sender, "feeModel", newValue);

    }



    function setInterestModel(address newValue) external onlyOwner {

        require(newValue.isContract(), "DInterest: not contract");

        interestModel = IInterestModel(newValue);

        emit ESetParamAddress(msg.sender, "interestModel", newValue);

    }



    function setInterestOracle(address newValue) external onlyOwner {

        require(newValue.isContract(), "DInterest: not contract");

        interestOracle = IInterestOracle(newValue);

        emit ESetParamAddress(msg.sender, "interestOracle", newValue);

    }



    function setRewards(address newValue) external onlyOwner {

        require(newValue.isContract(), "DInterest: not contract");

        moneyMarket.setRewards(newValue);

        emit ESetParamAddress(msg.sender, "moneyMarket.rewards", newValue);

    }



    function setMinDepositPeriod(uint256 newValue) external onlyOwner {

        require(newValue <= MaxDepositPeriod, "DInterest: invalid value");

        MinDepositPeriod = newValue;

        emit ESetParamUint(msg.sender, "MinDepositPeriod", newValue);

    }



    function setMaxDepositPeriod(uint256 newValue) external onlyOwner {

        require(

            newValue >= MinDepositPeriod && newValue > 0,

            "DInterest: invalid value"

        );

        MaxDepositPeriod = newValue;

        emit ESetParamUint(msg.sender, "MaxDepositPeriod", newValue);

    }



    function setMinDepositAmount(uint256 newValue) external onlyOwner {

        require(newValue <= MaxDepositAmount, "DInterest: invalid value");

        MinDepositAmount = newValue;

        emit ESetParamUint(msg.sender, "MinDepositAmount", newValue);

    }



    function setMaxDepositAmount(uint256 newValue) external onlyOwner {

        require(

            newValue >= MinDepositAmount && newValue > 0,

            "DInterest: invalid value"

        );

        MaxDepositAmount = newValue;

        emit ESetParamUint(msg.sender, "MaxDepositAmount", newValue);

    }



    function setDepositNFTTokenURI(uint256 tokenId, string calldata newURI)

        external

        onlyOwner

    {

        depositNFT.setTokenURI(tokenId, newURI);

    }



    function setDepositNFTBaseURI(string calldata newURI) external onlyOwner {

        depositNFT.setBaseURI(newURI);

    }



    function setDepositNFTContractURI(string calldata newURI)

        external

        onlyOwner

    {

        depositNFT.setContractURI(newURI);

    }



    function setFundingNFTTokenURI(uint256 tokenId, string calldata newURI)

        external

        onlyOwner

    {

        fundingNFT.setTokenURI(tokenId, newURI);

    }



    function setFundingNFTBaseURI(string calldata newURI) external onlyOwner {

        fundingNFT.setBaseURI(newURI);

    }



    function setFundingNFTContractURI(string calldata newURI)

        external

        onlyOwner

    {

        fundingNFT.setContractURI(newURI);

    }



    /**

        Internal getters

     */



    function _getDeposit(uint256 depositID)

        internal

        view

        returns (Deposit storage)

    {

        return deposits[depositID.sub(1)];

    }



    function _getFunding(uint256 fundingID)

        internal

        view

        returns (Funding storage)

    {

        return fundingList[fundingID.sub(1)];

    }



    /**

        Internals

     */



    function _deposit(uint256 amount, uint256 maturationTimestamp) internal {

        // Cannot deposit 0

        require(amount > 0, "DInterest: Deposit amount is 0");



        // Ensure deposit amount is not more than maximum

        require(

            amount >= MinDepositAmount && amount <= MaxDepositAmount,

            "DInterest: Deposit amount out of range"

        );



        // Ensure deposit period is at least MinDepositPeriod

        uint256 depositPeriod = maturationTimestamp.sub(now);

        require(

            depositPeriod >= MinDepositPeriod &&

                depositPeriod <= MaxDepositPeriod,

            "DInterest: Deposit period out of range"

        );



        // Update totalDeposit

        totalDeposit = totalDeposit.add(amount);



        // Update funding related data

        uint256 id = deposits.length.add(1);

        unfundedUserDepositAmount = unfundedUserDepositAmount.add(amount);



        // Calculate interest

        uint256 interestAmount = calculateInterestAmount(amount, depositPeriod);

        require(interestAmount > 0, "DInterest: interestAmount == 0");



        // Update totalInterestOwed

        totalInterestOwed = totalInterestOwed.add(interestAmount);



        // Mint MPH for msg.sender

        uint256 mintMPHAmount = mphMinter.mintDepositorReward(

            msg.sender,

            interestAmount

        );



        // Record deposit data for `msg.sender`

        deposits.push(

            Deposit({

                amount: amount,

                maturationTimestamp: maturationTimestamp,

                interestOwed: interestAmount,

                initialMoneyMarketIncomeIndex: moneyMarket.incomeIndex(),

                active: true,

                finalSurplusIsNegative: false,

                finalSurplusAmount: 0,

                mintMPHAmount: mintMPHAmount

            })

        );



        // Transfer `amount` stablecoin to DInterest

        stablecoin.safeTransferFrom(msg.sender, address(this), amount);



        // Lend `amount` stablecoin to money market

        stablecoin.safeIncreaseAllowance(address(moneyMarket), amount);

        moneyMarket.deposit(amount);



        // Mint depositNFT

        depositNFT.mint(msg.sender, id);



        // Emit event

        emit EDeposit(

            msg.sender,

            id,

            amount,

            maturationTimestamp,

            interestAmount,

            mintMPHAmount

        );

    }



    function _withdraw(

        uint256 depositID,

        uint256 fundingID,

        bool early

    ) internal {

        Deposit storage depositEntry = _getDeposit(depositID);



        // Verify deposit is active and set to inactive

        require(depositEntry.active, "DInterest: Deposit not active");

        depositEntry.active = false;



        if (early) {

            // Verify `now < depositEntry.maturationTimestamp`

            require(

                now < depositEntry.maturationTimestamp,

                "DInterest: Deposit mature, use withdraw() instead"

            );

        } else {

            // Verify `now >= depositEntry.maturationTimestamp`

            require(

                now >= depositEntry.maturationTimestamp,

                "DInterest: Deposit not mature"

            );

        }



        // Verify msg.sender owns the depositNFT

        require(

            depositNFT.ownerOf(depositID) == msg.sender,

            "DInterest: Sender doesn't own depositNFT"

        );



        // Take back MPH

        uint256 takeBackMPHAmount = mphMinter.takeBackDepositorReward(

            msg.sender,

            depositEntry.mintMPHAmount,

            early

        );



        // Update totalDeposit

        totalDeposit = totalDeposit.sub(depositEntry.amount);



        // Update totalInterestOwed

        totalInterestOwed = totalInterestOwed.sub(depositEntry.interestOwed);



        // Burn depositNFT

        depositNFT.burn(depositID);



        uint256 feeAmount;

        uint256 withdrawAmount;

        if (early) {

            // Withdraw the principal of the deposit from money market

            withdrawAmount = depositEntry.amount;

        } else {

            // Withdraw the principal & the interest from money market

            feeAmount = feeModel.getFee(depositEntry.interestOwed);

            withdrawAmount = depositEntry.amount.add(depositEntry.interestOwed);

        }

        withdrawAmount = moneyMarket.withdraw(withdrawAmount);



        (bool depositIsNegative, uint256 depositSurplus) = surplusOfDeposit(

            depositID

        );



        // If deposit was funded, payout interest to funder

        if (depositIsFunded(depositID)) {

            Funding storage f = _getFunding(fundingID);

            require(

                depositID > f.fromDepositID && depositID <= f.toDepositID,

                "DInterest: Deposit not funded by fundingID"

            );

            uint256 currentMoneyMarketIncomeIndex = moneyMarket.incomeIndex();

            require(

                currentMoneyMarketIncomeIndex > 0,

                "DInterest: currentMoneyMarketIncomeIndex == 0"

            );

            uint256 interestAmount = f

                .recordedFundedDepositAmount

                .mul(currentMoneyMarketIncomeIndex)

                .div(f.recordedMoneyMarketIncomeIndex)

                .sub(f.recordedFundedDepositAmount);



            // Update funding values

            f.recordedFundedDepositAmount = f.recordedFundedDepositAmount.sub(

                depositEntry.amount

            );

            f.recordedMoneyMarketIncomeIndex = currentMoneyMarketIncomeIndex;



            // Send interest to funder

            uint256 transferToFunderAmount = (early && depositIsNegative)

                ? interestAmount.add(depositSurplus)

                : interestAmount;

            if (transferToFunderAmount > 0) {

                transferToFunderAmount = moneyMarket.withdraw(

                    transferToFunderAmount

                );

                stablecoin.safeTransfer(

                    fundingNFT.ownerOf(fundingID),

                    transferToFunderAmount

                );

            }

        } else {

            // Remove deposit from future deficit fundings

            unfundedUserDepositAmount = unfundedUserDepositAmount.sub(

                depositEntry.amount

            );



            // Record remaining surplus

            depositEntry.finalSurplusIsNegative = depositIsNegative;

            depositEntry.finalSurplusAmount = depositSurplus;

        }



        // Send `withdrawAmount - feeAmount` stablecoin to `msg.sender`

        stablecoin.safeTransfer(msg.sender, withdrawAmount.sub(feeAmount));



        // Send `feeAmount` stablecoin to feeModel beneficiary

        stablecoin.safeTransfer(feeModel.beneficiary(), feeAmount);



        // Emit event

        emit EWithdraw(

            msg.sender,

            depositID,

            fundingID,

            early,

            takeBackMPHAmount

        );

    }



    function _fund(uint256 totalDeficit) internal {

        // Transfer `totalDeficit` stablecoins from msg.sender

        stablecoin.safeTransferFrom(msg.sender, address(this), totalDeficit);



        // Deposit `totalDeficit` stablecoins into moneyMarket

        stablecoin.safeIncreaseAllowance(address(moneyMarket), totalDeficit);

        moneyMarket.deposit(totalDeficit);



        // Mint fundingNFT

        fundingNFT.mint(msg.sender, fundingList.length);



        // Mint MPH for msg.sender

        uint256 mintMPHAmount = mphMinter.mintFunderReward(

            msg.sender,

            totalDeficit

        );



        // Emit event

        uint256 fundingID = fundingList.length;

        emit EFund(msg.sender, fundingID, totalDeficit, mintMPHAmount);

    }

}

library DecMath {

    using SafeMath for uint256;



    uint256 internal constant PRECISION = 10**18;



    function decmul(uint256 a, uint256 b) internal pure returns (uint256) {

        return a.mul(b).div(PRECISION);

    }



    function decdiv(uint256 a, uint256 b) internal pure returns (uint256) {

        return a.mul(PRECISION).div(b);

    }

}

contract ComptrollerMock {

    uint256 public constant CLAIM_AMOUNT = 10**18;

    ERC20Mock public comp;



    constructor (address _comp) public {

        comp = ERC20Mock(_comp);

    }



    function claimComp(address holder) external {

        comp.mint(holder, CLAIM_AMOUNT);

    }



    function getCompAddress() external view returns (address) {

        return address(comp);

    }

}

contract LendingPoolAddressesProviderMock {

    address internal pool;

    address internal core;



    function getLendingPool() external view returns (address) {

        return pool;

    }



    function setLendingPoolImpl(address _pool) external {

        pool = _pool;

    }



    function getLendingPoolCore() external view returns (address) {

        return core;

    }



    function setLendingPoolCoreImpl(address _pool) external {

        core = _pool;

    }

}

contract LendingPoolCoreMock {

    LendingPoolMock internal lendingPool;



    function setLendingPool(address lendingPoolAddress) public {

        lendingPool = LendingPoolMock(lendingPoolAddress);

    }



    function bounceTransfer(address _reserve, address _sender, uint256 _amount)

        external

    {

        ERC20 token = ERC20(_reserve);

        token.transferFrom(_sender, address(this), _amount);



        token.transfer(msg.sender, _amount);

    }



    // The equivalent of exchangeRateStored() for Compound cTokens

    function getReserveNormalizedIncome(address _reserve) external view returns (uint256) {

        (, , , , , , , , , , , address aTokenAddress, ) = lendingPool

            .getReserveData(_reserve);

        ATokenMock aToken = ATokenMock(aTokenAddress);

        return aToken.normalizedIncome();

    }

}

contract LendingPoolMock {

    mapping(address => address) internal reserveAToken;

    LendingPoolCoreMock public core;



    constructor(address _core) public {

        core = LendingPoolCoreMock(_core);

    }



    function setReserveAToken(address _reserve, address _aTokenAddress) external {

        reserveAToken[_reserve] = _aTokenAddress;

    }



    function deposit(address _reserve, uint256 _amount, uint16)

        external

    {

        ERC20 token = ERC20(_reserve);

        core.bounceTransfer(_reserve, msg.sender, _amount);



        // Mint aTokens

        address aTokenAddress = reserveAToken[_reserve];

        ATokenMock aToken = ATokenMock(aTokenAddress);

        aToken.mint(msg.sender, _amount);

        token.transfer(aTokenAddress, _amount);

    }



    function getReserveData(address _reserve)

        external

        view

        returns (

            uint256,

            uint256,

            uint256,

            uint256,

            uint256 liquidityRate,

            uint256,

            uint256,

            uint256,

            uint256,

            uint256,

            uint256,

            address aTokenAddress,

            uint40

        )

    {

        aTokenAddress = reserveAToken[_reserve];

        ATokenMock aToken = ATokenMock(aTokenAddress);

        liquidityRate = aToken.liquidityRate();

    }

}

interface IFeeModel {

    function beneficiary() external view returns (address payable);



    function getFee(uint256 _txAmount)

        external

        pure

        returns (uint256 _feeAmount);

}

contract PercentageFeeModel is IFeeModel {

    using SafeMath for uint256;



    address payable public beneficiary;



    constructor(address payable _beneficiary) public {

        beneficiary = _beneficiary;

    }



    function getFee(uint256 _txAmount)

        external

        pure

        returns (uint256 _feeAmount)

    {

        _feeAmount = _txAmount.div(10); // Precision is decreased by 1 decimal place

    }

}

interface IInterestOracle {

    function updateAndQuery() external returns (bool updated, uint256 value);



    function query() external view returns (uint256 value);



    function moneyMarket() external view returns (address);

}

interface IInterestModel {

    function calculateInterestAmount(

        uint256 depositAmount,

        uint256 depositPeriodInSeconds,

        uint256 moneyMarketInterestRatePerSecond,

        bool surplusIsNegative,

        uint256 surplusAmount

    ) external view returns (uint256 interestAmount);

}

contract LinearInterestModel {

    using SafeMath for uint256;

    using DecMath for uint256;



    uint256 public constant PRECISION = 10**18;

    uint256 public IRMultiplier;



    constructor(uint256 _IRMultiplier) public {

        IRMultiplier = _IRMultiplier;

    }



    function calculateInterestAmount(

        uint256 depositAmount,

        uint256 depositPeriodInSeconds,

        uint256 moneyMarketInterestRatePerSecond,

        bool, /*surplusIsNegative*/

        uint256 /*surplusAmount*/

    ) external view returns (uint256 interestAmount) {

        // interestAmount = depositAmount * moneyMarketInterestRatePerSecond * IRMultiplier * depositPeriodInSeconds

        interestAmount = depositAmount

            .mul(PRECISION)

            .decmul(moneyMarketInterestRatePerSecond)

            .decmul(IRMultiplier)

            .mul(depositPeriodInSeconds)

            .div(PRECISION);

    }

}

interface IMoneyMarket {

    function deposit(uint256 amount) external;



    function withdraw(uint256 amountInUnderlying)

        external

        returns (uint256 actualAmountWithdrawn);



    function claimRewards() external; // Claims farmed tokens (e.g. COMP, CRV) and sends it to the rewards pool



    function totalValue() external returns (uint256); // The total value locked in the money market, in terms of the underlying stablecoin



    function incomeIndex() external returns (uint256); // Used for calculating the interest generated (e.g. cDai's price for the Compound market)



    function stablecoin() external view returns (address);



    function setRewards(address newValue) external;



    event ESetParamAddress(

        address indexed sender,

        string indexed paramName,

        address newValue

    );

}

contract AaveMarket is IMoneyMarket, Ownable {

    using SafeMath for uint256;

    using SafeERC20 for ERC20;

    using Address for address;



    uint16 internal constant REFERRALCODE = 20; // Aave referral program code



    ILendingPoolAddressesProvider public provider; // Used for fetching the current address of LendingPool

    ERC20 public stablecoin;



    constructor(address _provider, address _stablecoin) public {

        // Verify input addresses

        require(

            _provider != address(0) && _stablecoin != address(0),

            "AaveMarket: An input address is 0"

        );

        require(

            _provider.isContract() && _stablecoin.isContract(),

            "AaveMarket: An input address is not a contract"

        );



        provider = ILendingPoolAddressesProvider(_provider);

        stablecoin = ERC20(_stablecoin);

    }



    function deposit(uint256 amount) external onlyOwner {

        require(amount > 0, "AaveMarket: amount is 0");



        ILendingPool lendingPool = ILendingPool(provider.getLendingPool());

        address lendingPoolCore = provider.getLendingPoolCore();



        // Transfer `amount` stablecoin from `msg.sender`

        stablecoin.safeTransferFrom(msg.sender, address(this), amount);



        // Approve `amount` stablecoin to lendingPool

        stablecoin.safeIncreaseAllowance(lendingPoolCore, amount);



        // Deposit `amount` stablecoin to lendingPool

        lendingPool.deposit(address(stablecoin), amount, REFERRALCODE);

    }



    function withdraw(uint256 amountInUnderlying)

        external

        onlyOwner

        returns (uint256 actualAmountWithdrawn)

    {

        require(amountInUnderlying > 0, "AaveMarket: amountInUnderlying is 0");



        ILendingPool lendingPool = ILendingPool(provider.getLendingPool());



        // Initialize aToken

        (, , , , , , , , , , , address aTokenAddress, ) = lendingPool

            .getReserveData(address(stablecoin));

        IAToken aToken = IAToken(aTokenAddress);



        // Redeem `amountInUnderlying` aToken, since 1 aToken = 1 stablecoin

        aToken.redeem(amountInUnderlying);



        // Transfer `amountInUnderlying` stablecoin to `msg.sender`

        stablecoin.safeTransfer(msg.sender, amountInUnderlying);



        return amountInUnderlying;

    }



    function claimRewards() external {}



    function totalValue() external returns (uint256) {

        ILendingPool lendingPool = ILendingPool(provider.getLendingPool());



        // Initialize aToken

        (, , , , , , , , , , , address aTokenAddress, ) = lendingPool

            .getReserveData(address(stablecoin));

        IAToken aToken = IAToken(aTokenAddress);



        return aToken.balanceOf(address(this));

    }



    function incomeIndex() external returns (uint256) {

        ILendingPoolCore lendingPoolCore = ILendingPoolCore(

            provider.getLendingPoolCore()

        );

        return lendingPoolCore.getReserveNormalizedIncome(address(stablecoin));

    }



    function setRewards(address newValue) external {}

}

interface IAToken {

    function redeem(uint256 _amount) external;



    function balanceOf(address owner) external view returns (uint256);

}

interface ILendingPool {

    function deposit(address _reserve, uint256 _amount, uint16 _referralCode)

        external;



    function getReserveData(address _reserve)

        external

        view

        returns (

            uint256 totalLiquidity,

            uint256 availableLiquidity,

            uint256 totalBorrowsStable,

            uint256 totalBorrowsVariable,

            uint256 liquidityRate,

            uint256 variableBorrowRate,

            uint256 stableBorrowRate,

            uint256 averageStableBorrowRate,

            uint256 utilizationRate,

            uint256 liquidityIndex,

            uint256 variableBorrowIndex,

            address aTokenAddress,

            uint40 lastUpdateTimestamp

        );

}

interface ILendingPoolAddressesProvider {

    function getLendingPool() external view returns (address);



    function setLendingPoolImpl(address _pool) external;



    function getLendingPoolCore() external view returns (address payable);



    function setLendingPoolCoreImpl(address _lendingPoolCore) external;



    function getLendingPoolConfigurator() external view returns (address);



    function setLendingPoolConfiguratorImpl(address _configurator) external;



    function getLendingPoolDataProvider() external view returns (address);



    function setLendingPoolDataProviderImpl(address _provider) external;



    function getLendingPoolParametersProvider() external view returns (address);



    function setLendingPoolParametersProviderImpl(address _parametersProvider)

        external;



    function getTokenDistributor() external view returns (address);



    function setTokenDistributor(address _tokenDistributor) external;



    function getFeeProvider() external view returns (address);



    function setFeeProviderImpl(address _feeProvider) external;



    function getLendingPoolLiquidationManager() external view returns (address);



    function setLendingPoolLiquidationManager(address _manager) external;



    function getLendingPoolManager() external view returns (address);



    function setLendingPoolManager(address _lendingPoolManager) external;



    function getPriceOracle() external view returns (address);



    function setPriceOracle(address _priceOracle) external;



    function getLendingRateOracle() external view returns (address);



    function setLendingRateOracle(address _lendingRateOracle) external;

}

interface ILendingPoolCore {

    // The equivalent of exchangeRateStored() for Compound cTokens

    function getReserveNormalizedIncome(address _reserve)

        external

        view

        returns (uint256);

}

contract CompoundERC20Market is IMoneyMarket, Ownable {

    using DecMath for uint256;

    using SafeERC20 for ERC20;

    using Address for address;



    uint256 internal constant ERRCODE_OK = 0;



    ICERC20 public cToken;

    IComptroller public comptroller;

    address public rewards;

    ERC20 public stablecoin;



    constructor(

        address _cToken,

        address _comptroller,

        address _rewards,

        address _stablecoin

    ) public {

        // Verify input addresses

        require(

            _cToken != address(0) &&

                _comptroller != address(0) &&

                _rewards != address(0) &&

                _stablecoin != address(0),

            "CompoundERC20Market: An input address is 0"

        );

        require(

            _cToken.isContract() &&

                _comptroller.isContract() &&

                _rewards.isContract() &&

                _stablecoin.isContract(),

            "CompoundERC20Market: An input address is not a contract"

        );



        cToken = ICERC20(_cToken);

        comptroller = IComptroller(_comptroller);

        rewards = _rewards;

        stablecoin = ERC20(_stablecoin);

    }



    function deposit(uint256 amount) external onlyOwner {

        require(amount > 0, "CompoundERC20Market: amount is 0");



        // Transfer `amount` stablecoin from `msg.sender`

        stablecoin.safeTransferFrom(msg.sender, address(this), amount);



        // Deposit `amount` stablecoin into cToken

        stablecoin.safeIncreaseAllowance(address(cToken), amount);

        require(

            cToken.mint(amount) == ERRCODE_OK,

            "CompoundERC20Market: Failed to mint cTokens"

        );

    }



    function withdraw(uint256 amountInUnderlying)

        external

        onlyOwner

        returns (uint256 actualAmountWithdrawn)

    {

        require(

            amountInUnderlying > 0,

            "CompoundERC20Market: amountInUnderlying is 0"

        );



        // Withdraw `amountInUnderlying` stablecoin from cToken

        require(

            cToken.redeemUnderlying(amountInUnderlying) == ERRCODE_OK,

            "CompoundERC20Market: Failed to redeem"

        );



        // Transfer `amountInUnderlying` stablecoin to `msg.sender`

        stablecoin.safeTransfer(msg.sender, amountInUnderlying);



        return amountInUnderlying;

    }



    function claimRewards() external {

        comptroller.claimComp(address(this));

        ERC20 comp = ERC20(comptroller.getCompAddress());

        comp.safeTransfer(rewards, comp.balanceOf(address(this)));

    }



    function totalValue() external returns (uint256) {

        uint256 cTokenBalance = cToken.balanceOf(address(this));

        // Amount of stablecoin units that 1 unit of cToken can be exchanged for, scaled by 10^18

        uint256 cTokenPrice = cToken.exchangeRateCurrent();

        return cTokenBalance.decmul(cTokenPrice);

    }



    function incomeIndex() external returns (uint256) {

        return cToken.exchangeRateCurrent();

    }



    /**

        Param setters

     */

    function setRewards(address newValue) external onlyOwner {

        require(newValue.isContract(), "CompoundERC20Market: not contract");

        rewards = newValue;

        emit ESetParamAddress(msg.sender, "rewards", newValue);

    }

}

interface ICERC20 {

    function transfer(address dst, uint256 amount) external returns (bool);



    function transferFrom(address src, address dst, uint256 amount)

        external

        returns (bool);



    function approve(address spender, uint256 amount) external returns (bool);



    function allowance(address owner, address spender)

        external

        view

        returns (uint256);



    function balanceOf(address owner) external view returns (uint256);



    function balanceOfUnderlying(address owner) external returns (uint256);



    function getAccountSnapshot(address account)

        external

        view

        returns (uint256, uint256, uint256, uint256);



    function borrowRatePerBlock() external view returns (uint256);



    function supplyRatePerBlock() external view returns (uint256);



    function totalBorrowsCurrent() external returns (uint256);



    function borrowBalanceCurrent(address account) external returns (uint256);



    function borrowBalanceStored(address account)

        external

        view

        returns (uint256);



    function exchangeRateCurrent() external returns (uint256);



    function exchangeRateStored() external view returns (uint256);



    function getCash() external view returns (uint256);



    function accrueInterest() external returns (uint256);



    function seize(address liquidator, address borrower, uint256 seizeTokens)

        external

        returns (uint256);



    function mint(uint256 mintAmount) external returns (uint256);



    function redeem(uint256 redeemTokens) external returns (uint256);



    function redeemUnderlying(uint256 redeemAmount) external returns (uint256);



    function borrow(uint256 borrowAmount) external returns (uint256);



    function repayBorrow(uint256 repayAmount) external returns (uint256);



    function repayBorrowBehalf(address borrower, uint256 repayAmount)

        external

        returns (uint256);



    function liquidateBorrow(

        address borrower,

        uint256 repayAmount,

        address cTokenCollateral

    ) external returns (uint256);

}

interface IComptroller {

    function claimComp(address holder) external;

    function getCompAddress() external view returns (address);

}

contract YVaultMarket is IMoneyMarket, Ownable {

    using SafeMath for uint256;

    using DecMath for uint256;

    using SafeERC20 for ERC20;

    using Address for address;



    Vault public vault;

    ERC20 public stablecoin;



    constructor(address _vault, address _stablecoin) public {

        // Verify input addresses

        require(

            _vault != address(0) && _stablecoin != address(0),

            "YVaultMarket: An input address is 0"

        );

        require(

            _vault.isContract() && _stablecoin.isContract(),

            "YVaultMarket: An input address is not a contract"

        );



        vault = Vault(_vault);

        stablecoin = ERC20(_stablecoin);

    }



    function deposit(uint256 amount) external onlyOwner {

        require(amount > 0, "YVaultMarket: amount is 0");



        // Transfer `amount` stablecoin from `msg.sender`

        stablecoin.safeTransferFrom(msg.sender, address(this), amount);



        // Approve `amount` stablecoin to vault

        stablecoin.safeIncreaseAllowance(address(vault), amount);



        // Deposit `amount` stablecoin to vault

        vault.deposit(amount);

    }



    function withdraw(uint256 amountInUnderlying)

        external

        onlyOwner

        returns (uint256 actualAmountWithdrawn)

    {

        require(

            amountInUnderlying > 0,

            "YVaultMarket: amountInUnderlying is 0"

        );



        // Withdraw `amountInShares` shares from vault

        uint256 sharePrice = vault.getPricePerFullShare();

        uint256 amountInShares = amountInUnderlying.decdiv(sharePrice);

        vault.withdraw(amountInShares);



        // Transfer stablecoin to `msg.sender`

        actualAmountWithdrawn = stablecoin.balanceOf(address(this));

        stablecoin.safeTransfer(msg.sender, actualAmountWithdrawn);

    }



    function claimRewards() external {}



    function totalValue() external returns (uint256) {

        uint256 sharePrice = vault.getPricePerFullShare();

        uint256 shareBalance = vault.balanceOf(address(this));

        return shareBalance.decmul(sharePrice);

    }



    function incomeIndex() external returns (uint256) {

        return vault.getPricePerFullShare();

    }



    function setRewards(address newValue) external {}

}

interface Vault {

    function deposit(uint256) external;



    function withdraw(uint256) external;



    function getPricePerFullShare() external view returns (uint256);



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

    function transfer(address recipient, uint256 amount)

        external

        returns (bool);



    /**

     * @dev Returns the remaining number of tokens that `spender` will be

     * allowed to spend on behalf of `owner` through {transferFrom}. This is

     * zero by default.

     *

     * This value changes when {approve} or {transferFrom} are called.

     */

    function allowance(address owner, address spender)

        external

        view

        returns (uint256);



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

    function transferFrom(

        address sender,

        address recipient,

        uint256 amount

    ) external returns (bool);



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

    event Approval(

        address indexed owner,

        address indexed spender,

        uint256 value

    );

}

interface IRewards {

    function notifyRewardAmount(uint256 reward) external;

}

contract MPHMinter is Ownable {

    using Address for address;

    using DecMath for uint256;

    using SafeMath for uint256;



    uint256 internal constant PRECISION = 10**18;



    /**

        @notice The multiplier applied to the interest generated by a pool when minting MPH

     */

    mapping(address => uint256) public poolMintingMultiplier;

    /**

        @notice The multiplier applied to the interest generated by a pool when letting depositors keep MPH

     */

    mapping(address => uint256) public poolDepositorRewardMultiplier;

    /**

        @notice The multiplier applied to the interest generated by a pool when letting deficit funders keep MPH

     */

    mapping(address => uint256) public poolFunderRewardMultiplier;

    /**

        @notice Multiplier used for calculating dev reward

     */

    uint256 public devRewardMultiplier;



    event ESetParamAddress(

        address indexed sender,

        string indexed paramName,

        address newValue

    );

    event ESetParamUint(

        address indexed sender,

        string indexed paramName,

        uint256 newValue

    );



    /**

        External contracts

     */

    MPHToken public mph;

    address public govTreasury;

    address public devWallet;



    constructor(

        address _mph,

        address _govTreasury,

        address _devWallet,

        uint256 _devRewardMultiplier

    ) public {

        mph = MPHToken(_mph);

        govTreasury = _govTreasury;

        devWallet = _devWallet;

        devRewardMultiplier = _devRewardMultiplier;

    }



    function mintDepositorReward(address to, uint256 interestAmount)

        external

        returns (uint256)

    {

        uint256 multiplier = poolMintingMultiplier[msg.sender];

        uint256 mintAmount = interestAmount.decmul(multiplier);

        if (mintAmount == 0) {

            // sender is not a pool/has been deactivated

            return 0;

        }



        mph.ownerMint(to, mintAmount);

        mph.ownerMint(devWallet, mintAmount.decmul(devRewardMultiplier));

        return mintAmount;

    }



    function mintFunderReward(address to, uint256 interestAmount)

        external

        returns (uint256)

    {

        uint256 multiplier = poolMintingMultiplier[msg.sender].decmul(

            poolFunderRewardMultiplier[msg.sender]

        );

        uint256 mintAmount = interestAmount.decmul(multiplier);

        if (mintAmount == 0) {

            // sender is not a pool/has been deactivated

            return 0;

        }



        mph.ownerMint(to, mintAmount);

        mph.ownerMint(devWallet, mintAmount.decmul(devRewardMultiplier));

        return mintAmount;

    }



    function takeBackDepositorReward(

        address from,

        uint256 mintMPHAmount,

        bool early

    ) external returns (uint256) {

        uint256 takeBackAmount = early

            ? mintMPHAmount

            : mintMPHAmount.decmul(

                PRECISION.sub(poolDepositorRewardMultiplier[msg.sender])

            );

        if (takeBackAmount == 0) {

            // sender is not a pool/has been deactivated

            return 0;

        }



        mph.ownerTransfer(from, govTreasury, takeBackAmount);

        return takeBackAmount;

    }



    /**

        Param setters

     */

    function setGovTreasury(address newValue) external onlyOwner {

        require(newValue != address(0), "MPHMinter: 0 address");

        govTreasury = newValue;

        emit ESetParamAddress(msg.sender, "govTreasury", newValue);

    }



    function setDevWallet(address newValue) external onlyOwner {

        require(newValue != address(0), "MPHMinter: 0 address");

        devWallet = newValue;

        emit ESetParamAddress(msg.sender, "devWallet", newValue);

    }



    function setPoolMintingMultiplier(address pool, uint256 newMultiplier)

        external

        onlyOwner

    {

        require(pool.isContract(), "MPHMinter: pool not contract");

        poolMintingMultiplier[pool] = newMultiplier;

        emit ESetParamUint(msg.sender, "poolMintingMultiplier", newMultiplier);

    }



    function setPoolDepositorRewardMultiplier(

        address pool,

        uint256 newMultiplier

    ) external onlyOwner {

        require(pool.isContract(), "MPHMinter: pool not contract");

        require(newMultiplier <= PRECISION, "MPHMinter: invalid multiplier");

        poolDepositorRewardMultiplier[pool] = newMultiplier;

        emit ESetParamUint(

            msg.sender,

            "poolDepositorRewardMultiplier",

            newMultiplier

        );

    }



    function setPoolFunderRewardMultiplier(address pool, uint256 newMultiplier)

        external

        onlyOwner

    {

        require(pool.isContract(), "MPHMinter: pool not contract");

        poolFunderRewardMultiplier[pool] = newMultiplier;

        emit ESetParamUint(

            msg.sender,

            "poolFunderRewardMultiplier",

            newMultiplier

        );

    }

}

interface OneSplitAudit {

    function swap(

        address fromToken,

        address destToken,

        uint256 amount,

        uint256 minReturn,

        uint256[] calldata distribution,

        uint256 flags

    ) external payable returns (uint256 returnAmount);



    function getExpectedReturn(

        address fromToken,

        address destToken,

        uint256 amount,

        uint256 parts,

        uint256 flags // See constants in IOneSplit.sol

    )

        external

        view

        returns (uint256 returnAmount, uint256[] memory distribution);

}

contract IRewardDistributionRecipient is Ownable {

    address rewardDistribution;



    function notifyRewardAmount(uint256 reward) external;



    modifier onlyRewardDistribution() {

        require(

            _msgSender() == rewardDistribution,

            "Caller is not reward distribution"

        );

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



    IERC20 public stakeToken;



    uint256 private _totalSupply;



    mapping(address => uint256) private _balances;



    constructor(address _stakeToken) public {

        stakeToken = IERC20(_stakeToken);

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

        stakeToken.safeTransferFrom(msg.sender, address(this), amount);

    }



    function withdraw(uint256 amount) public {

        _totalSupply = _totalSupply.sub(amount);

        _balances[msg.sender] = _balances[msg.sender].sub(amount);

        stakeToken.safeTransfer(msg.sender, amount);

    }

}

contract Rewards is LPTokenWrapper, IRewardDistributionRecipient {

    IERC20 public rewardToken;

    OneSplitAudit public oneSplit;

    uint256 public constant DURATION = 7 days;



    uint256 public starttime;

    uint256 public periodFinish = 0;

    uint256 public rewardRate = 0;

    uint256 public lastUpdateTime;

    uint256 public rewardPerTokenStored;



    bool public initialized = false;



    mapping(address => uint256) public userRewardPerTokenPaid;

    mapping(address => uint256) public rewards;



    event RewardAdded(uint256 reward);

    event Staked(address indexed user, uint256 amount);

    event Withdrawn(address indexed user, uint256 amount);

    event RewardPaid(address indexed user, uint256 reward);



    modifier updateReward(address account) {

        rewardPerTokenStored = rewardPerToken();

        lastUpdateTime = lastTimeRewardApplicable();

        if (account != address(0)) {

            rewards[account] = earned(account);

            userRewardPerTokenPaid[account] = rewardPerTokenStored;

        }

        _;

    }



    modifier checkStart {

        require(block.timestamp >= starttime, "Rewards: not start");

        _;

    }



    constructor(

        address _stakeToken,

        address _rewardToken,

        address _oneSplit,

        uint256 _starttime

    ) public LPTokenWrapper(_stakeToken) {

        rewardToken = IERC20(_rewardToken);

        oneSplit = OneSplitAudit(_oneSplit);

        starttime = _starttime;

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

        require(amount > 0, "Rewards: cannot stake 0");

        super.stake(amount);

        emit Staked(msg.sender, amount);

    }



    function withdraw(uint256 amount)

        public

        updateReward(msg.sender)

        checkStart

    {

        require(amount > 0, "Rewards: cannot withdraw 0");

        super.withdraw(amount);

        emit Withdrawn(msg.sender, amount);

    }



    function exit() external {

        withdraw(balanceOf(msg.sender));

        getReward();

    }



    function getReward() public updateReward(msg.sender) checkStart {

        uint256 reward = earned(msg.sender);

        if (reward > 0) {

            rewards[msg.sender] = 0;

            rewardToken.safeTransfer(msg.sender, reward);

            emit RewardPaid(msg.sender, reward);

        }

    }



    function notifyRewardAmount(uint256 reward)

        external

        onlyRewardDistribution

        updateReward(address(0))

    {

        _notifyRewardAmount(reward);

    }



    function dump(address token, uint256 parts) external {

        require(token != address(stakeToken), "Rewards: no dump stakeToken");

        require(token != address(rewardToken), "Rewards: no dump rewardToken");



        // dump token for rewardToken

        uint256 tokenBalance = IERC20(token).balanceOf(address(this));

        (uint256 returnAmount, uint256[] memory distribution) = oneSplit

            .getExpectedReturn(

            token,

            address(rewardToken),

            tokenBalance,

            parts,

            0

        );

        uint256 receivedRewardTokenAmount = oneSplit.swap(

            token,

            address(rewardToken),

            tokenBalance,

            returnAmount,

            distribution,

            0

        );



        // notify reward

        _notifyRewardAmount(receivedRewardTokenAmount);

    }



    function _notifyRewardAmount(uint256 reward) internal {

        // https://sips.synthetix.io/sips/sip-77

        require(

            reward < uint256(-1) / 10**18,

            "Rewards: rewards too large, would lock"

        );

        if (block.timestamp > starttime) {

            if (block.timestamp >= periodFinish) {

                rewardRate = reward.div(DURATION);

            } else {

                uint256 remaining = periodFinish.sub(block.timestamp);

                uint256 leftover = remaining.mul(rewardRate);

                rewardRate = reward.add(leftover).div(DURATION);

            }

            lastUpdateTime = block.timestamp;

            periodFinish = block.timestamp.add(DURATION);

            emit RewardAdded(reward);

        } else {

            rewardRate = reward.div(DURATION);

            lastUpdateTime = starttime;

            periodFinish = starttime.add(DURATION);

            emit RewardAdded(reward);

        }

    }

}

contract ERC165 is IERC165 {

    /*

     * bytes4(keccak256('supportsInterface(bytes4)')) == 0x01ffc9a7

     */

    bytes4 private constant _INTERFACE_ID_ERC165 = 0x01ffc9a7;



    /**

     * @dev Mapping of interface ids to whether or not it's supported.

     */

    mapping(bytes4 => bool) private _supportedInterfaces;



    constructor () internal {

        // Derived contracts need only register support for their own interfaces,

        // we register support for ERC165 itself here

        _registerInterface(_INTERFACE_ID_ERC165);

    }



    /**

     * @dev See {IERC165-supportsInterface}.

     *

     * Time complexity O(1), guaranteed to always use less than 30 000 gas.

     */

    function supportsInterface(bytes4 interfaceId) external view returns (bool) {

        return _supportedInterfaces[interfaceId];

    }



    /**

     * @dev Registers the contract as an implementer of the interface defined by

     * `interfaceId`. Support of the actual ERC165 interface is automatic and

     * registering its interface id is not required.

     *

     * See {IERC165-supportsInterface}.

     *

     * Requirements:

     *

     * - `interfaceId` cannot be the ERC165 invalid interface (`0xffffffff`).

     */

    function _registerInterface(bytes4 interfaceId) internal {

        require(interfaceId != 0xffffffff, "ERC165: invalid interface id");

        _supportedInterfaces[interfaceId] = true;

    }

}

contract ERC20 is Context, IERC20 {

    using SafeMath for uint256;



    mapping (address => uint256) private _balances;



    mapping (address => mapping (address => uint256)) private _allowances;



    uint256 private _totalSupply;



    /**

     * @dev See {IERC20-totalSupply}.

     */

    function totalSupply() public view returns (uint256) {

        return _totalSupply;

    }



    /**

     * @dev See {IERC20-balanceOf}.

     */

    function balanceOf(address account) public view returns (uint256) {

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

    function transfer(address recipient, uint256 amount) public returns (bool) {

        _transfer(_msgSender(), recipient, amount);

        return true;

    }



    /**

     * @dev See {IERC20-allowance}.

     */

    function allowance(address owner, address spender) public view returns (uint256) {

        return _allowances[owner][spender];

    }



    /**

     * @dev See {IERC20-approve}.

     *

     * Requirements:

     *

     * - `spender` cannot be the zero address.

     */

    function approve(address spender, uint256 amount) public returns (bool) {

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

     * - the caller must have allowance for `sender`'s tokens of at least

     * `amount`.

     */

    function transferFrom(address sender, address recipient, uint256 amount) public returns (bool) {

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

    function increaseAllowance(address spender, uint256 addedValue) public returns (bool) {

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

    function decreaseAllowance(address spender, uint256 subtractedValue) public returns (bool) {

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

    function _transfer(address sender, address recipient, uint256 amount) internal {

        require(sender != address(0), "ERC20: transfer from the zero address");

        require(recipient != address(0), "ERC20: transfer to the zero address");



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

    function _mint(address account, uint256 amount) internal {

        require(account != address(0), "ERC20: mint to the zero address");



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

    function _burn(address account, uint256 amount) internal {

        require(account != address(0), "ERC20: burn from the zero address");



        _balances[account] = _balances[account].sub(amount, "ERC20: burn amount exceeds balance");

        _totalSupply = _totalSupply.sub(amount);

        emit Transfer(account, address(0), amount);

    }



    /**

     * @dev Sets `amount` as the allowance of `spender` over the `owner`s tokens.

     *

     * This is internal function is equivalent to `approve`, and can be used to

     * e.g. set automatic allowances for certain subsystems, etc.

     *

     * Emits an {Approval} event.

     *

     * Requirements:

     *

     * - `owner` cannot be the zero address.

     * - `spender` cannot be the zero address.

     */

    function _approve(address owner, address spender, uint256 amount) internal {

        require(owner != address(0), "ERC20: approve from the zero address");

        require(spender != address(0), "ERC20: approve to the zero address");



        _allowances[owner][spender] = amount;

        emit Approval(owner, spender, amount);

    }



    /**

     * @dev Destroys `amount` tokens from `account`.`amount` is then deducted

     * from the caller's allowance.

     *

     * See {_burn} and {_approve}.

     */

    function _burnFrom(address account, uint256 amount) internal {

        _burn(account, amount);

        _approve(account, _msgSender(), _allowances[account][_msgSender()].sub(amount, "ERC20: burn amount exceeds allowance"));

    }

}

contract ERC20Detailed is IERC20 {

    string private _name;

    string private _symbol;

    uint8 private _decimals;



    /**

     * @dev Sets the values for `name`, `symbol`, and `decimals`. All three of

     * these values are immutable: they can only be set once during

     * construction.

     */

    constructor (string memory name, string memory symbol, uint8 decimals) public {

        _name = name;

        _symbol = symbol;

        _decimals = decimals;

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

     * Ether and Wei.

     *

     * NOTE: This information is only used for _display_ purposes: it in

     * no way affects any of the arithmetic of the contract, including

     * {IERC20-balanceOf} and {IERC20-transfer}.

     */

    function decimals() public view returns (uint8) {

        return _decimals;

    }

}

contract ERC721 is Context, ERC165, IERC721 {

    using SafeMath for uint256;

    using Address for address;

    using Counters for Counters.Counter;



    // Equals to `bytes4(keccak256("onERC721Received(address,address,uint256,bytes)"))`

    // which can be also obtained as `IERC721Receiver(0).onERC721Received.selector`

    bytes4 private constant _ERC721_RECEIVED = 0x150b7a02;



    // Mapping from token ID to owner

    mapping (uint256 => address) private _tokenOwner;



    // Mapping from token ID to approved address

    mapping (uint256 => address) private _tokenApprovals;



    // Mapping from owner to number of owned token

    mapping (address => Counters.Counter) private _ownedTokensCount;



    // Mapping from owner to operator approvals

    mapping (address => mapping (address => bool)) private _operatorApprovals;



    /*

     *     bytes4(keccak256('balanceOf(address)')) == 0x70a08231

     *     bytes4(keccak256('ownerOf(uint256)')) == 0x6352211e

     *     bytes4(keccak256('approve(address,uint256)')) == 0x095ea7b3

     *     bytes4(keccak256('getApproved(uint256)')) == 0x081812fc

     *     bytes4(keccak256('setApprovalForAll(address,bool)')) == 0xa22cb465

     *     bytes4(keccak256('isApprovedForAll(address,address)')) == 0xe985e9c5

     *     bytes4(keccak256('transferFrom(address,address,uint256)')) == 0x23b872dd

     *     bytes4(keccak256('safeTransferFrom(address,address,uint256)')) == 0x42842e0e

     *     bytes4(keccak256('safeTransferFrom(address,address,uint256,bytes)')) == 0xb88d4fde

     *

     *     => 0x70a08231 ^ 0x6352211e ^ 0x095ea7b3 ^ 0x081812fc ^

     *        0xa22cb465 ^ 0xe985e9c ^ 0x23b872dd ^ 0x42842e0e ^ 0xb88d4fde == 0x80ac58cd

     */

    bytes4 private constant _INTERFACE_ID_ERC721 = 0x80ac58cd;



    constructor () public {

        // register the supported interfaces to conform to ERC721 via ERC165

        _registerInterface(_INTERFACE_ID_ERC721);

    }



    /**

     * @dev Gets the balance of the specified address.

     * @param owner address to query the balance of

     * @return uint256 representing the amount owned by the passed address

     */

    function balanceOf(address owner) public view returns (uint256) {

        require(owner != address(0), "ERC721: balance query for the zero address");



        return _ownedTokensCount[owner].current();

    }



    /**

     * @dev Gets the owner of the specified token ID.

     * @param tokenId uint256 ID of the token to query the owner of

     * @return address currently marked as the owner of the given token ID

     */

    function ownerOf(uint256 tokenId) public view returns (address) {

        address owner = _tokenOwner[tokenId];

        require(owner != address(0), "ERC721: owner query for nonexistent token");



        return owner;

    }



    /**

     * @dev Approves another address to transfer the given token ID

     * The zero address indicates there is no approved address.

     * There can only be one approved address per token at a given time.

     * Can only be called by the token owner or an approved operator.

     * @param to address to be approved for the given token ID

     * @param tokenId uint256 ID of the token to be approved

     */

    function approve(address to, uint256 tokenId) public {

        address owner = ownerOf(tokenId);

        require(to != owner, "ERC721: approval to current owner");



        require(_msgSender() == owner || isApprovedForAll(owner, _msgSender()),

            "ERC721: approve caller is not owner nor approved for all"

        );



        _tokenApprovals[tokenId] = to;

        emit Approval(owner, to, tokenId);

    }



    /**

     * @dev Gets the approved address for a token ID, or zero if no address set

     * Reverts if the token ID does not exist.

     * @param tokenId uint256 ID of the token to query the approval of

     * @return address currently approved for the given token ID

     */

    function getApproved(uint256 tokenId) public view returns (address) {

        require(_exists(tokenId), "ERC721: approved query for nonexistent token");



        return _tokenApprovals[tokenId];

    }



    /**

     * @dev Sets or unsets the approval of a given operator

     * An operator is allowed to transfer all tokens of the sender on their behalf.

     * @param to operator address to set the approval

     * @param approved representing the status of the approval to be set

     */

    function setApprovalForAll(address to, bool approved) public {

        require(to != _msgSender(), "ERC721: approve to caller");



        _operatorApprovals[_msgSender()][to] = approved;

        emit ApprovalForAll(_msgSender(), to, approved);

    }



    /**

     * @dev Tells whether an operator is approved by a given owner.

     * @param owner owner address which you want to query the approval of

     * @param operator operator address which you want to query the approval of

     * @return bool whether the given operator is approved by the given owner

     */

    function isApprovedForAll(address owner, address operator) public view returns (bool) {

        return _operatorApprovals[owner][operator];

    }



    /**

     * @dev Transfers the ownership of a given token ID to another address.

     * Usage of this method is discouraged, use {safeTransferFrom} whenever possible.

     * Requires the msg.sender to be the owner, approved, or operator.

     * @param from current owner of the token

     * @param to address to receive the ownership of the given token ID

     * @param tokenId uint256 ID of the token to be transferred

     */

    function transferFrom(address from, address to, uint256 tokenId) public {

        //solhint-disable-next-line max-line-length

        require(_isApprovedOrOwner(_msgSender(), tokenId), "ERC721: transfer caller is not owner nor approved");



        _transferFrom(from, to, tokenId);

    }



    /**

     * @dev Safely transfers the ownership of a given token ID to another address

     * If the target address is a contract, it must implement {IERC721Receiver-onERC721Received},

     * which is called upon a safe transfer, and return the magic value

     * `bytes4(keccak256("onERC721Received(address,address,uint256,bytes)"))`; otherwise,

     * the transfer is reverted.

     * Requires the msg.sender to be the owner, approved, or operator

     * @param from current owner of the token

     * @param to address to receive the ownership of the given token ID

     * @param tokenId uint256 ID of the token to be transferred

     */

    function safeTransferFrom(address from, address to, uint256 tokenId) public {

        safeTransferFrom(from, to, tokenId, "");

    }



    /**

     * @dev Safely transfers the ownership of a given token ID to another address

     * If the target address is a contract, it must implement {IERC721Receiver-onERC721Received},

     * which is called upon a safe transfer, and return the magic value

     * `bytes4(keccak256("onERC721Received(address,address,uint256,bytes)"))`; otherwise,

     * the transfer is reverted.

     * Requires the _msgSender() to be the owner, approved, or operator

     * @param from current owner of the token

     * @param to address to receive the ownership of the given token ID

     * @param tokenId uint256 ID of the token to be transferred

     * @param _data bytes data to send along with a safe transfer check

     */

    function safeTransferFrom(address from, address to, uint256 tokenId, bytes memory _data) public {

        require(_isApprovedOrOwner(_msgSender(), tokenId), "ERC721: transfer caller is not owner nor approved");

        _safeTransferFrom(from, to, tokenId, _data);

    }



    /**

     * @dev Safely transfers the ownership of a given token ID to another address

     * If the target address is a contract, it must implement `onERC721Received`,

     * which is called upon a safe transfer, and return the magic value

     * `bytes4(keccak256("onERC721Received(address,address,uint256,bytes)"))`; otherwise,

     * the transfer is reverted.

     * Requires the msg.sender to be the owner, approved, or operator

     * @param from current owner of the token

     * @param to address to receive the ownership of the given token ID

     * @param tokenId uint256 ID of the token to be transferred

     * @param _data bytes data to send along with a safe transfer check

     */

    function _safeTransferFrom(address from, address to, uint256 tokenId, bytes memory _data) internal {

        _transferFrom(from, to, tokenId);

        require(_checkOnERC721Received(from, to, tokenId, _data), "ERC721: transfer to non ERC721Receiver implementer");

    }



    /**

     * @dev Returns whether the specified token exists.

     * @param tokenId uint256 ID of the token to query the existence of

     * @return bool whether the token exists

     */

    function _exists(uint256 tokenId) internal view returns (bool) {

        address owner = _tokenOwner[tokenId];

        return owner != address(0);

    }



    /**

     * @dev Returns whether the given spender can transfer a given token ID.

     * @param spender address of the spender to query

     * @param tokenId uint256 ID of the token to be transferred

     * @return bool whether the msg.sender is approved for the given token ID,

     * is an operator of the owner, or is the owner of the token

     */

    function _isApprovedOrOwner(address spender, uint256 tokenId) internal view returns (bool) {

        require(_exists(tokenId), "ERC721: operator query for nonexistent token");

        address owner = ownerOf(tokenId);

        return (spender == owner || getApproved(tokenId) == spender || isApprovedForAll(owner, spender));

    }



    /**

     * @dev Internal function to safely mint a new token.

     * Reverts if the given token ID already exists.

     * If the target address is a contract, it must implement `onERC721Received`,

     * which is called upon a safe transfer, and return the magic value

     * `bytes4(keccak256("onERC721Received(address,address,uint256,bytes)"))`; otherwise,

     * the transfer is reverted.

     * @param to The address that will own the minted token

     * @param tokenId uint256 ID of the token to be minted

     */

    function _safeMint(address to, uint256 tokenId) internal {

        _safeMint(to, tokenId, "");

    }



    /**

     * @dev Internal function to safely mint a new token.

     * Reverts if the given token ID already exists.

     * If the target address is a contract, it must implement `onERC721Received`,

     * which is called upon a safe transfer, and return the magic value

     * `bytes4(keccak256("onERC721Received(address,address,uint256,bytes)"))`; otherwise,

     * the transfer is reverted.

     * @param to The address that will own the minted token

     * @param tokenId uint256 ID of the token to be minted

     * @param _data bytes data to send along with a safe transfer check

     */

    function _safeMint(address to, uint256 tokenId, bytes memory _data) internal {

        _mint(to, tokenId);

        require(_checkOnERC721Received(address(0), to, tokenId, _data), "ERC721: transfer to non ERC721Receiver implementer");

    }



    /**

     * @dev Internal function to mint a new token.

     * Reverts if the given token ID already exists.

     * @param to The address that will own the minted token

     * @param tokenId uint256 ID of the token to be minted

     */

    function _mint(address to, uint256 tokenId) internal {

        require(to != address(0), "ERC721: mint to the zero address");

        require(!_exists(tokenId), "ERC721: token already minted");



        _tokenOwner[tokenId] = to;

        _ownedTokensCount[to].increment();



        emit Transfer(address(0), to, tokenId);

    }



    /**

     * @dev Internal function to burn a specific token.

     * Reverts if the token does not exist.

     * Deprecated, use {_burn} instead.

     * @param owner owner of the token to burn

     * @param tokenId uint256 ID of the token being burned

     */

    function _burn(address owner, uint256 tokenId) internal {

        require(ownerOf(tokenId) == owner, "ERC721: burn of token that is not own");



        _clearApproval(tokenId);



        _ownedTokensCount[owner].decrement();

        _tokenOwner[tokenId] = address(0);



        emit Transfer(owner, address(0), tokenId);

    }



    /**

     * @dev Internal function to burn a specific token.

     * Reverts if the token does not exist.

     * @param tokenId uint256 ID of the token being burned

     */

    function _burn(uint256 tokenId) internal {

        _burn(ownerOf(tokenId), tokenId);

    }



    /**

     * @dev Internal function to transfer ownership of a given token ID to another address.

     * As opposed to {transferFrom}, this imposes no restrictions on msg.sender.

     * @param from current owner of the token

     * @param to address to receive the ownership of the given token ID

     * @param tokenId uint256 ID of the token to be transferred

     */

    function _transferFrom(address from, address to, uint256 tokenId) internal {

        require(ownerOf(tokenId) == from, "ERC721: transfer of token that is not own");

        require(to != address(0), "ERC721: transfer to the zero address");



        _clearApproval(tokenId);



        _ownedTokensCount[from].decrement();

        _ownedTokensCount[to].increment();



        _tokenOwner[tokenId] = to;



        emit Transfer(from, to, tokenId);

    }



    /**

     * @dev Internal function to invoke {IERC721Receiver-onERC721Received} on a target address.

     * The call is not executed if the target address is not a contract.

     *

     * This is an internal detail of the `ERC721` contract and its use is deprecated.

     * @param from address representing the previous owner of the given token ID

     * @param to target address that will receive the tokens

     * @param tokenId uint256 ID of the token to be transferred

     * @param _data bytes optional data to send along with the call

     * @return bool whether the call correctly returned the expected magic value

     */

    function _checkOnERC721Received(address from, address to, uint256 tokenId, bytes memory _data)

        internal returns (bool)

    {

        if (!to.isContract()) {

            return true;

        }

        // solhint-disable-next-line avoid-low-level-calls

        (bool success, bytes memory returndata) = to.call(abi.encodeWithSelector(

            IERC721Receiver(to).onERC721Received.selector,

            _msgSender(),

            from,

            tokenId,

            _data

        ));

        if (!success) {

            if (returndata.length > 0) {

                // solhint-disable-next-line no-inline-assembly

                assembly {

                    let returndata_size := mload(returndata)

                    revert(add(32, returndata), returndata_size)

                }

            } else {

                revert("ERC721: transfer to non ERC721Receiver implementer");

            }

        } else {

            bytes4 retval = abi.decode(returndata, (bytes4));

            return (retval == _ERC721_RECEIVED);

        }

    }



    /**

     * @dev Private function to clear current approval of a given token ID.

     * @param tokenId uint256 ID of the token to be transferred

     */

    function _clearApproval(uint256 tokenId) private {

        if (_tokenApprovals[tokenId] != address(0)) {

            _tokenApprovals[tokenId] = address(0);

        }

    }

}

contract ERC721Metadata is Context, ERC165, ERC721, IERC721Metadata {

    // Token name

    string private _name;



    // Token symbol

    string private _symbol;



    // Base URI

    string private _baseURI;



    // Optional mapping for token URIs

    mapping(uint256 => string) private _tokenURIs;



    /*

     *     bytes4(keccak256('name()')) == 0x06fdde03

     *     bytes4(keccak256('symbol()')) == 0x95d89b41

     *     bytes4(keccak256('tokenURI(uint256)')) == 0xc87b56dd

     *

     *     => 0x06fdde03 ^ 0x95d89b41 ^ 0xc87b56dd == 0x5b5e139f

     */

    bytes4 private constant _INTERFACE_ID_ERC721_METADATA = 0x5b5e139f;



    /**

     * @dev Constructor function

     */

    constructor (string memory name, string memory symbol) public {

        _name = name;

        _symbol = symbol;



        // register the supported interfaces to conform to ERC721 via ERC165

        _registerInterface(_INTERFACE_ID_ERC721_METADATA);

    }



    /**

     * @dev Gets the token name.

     * @return string representing the token name

     */

    function name() external view returns (string memory) {

        return _name;

    }



    /**

     * @dev Gets the token symbol.

     * @return string representing the token symbol

     */

    function symbol() external view returns (string memory) {

        return _symbol;

    }



    /**

     * @dev Returns the URI for a given token ID. May return an empty string.

     *

     * If the token's URI is non-empty and a base URI was set (via

     * {_setBaseURI}), it will be added to the token ID's URI as a prefix.

     *

     * Reverts if the token ID does not exist.

     */

    function tokenURI(uint256 tokenId) external view returns (string memory) {

        require(_exists(tokenId), "ERC721Metadata: URI query for nonexistent token");



        string memory _tokenURI = _tokenURIs[tokenId];



        // Even if there is a base URI, it is only appended to non-empty token-specific URIs

        if (bytes(_tokenURI).length == 0) {

            return "";

        } else {

            // abi.encodePacked is being used to concatenate strings

            return string(abi.encodePacked(_baseURI, _tokenURI));

        }

    }



    /**

     * @dev Internal function to set the token URI for a given token.

     *

     * Reverts if the token ID does not exist.

     *

     * TIP: if all token IDs share a prefix (e.g. if your URIs look like

     * `http://api.myproject.com/token/<id>`), use {_setBaseURI} to store

     * it and save gas.

     */

    function _setTokenURI(uint256 tokenId, string memory _tokenURI) internal {

        require(_exists(tokenId), "ERC721Metadata: URI set of nonexistent token");

        _tokenURIs[tokenId] = _tokenURI;

    }



    /**

     * @dev Internal function to set the base URI for all token IDs. It is

     * automatically added as a prefix to the value returned in {tokenURI}.

     *

     * _Available since v2.5.0._

     */

    function _setBaseURI(string memory baseURI) internal {

        _baseURI = baseURI;

    }



    /**

    * @dev Returns the base URI set via {_setBaseURI}. This will be

    * automatically added as a preffix in {tokenURI} to each token's URI, when

    * they are non-empty.

    *

    * _Available since v2.5.0._

    */

    function baseURI() external view returns (string memory) {

        return _baseURI;

    }



    /**

     * @dev Internal function to burn a specific token.

     * Reverts if the token does not exist.

     * Deprecated, use _burn(uint256) instead.

     * @param owner owner of the token to burn

     * @param tokenId uint256 ID of the token being burned by the msg.sender

     */

    function _burn(address owner, uint256 tokenId) internal {

        super._burn(owner, tokenId);



        // Clear metadata (if any)

        if (bytes(_tokenURIs[tokenId]).length != 0) {

            delete _tokenURIs[tokenId];

        }

    }

}

contract NFT is ERC721Metadata, Ownable {

    string internal _contractURI;



    constructor(string memory name, string memory symbol)

        public

        ERC721Metadata(name, symbol)

    {}



    function contractURI() external view returns (string memory) {

        return _contractURI;

    }



    function mint(address to, uint256 tokenId) external onlyOwner {

        _safeMint(to, tokenId);

    }



    function burn(uint256 tokenId) external onlyOwner {

        _burn(tokenId);

    }



    function setContractURI(string calldata newURI) external onlyOwner {

        _contractURI = newURI;

    }



    function setTokenURI(uint256 tokenId, string calldata newURI)

        external

        onlyOwner

    {

        _setTokenURI(tokenId, newURI);

    }



    function setBaseURI(string calldata newURI) external onlyOwner {

        _setBaseURI(newURI);

    }

}

contract ATokenMock is ERC20, ERC20Detailed {

    using SafeMath for uint256;

    using DecMath for uint256;



    uint256 internal constant YEAR = 31556952; // Number of seconds in one Gregorian calendar year (365.2425 days)



    ERC20 public dai;

    uint256 public liquidityRate;

    uint256 public normalizedIncome;

    address[] public users;

    mapping(address => bool) public isUser;



    constructor(address _dai)

        public

        ERC20Detailed("aDAI", "aDAI", 18)

    {

        dai = ERC20(_dai);



        liquidityRate = 10 ** 26; // 10% APY

        normalizedIncome = 10 ** 27;

    }



    function redeem(uint256 _amount) external {

        _burn(msg.sender, _amount);

        dai.transfer(msg.sender, _amount);

    }



    function mint(address _user, uint256 _amount) external {

        _mint(_user, _amount);

        if (!isUser[_user]) {

            users.push(_user);

            isUser[_user] = true;

        }

    }



    function mintInterest(uint256 _seconds) external {

        uint256 interest;

        address user;

        for (uint256 i = 0; i < users.length; i++) {

            user = users[i];

            interest = balanceOf(user).mul(_seconds).mul(liquidityRate).div(YEAR.mul(10**27));

            _mint(user, interest);

        }

        normalizedIncome = normalizedIncome.mul(_seconds).mul(liquidityRate).div(YEAR.mul(10**27)).add(normalizedIncome);

    }



    function setLiquidityRate(uint256 _liquidityRate) external {

        liquidityRate = _liquidityRate;

    }

}

contract CERC20Mock is ERC20, ERC20Detailed {

    address public dai;



    uint256 internal _supplyRate;

    uint256 internal _exchangeRate;



    constructor(address _dai) public ERC20Detailed("cDAI", "cDAI", 8) {

        dai = _dai;

        uint256 daiDecimals = ERC20Detailed(_dai).decimals();

        _exchangeRate = 2 * (10**(daiDecimals + 8)); // 1 cDAI = 0.02 DAI

        _supplyRate = 45290900000; // 10% supply rate per year

    }



    function mint(uint256 amount) external returns (uint256) {

        require(

            ERC20(dai).transferFrom(msg.sender, address(this), amount),

            "Error during transferFrom"

        ); // 1 DAI

        _mint(msg.sender, (amount * 10**18) / _exchangeRate);

        return 0;

    }



    function redeemUnderlying(uint256 amount) external returns (uint256) {

        _burn(msg.sender, (amount * 10**18) / _exchangeRate);

        require(

            ERC20(dai).transfer(msg.sender, amount),

            "Error during transfer"

        ); // 1 DAI

        return 0;

    }



    function exchangeRateStored() external view returns (uint256) {

        return _exchangeRate;

    }



    function exchangeRateCurrent() external view returns (uint256) {

        return _exchangeRate;

    }



    function _setExchangeRateStored(uint256 _rate) external returns (uint256) {

        _exchangeRate = _rate;

    }



    function supplyRatePerBlock() external view returns (uint256) {

        return _supplyRate;

    }



    function _setSupplyRatePerBlock(uint256 _rate) external {

        _supplyRate = _rate;

    }

}

contract ERC20Mock is ERC20, ERC20Detailed("", "", 6) {

    function mint(address to, uint256 amount) public {

        _mint(to, amount);

    }

}

contract VaultMock is ERC20, ERC20Detailed {

    using SafeMath for uint256;

    using DecMath for uint256;



    ERC20 public underlying;



    constructor(address _underlying) public ERC20Detailed("yUSD", "yUSD", 18) {

        underlying = ERC20(_underlying);

    }



    function deposit(uint256 tokenAmount) public {

        uint256 sharePrice = getPricePerFullShare();

        _mint(msg.sender, tokenAmount.decdiv(sharePrice));



        underlying.transferFrom(msg.sender, address(this), tokenAmount);

    }



    function withdraw(uint256 sharesAmount) public {

        uint256 sharePrice = getPricePerFullShare();

        uint256 underlyingAmount = sharesAmount.decmul(sharePrice);

        _burn(msg.sender, sharesAmount);



        underlying.transfer(msg.sender, underlyingAmount);

    }



    function getPricePerFullShare() public view returns (uint256) {

        uint256 _totalSupply = totalSupply();

        if (_totalSupply == 0) {

            return 10**18;

        }

        return underlying.balanceOf(address(this)).decdiv(_totalSupply);

    }

}

contract EMAOracle is IInterestOracle {

    using SafeMath for uint256;

    using DecMath for uint256;



    uint256 internal constant PRECISION = 10**18;



    /**

        Immutable parameters

     */

    uint256 public UPDATE_INTERVAL;

    uint256 public UPDATE_MULTIPLIER;

    uint256 public ONE_MINUS_UPDATE_MULTIPLIER;



    /**

        Public variables

     */

    uint256 public emaStored;

    uint256 public lastIncomeIndex;

    uint256 public lastUpdateTimestamp;



    /**

        External contracts

     */

    IMoneyMarket public moneyMarket;



    constructor(

        uint256 _emaInitial,

        uint256 _updateInterval,

        uint256 _smoothingFactor,

        uint256 _averageWindowInIntervals,

        address _moneyMarket

    ) public {

        emaStored = _emaInitial;

        UPDATE_INTERVAL = _updateInterval;

        lastUpdateTimestamp = now;



        uint256 updateMultiplier = _smoothingFactor.div(_averageWindowInIntervals.add(1));

        UPDATE_MULTIPLIER = updateMultiplier;

        ONE_MINUS_UPDATE_MULTIPLIER = PRECISION.sub(updateMultiplier);



        moneyMarket = IMoneyMarket(_moneyMarket);

        lastIncomeIndex = moneyMarket.incomeIndex();

    }



    function updateAndQuery() public returns (bool updated, uint256 value) {

        uint256 timeElapsed = now - lastUpdateTimestamp;

        if (timeElapsed < UPDATE_INTERVAL) {

            return (false, emaStored);

        }



        // save gas by loading storage variables to memory

        uint256 _lastIncomeIndex = lastIncomeIndex;

        uint256 _emaStored = emaStored;



        uint256 newIncomeIndex = moneyMarket.incomeIndex();

        uint256 incomingValue = newIncomeIndex.sub(_lastIncomeIndex).decdiv(_lastIncomeIndex).div(timeElapsed);



        updated = true;

        value = incomingValue.mul(UPDATE_MULTIPLIER).add(_emaStored.mul(ONE_MINUS_UPDATE_MULTIPLIER)).div(PRECISION);

        emaStored = value;

        lastIncomeIndex = newIncomeIndex;

        lastUpdateTimestamp = now;

    }



    function query() public view returns (uint256 value) {

        return emaStored;

    }

}

contract MPHToken is ERC20, ERC20Detailed, Ownable {

    constructor() public ERC20Detailed("88mph.app", "MPH", 18) {}



    function ownerMint(address account, uint256 amount)

        public

        onlyOwner

        returns (bool)

    {

        _mint(account, amount);

        return true;

    }



    function ownerTransfer(

        address from,

        address to,

        uint256 amount

    ) public onlyOwner returns (bool) {

        _transfer(from, to, amount);

        return true;

    }

}
