pragma solidity 0.6.12;
pragma experimental ABIEncoderV2;

contract DSMath {

    function add(uint x, uint y) internal pure returns (uint z) {

        require((z = x + y) >= x, "ds-math-add-overflow");

    }

    function sub(uint x, uint y) internal pure returns (uint z) {

        require((z = x - y) <= x, "ds-math-sub-underflow");

    }

    function mul(uint x, uint y) internal pure returns (uint z) {

        require(y == 0 || (z = x * y) / y == x, "ds-math-mul-overflow");

    }



    function min(uint x, uint y) internal pure returns (uint z) {

        return x <= y ? x : y;

    }

    function max(uint x, uint y) internal pure returns (uint z) {

        return x >= y ? x : y;

    }

    function imin(int x, int y) internal pure returns (int z) {

        return x <= y ? x : y;

    }

    function imax(int x, int y) internal pure returns (int z) {

        return x >= y ? x : y;

    }



    uint constant WAD = 10 ** 18;

    uint constant RAY = 10 ** 27;



    //rounds to zero if x*y < WAD / 2

    function wmul(uint x, uint y) internal pure returns (uint z) {

        z = add(mul(x, y), WAD / 2) / WAD;

    }

    //rounds to zero if x*y < WAD / 2

    function rmul(uint x, uint y) internal pure returns (uint z) {

        z = add(mul(x, y), RAY / 2) / RAY;

    }

    //rounds to zero if x*y < WAD / 2

    function wdiv(uint x, uint y) internal pure returns (uint z) {

        z = add(mul(x, WAD), y / 2) / y;

    }

    //rounds to zero if x*y < RAY / 2

    function rdiv(uint x, uint y) internal pure returns (uint z) {

        z = add(mul(x, RAY), y / 2) / y;

    }



    // This famous algorithm is called "exponentiation by squaring"

    // and calculates x^n with x as fixed-point and n as regular unsigned.

    //

    // It's O(log n), instead of O(n) for naive repeated multiplication.

    //

    // These facts are why it works:

    //

    //  If n is even, then x^n = (x^2)^(n/2).

    //  If n is odd,  then x^n = x * x^(n-1),

    //   and applying the equation for even x gives

    //    x^n = x * (x^2)^((n-1) / 2).

    //

    //  Also, EVM division is flooring and

    //    floor[(n-1) / 2] = floor[n / 2].

    //

    function rpow(uint x, uint n) internal pure returns (uint z) {

        z = n % 2 != 0 ? x : RAY;



        for (n /= 2; n != 0; n /= 2) {

            x = rmul(x, x);



            if (n % 2 != 0) {

                z = rmul(z, x);

            }

        }

    }

}

interface ERC20 {

    function totalSupply() external view returns (uint);

    function decimals() external view returns (uint);

    function balanceOf(address tokenOwner) external view returns (uint balance);

    function allowance(address tokenOwner, address spender) external view returns (uint remaining);

    function transfer(address to, uint tokens) external returns (bool success);

    function approve(address spender, uint tokens) external returns (bool success);

    function transferFrom(address from, address to, uint tokens) external returns (bool success);

}

interface IFeature {



    enum OwnerSignature {

        Anyone,             // Anyone

        Required,           // Owner required

        Optional,           // Owner and/or guardians

        Disallowed          // guardians only

    }



    /**

    * @notice Utility method to recover any ERC20 token that was sent to the Feature by mistake.

    * @param _token The token to recover.

    */

    function recoverToken(address _token) external;



    /**

     * @notice Inits a Feature for a wallet by e.g. setting some wallet specific parameters in storage.

     * @param _wallet The wallet.

     */

    function init(address _wallet) external;



    /**

     * @notice Helper method to check if an address is an authorised feature of a target wallet.

     * @param _wallet The target wallet.

     * @param _feature The address.

     */

    function isFeatureAuthorisedInVersionManager(address _wallet, address _feature) external view returns (bool);



    /**

    * @notice Gets the number of valid signatures that must be provided to execute a

    * specific relayed transaction.

    * @param _wallet The target wallet.

    * @param _data The data of the relayed transaction.

    * @return The number of required signatures and the wallet owner signature requirement.

    */

    function getRequiredSignatures(address _wallet, bytes calldata _data) external view returns (uint256, OwnerSignature);



    /**

    * @notice Gets the list of static call signatures that this feature responds to on behalf of wallets

    */

    function getStaticCallSignatures() external view returns (bytes4[] memory);

}

interface ILimitStorage {



    struct Limit {

        // the current limit

        uint128 current;

        // the pending limit if any

        uint128 pending;

        // when the pending limit becomes the current limit

        uint64 changeAfter;

    }



    struct DailySpent {

        // The amount already spent during the current period

        uint128 alreadySpent;

        // The end of the current period

        uint64 periodEnd;

    }



    function setLimit(address _wallet, Limit memory _limit) external;



    function getLimit(address _wallet) external view returns (Limit memory _limit);



    function setDailySpent(address _wallet, DailySpent memory _dailySpent) external;



    function getDailySpent(address _wallet) external view returns (DailySpent memory _dailySpent);



    function setLimitAndDailySpent(address _wallet, Limit memory _limit, DailySpent memory _dailySpent) external;



    function getLimitAndDailySpent(address _wallet) external view returns (Limit memory _limit, DailySpent memory _dailySpent);

}

interface ILockStorage {

    function isLocked(address _wallet) external view returns (bool);



    function getLock(address _wallet) external view returns (uint256);



    function getLocker(address _wallet) external view returns (address);



    function setLock(address _wallet, address _locker, uint256 _releaseAfter) external;

}

interface IMakerRegistry {

    function collaterals(address _collateral) external view returns (bool exists, uint128 index, JoinLike join, bytes32 ilk);

    function addCollateral(JoinLike _joinAdapter) external;

    function removeCollateral(address _token) external;

    function getCollateralTokens() external view returns (address[] memory _tokens);

    function getIlk(address _token) external view returns (bytes32 _ilk);

    function getCollateral(bytes32 _ilk) external view returns (JoinLike _join, GemLike _token);

}

interface IModuleRegistry {

    function registerModule(address _module, bytes32 _name) external;



    function deregisterModule(address _module) external;



    function registerUpgrader(address _upgrader, bytes32 _name) external;



    function deregisterUpgrader(address _upgrader) external;



    function recoverToken(address _token) external;



    function moduleInfo(address _module) external view returns (bytes32);



    function upgraderInfo(address _upgrader) external view returns (bytes32);



    function isRegisteredModule(address _module) external view returns (bool);



    function isRegisteredModule(address[] calldata _modules) external view returns (bool);



    function isRegisteredUpgrader(address _upgrader) external view returns (bool);

}

interface IUniswapExchange {

    function getEthToTokenOutputPrice(uint256 _tokensBought) external view returns (uint256);

    function getEthToTokenInputPrice(uint256 _ethSold) external view returns (uint256);

    function getTokenToEthOutputPrice(uint256 _ethBought) external view returns (uint256);

    function getTokenToEthInputPrice(uint256 _tokensSold) external view returns (uint256);

}

interface IUniswapFactory {

    function getExchange(address _token) external view returns(address);

}

interface IVersionManager {

    /**

     * @notice Returns true if the feature is authorised for the wallet

     * @param _wallet The target wallet.

     * @param _feature The feature.

     */

    function isFeatureAuthorised(address _wallet, address _feature) external view returns (bool);



    /**

     * @notice Lets a feature (caller) invoke a wallet.

     * @param _wallet The target wallet.

     * @param _to The target address for the transaction.

     * @param _value The value of the transaction.

     * @param _data The data of the transaction.

     */

    function checkAuthorisedFeatureAndInvokeWallet(

        address _wallet,

        address _to,

        uint256 _value,

        bytes calldata _data

    ) external returns (bytes memory _res);



    /* ******* Backward Compatibility with old Storages and BaseWallet *************** */



    /**

     * @notice Sets a new owner for the wallet.

     * @param _newOwner The new owner.

     */

    function setOwner(address _wallet, address _newOwner) external;



    /**

     * @notice Lets a feature write data to a storage contract.

     * @param _wallet The target wallet.

     * @param _storage The storage contract.

     * @param _data The data of the call

     */

    function invokeStorage(address _wallet, address _storage, bytes calldata _data) external;



    /**

     * @notice Upgrade a wallet to a new version.

     * @param _wallet the wallet to upgrade

     * @param _toVersion the new version

     */

    function upgradeWallet(address _wallet, uint256 _toVersion) external;

 

}

interface IWallet {

    /**

     * @notice Returns the wallet owner.

     * @return The wallet owner address.

     */

    function owner() external view returns (address);



    /**

     * @notice Returns the number of authorised modules.

     * @return The number of authorised modules.

     */

    function modules() external view returns (uint);



    /**

     * @notice Sets a new owner for the wallet.

     * @param _newOwner The new owner.

     */

    function setOwner(address _newOwner) external;



    /**

     * @notice Checks if a module is authorised on the wallet.

     * @param _module The module address to check.

     * @return `true` if the module is authorised, otherwise `false`.

     */

    function authorised(address _module) external view returns (bool);



    /**

     * @notice Returns the module responsible for a static call redirection.

     * @param _sig The signature of the static call.

     * @return the module doing the redirection

     */

    function enabled(bytes4 _sig) external view returns (address);



    /**

     * @notice Enables/Disables a module.

     * @param _module The target module.

     * @param _value Set to `true` to authorise the module.

     */

    function authoriseModule(address _module, bool _value) external;



    /**

    * @notice Enables a static method by specifying the target module to which the call must be delegated.

    * @param _module The target module.

    * @param _method The static method signature.

    */

    function enableStaticCall(address _module, bytes4 _method) external;

}

interface GemLike {

    function balanceOf(address) external view returns (uint);

    function transferFrom(address, address, uint) external returns (bool);

    function approve(address, uint) external returns (bool success);

    function decimals() external view returns (uint);

    function transfer(address,uint) external returns (bool);

}

interface DSTokenLike {

    function mint(address,uint) external;

    function burn(address,uint) external;

}

interface VatLike {

    function can(address, address) external view returns (uint);

    function dai(address) external view returns (uint);

    function hope(address) external;

    function wards(address) external view returns (uint);

    function ilks(bytes32) external view returns (uint Art, uint rate, uint spot, uint line, uint dust);

    function urns(bytes32, address) external view returns (uint ink, uint art);

    function frob(bytes32, address, address, address, int, int) external;

    function slip(bytes32,address,int) external;

    function move(address,address,uint) external;

    function fold(bytes32,address,int) external;

    function suck(address,address,uint256) external;

    function flux(bytes32, address, address, uint) external;

    function fork(bytes32, address, address, int, int) external;

}

interface JoinLike {

    function ilk() external view returns (bytes32);

    function gem() external view returns (GemLike);

    function dai() external view returns (GemLike);

    function join(address, uint) external;

    function exit(address, uint) external;

    function vat() external returns (VatLike);

    function live() external returns (uint);

}

interface ManagerLike {

    function vat() external view returns (address);

    function urns(uint) external view returns (address);

    function open(bytes32, address) external returns (uint);

    function frob(uint, int, int) external;

    function give(uint, address) external;

    function move(uint, address, uint) external;

    function flux(uint, address, uint) external;

    function shift(uint, uint) external;

    function ilks(uint) external view returns (bytes32);

    function owns(uint) external view returns (address);

}

interface ScdMcdMigrationLike {

    function swapSaiToDai(uint) external;

    function swapDaiToSai(uint) external;

    function migrate(bytes32) external returns (uint);

    function saiJoin() external returns (JoinLike);

    function wethJoin() external returns (JoinLike);

    function daiJoin() external returns (JoinLike);

    function cdpManager() external returns (ManagerLike);

    function tub() external returns (SaiTubLike);

}

interface ValueLike {

    function peek() external returns (uint, bool);

}

interface SaiTubLike {

    function skr() external view returns (GemLike);

    function gem() external view returns (GemLike);

    function gov() external view returns (GemLike);

    function sai() external view returns (GemLike);

    function pep() external view returns (ValueLike);

    function bid(uint) external view returns (uint);

    function ink(bytes32) external view returns (uint);

    function tab(bytes32) external returns (uint);

    function rap(bytes32) external returns (uint);

    function shut(bytes32) external;

    function exit(uint) external;

}

interface VoxLike {

    function par() external returns (uint);

}

interface JugLike {

    function drip(bytes32) external;

}

interface PotLike {

    function chi() external view returns (uint);

    function pie(address) external view returns (uint);

    function drip() external;

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

     */

    function mod(uint256 a, uint256 b, string memory errorMessage) internal pure returns (uint256) {

        require(b != 0, errorMessage);

        return a % b;

    }

}

contract BaseFeature is IFeature {



    // Empty calldata

    bytes constant internal EMPTY_BYTES = "";

    // Mock token address for ETH

    address constant internal ETH_TOKEN = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;

    // The address of the Lock storage

    ILockStorage internal lockStorage;

    // The address of the Version Manager

    IVersionManager internal versionManager;



    event FeatureCreated(bytes32 name);



    /**

     * @notice Throws if the wallet is locked.

     */

    modifier onlyWhenUnlocked(address _wallet) {

        require(!lockStorage.isLocked(_wallet), "BF: wallet locked");

        _;

    }



    /**

     * @notice Throws if the sender is not the VersionManager.

     */

    modifier onlyVersionManager() {

        require(msg.sender == address(versionManager), "BF: caller must be VersionManager");

        _;

    }



    /**

     * @notice Throws if the sender is not the owner of the target wallet.

     */

    modifier onlyWalletOwner(address _wallet) {

        require(isOwner(_wallet, msg.sender), "BF: must be wallet owner");

        _;

    }



    /**

     * @notice Throws if the sender is not an authorised feature of the target wallet.

     */

    modifier onlyWalletFeature(address _wallet) {

        require(versionManager.isFeatureAuthorised(_wallet, msg.sender), "BF: must be a wallet feature");

        _;

    }



    /**

     * @notice Throws if the sender is not the owner of the target wallet or the feature itself.

     */

    modifier onlyWalletOwnerOrFeature(address _wallet) {

        // Wrapping in an internal method reduces deployment cost by avoiding duplication of inlined code

        verifyOwnerOrAuthorisedFeature(_wallet, msg.sender);

        _;

    }



    constructor(

        ILockStorage _lockStorage,

        IVersionManager _versionManager,

        bytes32 _name

    ) public {

        lockStorage = _lockStorage;

        versionManager = _versionManager;

        emit FeatureCreated(_name);

    }



    /**

    * @inheritdoc IFeature

    */

    function recoverToken(address _token) external virtual override {

        uint total = ERC20(_token).balanceOf(address(this));

        _token.call(abi.encodeWithSelector(ERC20(_token).transfer.selector, address(versionManager), total));

    }



    /**

     * @notice Inits the feature for a wallet by doing nothing.

     * @dev !! Overriding methods need make sure `init()` can only be called by the VersionManager !!

     * @param _wallet The wallet.

     */

    function init(address _wallet) external virtual override  {}



    /**

     * @inheritdoc IFeature

     */

    function getRequiredSignatures(address, bytes calldata) external virtual view override returns (uint256, OwnerSignature) {

        revert("BF: disabled method");

    }



    /**

     * @inheritdoc IFeature

     */

    function getStaticCallSignatures() external virtual override view returns (bytes4[] memory _sigs) {}



    /**

     * @inheritdoc IFeature

     */

    function isFeatureAuthorisedInVersionManager(address _wallet, address _feature) public override view returns (bool) {

        return versionManager.isFeatureAuthorised(_wallet, _feature);

    }



    /**

    * @notice Checks that the wallet address provided as the first parameter of _data matches _wallet

    * @return false if the addresses are different.

    */

    function verifyData(address _wallet, bytes calldata _data) internal pure returns (bool) {

        require(_data.length >= 36, "RM: Invalid dataWallet");

        address dataWallet = abi.decode(_data[4:], (address));

        return dataWallet == _wallet;

    }

    

     /**

     * @notice Helper method to check if an address is the owner of a target wallet.

     * @param _wallet The target wallet.

     * @param _addr The address.

     */

    function isOwner(address _wallet, address _addr) internal view returns (bool) {

        return IWallet(_wallet).owner() == _addr;

    }



    /**

     * @notice Verify that the caller is an authorised feature or the wallet owner.

     * @param _wallet The target wallet.

     * @param _sender The caller.

     */

    function verifyOwnerOrAuthorisedFeature(address _wallet, address _sender) internal view {

        require(isFeatureAuthorisedInVersionManager(_wallet, _sender) || isOwner(_wallet, _sender), "BF: must be owner or feature");

    }



    /**

     * @notice Helper method to invoke a wallet.

     * @param _wallet The target wallet.

     * @param _to The target address for the transaction.

     * @param _value The value of the transaction.

     * @param _data The data of the transaction.

     */

    function invokeWallet(address _wallet, address _to, uint256 _value, bytes memory _data)

        internal

        returns (bytes memory _res) 

    {

        _res = versionManager.checkAuthorisedFeatureAndInvokeWallet(_wallet, _to, _value, _data);

    }



}

abstract contract MakerV2Base is DSMath, BaseFeature {



    bytes32 constant private NAME = "MakerV2Manager";



    // The address of the (MCD) DAI token

    GemLike internal daiToken;

    // The address of the SAI <-> DAI migration contract

    address internal scdMcdMigration;

    // The address of the Dai Adapter

    JoinLike internal daiJoin;

    // The address of the Vat

    VatLike internal vat;



    using SafeMath for uint256;



    // *************** Constructor ********************** //



    constructor(

        ILockStorage _lockStorage,

        ScdMcdMigrationLike _scdMcdMigration,

        IVersionManager _versionManager

    )

        BaseFeature(_lockStorage, _versionManager, NAME)

        public

    {

        scdMcdMigration = address(_scdMcdMigration);

        daiJoin = _scdMcdMigration.daiJoin();

        daiToken = daiJoin.dai();

        vat = daiJoin.vat();

    }



    /**

     * @inheritdoc IFeature

     */

    function getRequiredSignatures(address, bytes calldata) external view override returns (uint256, OwnerSignature) {

        return (1, OwnerSignature.Required);

    }

}

abstract contract MakerV2Invest is MakerV2Base {



    // The address of the Pot

    PotLike internal pot;



    // *************** Events ********************** //



    // WARNING: in a previous version of this module, the third parameter of `InvestmentRemoved`

    // represented the *fraction* (out of 10000) of the investment withdrawn, not the absolute amount withdrawn

    event InvestmentRemoved(address indexed _wallet, address _token, uint256 _amount);

    event InvestmentAdded(address indexed _wallet, address _token, uint256 _amount, uint256 _period);



    // *************** Constructor ********************** //



    constructor(PotLike _pot) public {

        pot = _pot;

    }



    // *************** External/Public Functions ********************* //



    /**

    * @notice Lets the wallet owner deposit MCD DAI into the DSR Pot.

    * @param _wallet The target wallet.

    * @param _amount The amount of DAI to deposit

    */

    function joinDsr(

        address _wallet,

        uint256 _amount

    )

        external

        onlyWalletOwnerOrFeature(_wallet)

        onlyWhenUnlocked(_wallet)

    {

        // Execute drip to get the chi rate updated to rho == block.timestamp, otherwise join will fail

        pot.drip();

        // Approve DAI adapter to take the DAI amount

        invokeWallet(

            _wallet,

            address(daiToken),

            0,

            abi.encodeWithSignature("approve(address,uint256)", address(daiJoin), _amount)

        );

        // Join DAI into the vat (_amount of external DAI is burned and the vat transfers _amount of internal DAI from the adapter to the _wallet)

        invokeWallet(

            _wallet,

            address(daiJoin),

            0,

            abi.encodeWithSignature("join(address,uint256)", address(_wallet), _amount)

        );

        // Approve the pot to take out (internal) DAI from the wallet's balance in the vat

        grantVatAccess(_wallet, address(pot));

        // Compute the pie value in the pot

        uint256 pie = _amount.mul(RAY) / pot.chi();

        // Join the pie value to the pot

        invokeWallet(_wallet, address(pot), 0, abi.encodeWithSignature("join(uint256)", pie));

        // Emitting event

        emit InvestmentAdded(_wallet, address(daiToken), _amount, 0);

    }



    /**

    * @notice Lets the wallet owner withdraw MCD DAI from the DSR pot.

    * @param _wallet The target wallet.

    * @param _amount The amount of DAI to withdraw.

    */

    function exitDsr(

        address _wallet,

        uint256 _amount

    )

        external

        onlyWalletOwnerOrFeature(_wallet)

        onlyWhenUnlocked(_wallet)

    {

        // Execute drip to count the savings accumulated until this moment

        pot.drip();

        // Calculates the pie value in the pot equivalent to the DAI wad amount

        uint256 pie = _amount.mul(RAY) / pot.chi();

        // Exit DAI from the pot

        invokeWallet(_wallet, address(pot), 0, abi.encodeWithSignature("exit(uint256)", pie)

        );

        // Allow adapter to access the _wallet's DAI balance in the vat

        grantVatAccess(_wallet, address(daiJoin));

        // Check the actual balance of DAI in the vat after the pot exit

        uint bal = vat.dai(_wallet);

        // It is necessary to check if due to rounding the exact _amount can be exited by the adapter.

        // Otherwise it will do the maximum DAI balance in the vat

        uint256 withdrawn = bal >= _amount.mul(RAY) ? _amount : bal / RAY;

        invokeWallet(

            _wallet,

            address(daiJoin),

            0,

            abi.encodeWithSignature("exit(address,uint256)", address(_wallet), withdrawn)

        );

        // Emitting event

        emit InvestmentRemoved(_wallet, address(daiToken), withdrawn);

    }



    /**

    * @notice Lets the wallet owner withdraw their entire MCD DAI balance from the DSR pot.

    * @param _wallet The target wallet.

    */

    function exitAllDsr(

        address _wallet

    )

        external

        onlyWalletOwnerOrFeature(_wallet)

        onlyWhenUnlocked(_wallet)

    {

        // Execute drip to count the savings accumulated until this moment

        pot.drip();

        // Gets the total pie belonging to the _wallet

        uint256 pie = pot.pie(_wallet);

        // Exit DAI from the pot

        invokeWallet(_wallet, address(pot), 0, abi.encodeWithSignature("exit(uint256)", pie));

        // Allow adapter to access the _wallet's DAI balance in the vat

        grantVatAccess(_wallet, address(daiJoin));

        // Exits the DAI amount corresponding to the value of pie

        uint256 withdrawn = pot.chi().mul(pie) / RAY;

        invokeWallet(

            _wallet,

            address(daiJoin),

            0,

            abi.encodeWithSignature("exit(address,uint256)", address(_wallet), withdrawn)

        );

        // Emitting event

        emit InvestmentRemoved(_wallet, address(daiToken), withdrawn);

    }



    /**

    * @notice Returns the amount of DAI currently held in the DSR pot.

    * @param _wallet The target wallet.

    * @return _balance The DSR balance.

    */

    function dsrBalance(address _wallet) external view returns (uint256 _balance) {

        return pot.chi().mul(pot.pie(_wallet)) / RAY;

    }



    /* ****************************************** Internal method ******************************************* */



    /**

    * @notice Grant access to the wallet's internal DAI balance in the VAT to an operator.

    * @param _wallet The target wallet.

    * @param _operator The grantee of the access

    */

    function grantVatAccess(address _wallet, address _operator) internal {

        if (vat.can(_wallet, _operator) == 0) {

            invokeWallet(_wallet, address(vat), 0, abi.encodeWithSignature("hope(address)", _operator));

        }

    }

}

abstract contract MakerV2Loan is MakerV2Base {



    bytes4 private constant IS_NEW_VERSION = bytes4(keccak256("isNewVersion(address)"));



    // The address of the MKR token

    GemLike internal mkrToken;

    // The address of the WETH token

    GemLike internal wethToken;

    // The address of the WETH Adapter

    JoinLike internal wethJoin;

    // The address of the Jug

    JugLike internal jug;

    // The address of the Vault Manager (referred to as 'CdpManager' to match Maker's naming)

    ManagerLike internal cdpManager;

    // The address of the SCD Tub

    SaiTubLike internal tub;

    // The Maker Registry in which all supported collateral tokens and their adapters are stored

    IMakerRegistry internal makerRegistry;

    // The Uniswap Exchange contract for DAI

    IUniswapExchange internal daiUniswap;

    // The Uniswap Exchange contract for MKR

    IUniswapExchange internal mkrUniswap;

    // Mapping [wallet][ilk] -> loanId, that keeps track of cdp owners

    // while also enforcing a maximum of one loan per token (ilk) and per wallet

    // (which will make future upgrades of the module easier)

    mapping(address => mapping(bytes32 => bytes32)) public loanIds;

    // Lock used by nonReentrant()

    bool private _notEntered = true;



    // ****************** Events *************************** //



    // Vault management events

    event LoanOpened(

        address indexed _wallet,

        bytes32 indexed _loanId,

        address _collateral,

        uint256 _collateralAmount,

        address _debtToken,

        uint256 _debtAmount

    );

    event LoanAcquired(address indexed _wallet, bytes32 indexed _loanId);

    event LoanClosed(address indexed _wallet, bytes32 indexed _loanId);

    event CollateralAdded(address indexed _wallet, bytes32 indexed _loanId, address _collateral, uint256 _collateralAmount);

    event CollateralRemoved(address indexed _wallet, bytes32 indexed _loanId, address _collateral, uint256 _collateralAmount);

    event DebtAdded(address indexed _wallet, bytes32 indexed _loanId, address _debtToken, uint256 _debtAmount);

    event DebtRemoved(address indexed _wallet, bytes32 indexed _loanId, address _debtToken, uint256 _debtAmount);





    // *************** Modifiers *************************** //



    /**

     * @notice Prevents call reentrancy

     */

    modifier nonReentrant() {

        require(_notEntered, "MV2: reentrant call");

        _notEntered = false;

        _;

        _notEntered = true;

    }



    modifier onlyNewVersion() {

        (bool success, bytes memory res) = msg.sender.call(abi.encodeWithSignature("isNewVersion(address)", address(this)));

        require(success && abi.decode(res, (bytes4)) == IS_NEW_VERSION , "MV2: not a new version");

        _;

    }



    // *************** Constructor ********************** //



    constructor(

        JugLike _jug,

        IMakerRegistry _makerRegistry,

        IUniswapFactory _uniswapFactory

    )

        public

    {

        cdpManager = ScdMcdMigrationLike(scdMcdMigration).cdpManager();

        tub = ScdMcdMigrationLike(scdMcdMigration).tub();

        wethJoin = ScdMcdMigrationLike(scdMcdMigration).wethJoin();

        wethToken = wethJoin.gem();

        mkrToken = tub.gov();

        jug = _jug;

        makerRegistry = _makerRegistry;

        daiUniswap = IUniswapExchange(_uniswapFactory.getExchange(address(daiToken)));

        mkrUniswap = IUniswapExchange(_uniswapFactory.getExchange(address(mkrToken)));

        // Authorize daiJoin to exit DAI from the module's internal balance in the vat

        vat.hope(address(daiJoin));

    }



    // *************** External/Public Functions ********************* //



    /* ********************************** Implementation of Loan ************************************* */



   /**

     * @notice Opens a collateralized loan.

     * @param _wallet The target wallet.

     * @param _collateral The token used as a collateral.

     * @param _collateralAmount The amount of collateral token provided.

     * @param _debtToken The token borrowed (must be the address of the DAI contract).

     * @param _debtAmount The amount of tokens borrowed.

     * @return _loanId The ID of the created vault.

     */

    function openLoan(

        address _wallet,

        address _collateral,

        uint256 _collateralAmount,

        address _debtToken,

        uint256 _debtAmount

    )

        external

        onlyWalletOwnerOrFeature(_wallet)

        onlyWhenUnlocked(_wallet)

        returns (bytes32 _loanId)

    {

        verifySupportedCollateral(_collateral);

        require(_debtToken == address(daiToken), "MV2: debt token not DAI");

        _loanId = bytes32(openVault(_wallet, _collateral, _collateralAmount, _debtAmount));

        emit LoanOpened(_wallet, _loanId, _collateral, _collateralAmount, _debtToken, _debtAmount);

    }



    /**

     * @notice Adds collateral to a loan identified by its ID.

     * @param _wallet The target wallet.

     * @param _loanId The ID of the target vault.

     * @param _collateral The token used as a collateral.

     * @param _collateralAmount The amount of collateral to add.

     */

    function addCollateral(

        address _wallet,

        bytes32 _loanId,

        address _collateral,

        uint256 _collateralAmount

    )

        external

        onlyWalletOwnerOrFeature(_wallet)

        onlyWhenUnlocked(_wallet)

    {

        verifyLoanOwner(_wallet, _loanId);

        addCollateral(_wallet, uint256(_loanId), _collateralAmount);

        emit CollateralAdded(_wallet, _loanId, _collateral, _collateralAmount);

    }



    /**

     * @notice Removes collateral from a loan identified by its ID.

     * @param _wallet The target wallet.

     * @param _loanId The ID of the target vault.

     * @param _collateral The token used as a collateral.

     * @param _collateralAmount The amount of collateral to remove.

     */

    function removeCollateral(

        address _wallet,

        bytes32 _loanId,

        address _collateral,

        uint256 _collateralAmount

    )

        external

        onlyWalletOwnerOrFeature(_wallet)

        onlyWhenUnlocked(_wallet)

    {

        verifyLoanOwner(_wallet, _loanId);

        removeCollateral(_wallet, uint256(_loanId), _collateralAmount);

        emit CollateralRemoved(_wallet, _loanId, _collateral, _collateralAmount);

    }



    /**

     * @notice Increases the debt by borrowing more token from a loan identified by its ID.

     * @param _wallet The target wallet.

     * @param _loanId The ID of the target vault.

     * @param _debtToken The token borrowed (must be the address of the DAI contract).

     * @param _debtAmount The amount of token to borrow.

     */

    function addDebt(

        address _wallet,

        bytes32 _loanId,

        address _debtToken,

        uint256 _debtAmount

    )

        external

        onlyWalletOwnerOrFeature(_wallet)

        onlyWhenUnlocked(_wallet)

    {

        verifyLoanOwner(_wallet, _loanId);

        addDebt(_wallet, uint256(_loanId), _debtAmount);

        emit DebtAdded(_wallet, _loanId, _debtToken, _debtAmount);

    }



    /**

     * @notice Decreases the debt by repaying some token from a loan identified by its ID.

     * @param _wallet The target wallet.

     * @param _loanId The ID of the target vault.

     * @param _debtToken The token to repay (must be the address of the DAI contract).

     * @param _debtAmount The amount of token to repay.

     */

    function removeDebt(

        address _wallet,

        bytes32 _loanId,

        address _debtToken,

        uint256 _debtAmount

    )

        external

        onlyWalletOwnerOrFeature(_wallet)

        onlyWhenUnlocked(_wallet)

    {

        verifyLoanOwner(_wallet, _loanId);

        updateStabilityFee(uint256(_loanId));

        removeDebt(_wallet, uint256(_loanId), _debtAmount);

        emit DebtRemoved(_wallet, _loanId, _debtToken, _debtAmount);

    }



    /**

     * @notice Closes a collateralized loan by repaying all debts (plus interest) and redeeming all collateral.

     * @param _wallet The target wallet.

     * @param _loanId The ID of the target vault.

     */

    function closeLoan(

        address _wallet,

        bytes32 _loanId

    )

        external

        onlyWalletOwnerOrFeature(_wallet)

        onlyWhenUnlocked(_wallet)

    {

        verifyLoanOwner(_wallet, _loanId);

        updateStabilityFee(uint256(_loanId));

        closeVault(_wallet, uint256(_loanId));

        emit LoanClosed(_wallet, _loanId);

    }



    /* *************************************** Other vault methods ***************************************** */



    /**

     * @notice Lets a vault owner transfer their vault from their wallet to the present module so the vault

     * can be managed by the module.

     * @param _wallet The target wallet.

     * @param _loanId The ID of the target vault.

     */

    function acquireLoan(

        address _wallet,

        bytes32 _loanId

    )

        external

        nonReentrant

        onlyWalletOwnerOrFeature(_wallet)

        onlyWhenUnlocked(_wallet)

    {

        require(cdpManager.owns(uint256(_loanId)) == _wallet, "MV2: wrong vault owner");

        // Transfer the vault from the wallet to the module

        invokeWallet(

            _wallet,

            address(cdpManager),

            0,

            abi.encodeWithSignature("give(uint256,address)", uint256(_loanId), address(this))

        );

        require(cdpManager.owns(uint256(_loanId)) == address(this), "MV2: failed give");

        // Mark the incoming vault as belonging to the wallet (or merge it into the existing vault if there is one)

        assignLoanToWallet(_wallet, _loanId);

        emit LoanAcquired(_wallet, _loanId);

    }



    /**

     * @notice Lets a future upgrade of this module transfer a vault to itself

     * @param _wallet The target wallet.

     * @param _loanId The ID of the target vault.

     */

    function giveVault(

        address _wallet,

        bytes32 _loanId

    )

        external

        onlyWalletFeature(_wallet)

        onlyNewVersion

        onlyWhenUnlocked(_wallet)

    {

        verifyLoanOwner(_wallet, _loanId);

        cdpManager.give(uint256(_loanId), msg.sender);

        clearLoanOwner(_wallet, _loanId);

    }



    /* ************************************** Internal Functions ************************************** */



    function toInt(uint256 _x) internal pure returns (int _y) {

        _y = int(_x);

        require(_y >= 0, "MV2: int overflow");

    }



    function assignLoanToWallet(address _wallet, bytes32 _loanId) internal returns (bytes32 _assignedLoanId) {

        bytes32 ilk = cdpManager.ilks(uint256(_loanId));

        // Check if the user already holds a vault in the MakerV2Manager

        bytes32 existingLoanId = loanIds[_wallet][ilk];

        if (existingLoanId > 0) {

            // Merge the new loan into the existing loan

            cdpManager.shift(uint256(_loanId), uint256(existingLoanId));

            return existingLoanId;

        }

        // Record the new vault as belonging to the wallet

        loanIds[_wallet][ilk] = _loanId;

        return _loanId;

    }



    function clearLoanOwner(address _wallet, bytes32 _loanId) internal {

        delete loanIds[_wallet][cdpManager.ilks(uint256(_loanId))];

    }



    function verifyLoanOwner(address _wallet, bytes32 _loanId) internal view {

        require(loanIds[_wallet][cdpManager.ilks(uint256(_loanId))] == _loanId, "MV2: unauthorized loanId");

    }



    function verifySupportedCollateral(address _collateral) internal view {

        if (_collateral != ETH_TOKEN) {

            (bool collateralSupported,,,) = makerRegistry.collaterals(_collateral);

            require(collateralSupported, "MV2: unsupported collateral");

        }

    }



    function joinCollateral(

        address _wallet,

        uint256 _cdpId,

        uint256 _collateralAmount,

        bytes32 _ilk

    )

        internal

    {

        // Get the adapter and collateral token for the vault

        (JoinLike gemJoin, GemLike collateral) = makerRegistry.getCollateral(_ilk);

        // Convert ETH to WETH if needed

        if (gemJoin == wethJoin) {

            invokeWallet(_wallet, address(wethToken), _collateralAmount, abi.encodeWithSignature("deposit()"));

        }

        // Send the collateral to the module

        invokeWallet(

            _wallet,

            address(collateral),

            0,

            abi.encodeWithSignature("transfer(address,uint256)", address(this), _collateralAmount)

        );

        // Approve the adapter to pull the collateral from the module

        collateral.approve(address(gemJoin), _collateralAmount);

        // Join collateral to the adapter. The first argument to `join` is the address that *technically* owns the vault

        gemJoin.join(cdpManager.urns(_cdpId), _collateralAmount);

    }



    function joinDebt(

        address _wallet,

        uint256 _cdpId,

        uint256 _debtAmount //  art.mul(rate).div(RAY) === [wad]*[ray]/[ray]=[wad]

    )

        internal

    {

        // Send the DAI to the module

        invokeWallet(

            _wallet,

            address(daiToken),

            0,

            abi.encodeWithSignature("transfer(address,uint256)", address(this), _debtAmount)

        );

        // Approve the DAI adapter to burn DAI from the module

        daiToken.approve(address(daiJoin), _debtAmount);

        // Join DAI to the adapter. The first argument to `join` is the address that *technically* owns the vault

        // To avoid rounding issues, we substract one wei to the amount joined

        daiJoin.join(cdpManager.urns(_cdpId), _debtAmount.sub(1));

    }



    function drawAndExitDebt(

        address _wallet,

        uint256 _cdpId,

        uint256 _debtAmount,

        uint256 _collateralAmount,

        bytes32 _ilk

    )

        internal

    {

        // Get the accumulated rate for the collateral type

        (, uint rate,,,) = vat.ilks(_ilk);

        // Express the debt in the RAD units used internally by the vat

        uint daiDebtInRad = _debtAmount.mul(RAY);

        // Lock the collateral and draw the debt. To avoid rounding issues we add an extra wei of debt

        cdpManager.frob(_cdpId, toInt(_collateralAmount), toInt(daiDebtInRad.div(rate) + 1));

        // Transfer the (internal) DAI debt from the cdp's urn to the module.

        cdpManager.move(_cdpId, address(this), daiDebtInRad);

        // Mint the DAI token and exit it to the user's wallet

        daiJoin.exit(_wallet, _debtAmount);

    }



    function updateStabilityFee(

        uint256 _cdpId

    )

        internal

    {

        jug.drip(cdpManager.ilks(_cdpId));

    }



    function debt(

        uint256 _cdpId

    )

        internal

        view

        returns (uint256 _fullRepayment, uint256 _maxNonFullRepayment)

    {

        bytes32 ilk = cdpManager.ilks(_cdpId);

        (, uint256 art) = vat.urns(ilk, cdpManager.urns(_cdpId));

        if (art > 0) {

            (, uint rate,,, uint dust) = vat.ilks(ilk);

            _maxNonFullRepayment = art.mul(rate).sub(dust).div(RAY);

            _fullRepayment = art.mul(rate).div(RAY)

                .add(1) // the amount approved is 1 wei more than the amount repaid, to avoid rounding issues

                .add(art-art.mul(rate).div(RAY).mul(RAY).div(rate)); // adding 1 extra wei if further rounding issues are expected

        }

    }



    function collateral(

        uint256 _cdpId

    )

        internal

        view

        returns (uint256 _collateralAmount)

    {

        (_collateralAmount,) = vat.urns(cdpManager.ilks(_cdpId), cdpManager.urns(_cdpId));

    }



    function verifyValidRepayment(

        uint256 _cdpId,

        uint256 _debtAmount

    )

        internal

        view

    {

        (uint256 fullRepayment, uint256 maxRepayment) = debt(_cdpId);

        require(_debtAmount <= maxRepayment || _debtAmount == fullRepayment, "MV2: repay less or full");

    }



     /**

     * @notice Lets the owner of a wallet open a new vault. The owner must have enough collateral

     * in their wallet.

     * @param _wallet The target wallet

     * @param _collateral The token to use as collateral in the vault.

     * @param _collateralAmount The amount of collateral to lock in the vault.

     * @param _debtAmount The amount of DAI to draw from the vault

     * @return _cdpId The id of the created vault.

     */

    function openVault(

        address _wallet,

        address _collateral,

        uint256 _collateralAmount,

        uint256 _debtAmount

    )

        internal

        returns (uint256 _cdpId)

    {

        // Continue with WETH as collateral instead of ETH if needed

        if (_collateral == ETH_TOKEN) {

            _collateral = address(wethToken);

        }

        // Get the ilk for the collateral

        bytes32 ilk = makerRegistry.getIlk(_collateral);

        // Open a vault if there isn't already one for the collateral type (the vault owner will effectively be the module)

        _cdpId = uint256(loanIds[_wallet][ilk]);

        if (_cdpId == 0) {

            _cdpId = cdpManager.open(ilk, address(this));

            // Mark the vault as belonging to the wallet

            loanIds[_wallet][ilk] = bytes32(_cdpId);

        }

        // Move the collateral from the wallet to the vat

        joinCollateral(_wallet, _cdpId, _collateralAmount, ilk);

        // Draw the debt and exit it to the wallet

        if (_debtAmount > 0) {

            drawAndExitDebt(_wallet, _cdpId, _debtAmount, _collateralAmount, ilk);

        }

    }



    /**

     * @notice Lets the owner of a vault add more collateral to their vault. The owner must have enough of the

     * collateral token in their wallet.

     * @param _wallet The target wallet

     * @param _cdpId The id of the vault.

     * @param _collateralAmount The amount of collateral to add to the vault.

     */

    function addCollateral(

        address _wallet,

        uint256 _cdpId,

        uint256 _collateralAmount

    )

        internal

    {

        // Move the collateral from the wallet to the vat

        joinCollateral(_wallet, _cdpId, _collateralAmount, cdpManager.ilks(_cdpId));

        // Lock the collateral

        cdpManager.frob(_cdpId, toInt(_collateralAmount), 0);

    }



    /**

     * @notice Lets the owner of a vault remove some collateral from their vault

     * @param _wallet The target wallet

     * @param _cdpId The id of the vault.

     * @param _collateralAmount The amount of collateral to remove from the vault.

     */

    function removeCollateral(

        address _wallet,

        uint256 _cdpId,

        uint256 _collateralAmount

    )

        internal

    {

        // Unlock the collateral

        cdpManager.frob(_cdpId, -toInt(_collateralAmount), 0);

        // Transfer the (internal) collateral from the cdp's urn to the module.

        cdpManager.flux(_cdpId, address(this), _collateralAmount);

        // Get the adapter for the collateral

        (JoinLike gemJoin,) = makerRegistry.getCollateral(cdpManager.ilks(_cdpId));

        // Exit the collateral from the adapter.

        gemJoin.exit(_wallet, _collateralAmount);

        // Convert WETH to ETH if needed

        if (gemJoin == wethJoin) {

            invokeWallet(_wallet, address(wethToken), 0, abi.encodeWithSignature("withdraw(uint256)", _collateralAmount));

        }

    }



    /**

     * @notice Lets the owner of a vault draw more DAI from their vault.

     * @param _wallet The target wallet

     * @param _cdpId The id of the vault.

     * @param _amount The amount of additional DAI to draw from the vault.

     */

    function addDebt(

        address _wallet,

        uint256 _cdpId,

        uint256 _amount

    )

        internal

    {

        // Draw and exit the debt to the wallet

        drawAndExitDebt(_wallet, _cdpId, _amount, 0, cdpManager.ilks(_cdpId));

    }



    /**

     * @notice Lets the owner of a vault partially repay their debt. The repayment is made up of

     * the outstanding DAI debt plus the DAI stability fee.

     * The method will use the user's DAI tokens in priority and will, if needed, convert the required

     * amount of ETH to cover for any missing DAI tokens.

     * @param _wallet The target wallet

     * @param _cdpId The id of the vault.

     * @param _amount The amount of DAI debt to repay.

     */

    function removeDebt(

        address _wallet,

        uint256 _cdpId,

        uint256 _amount

    )

        internal

    {

        verifyValidRepayment(_cdpId, _amount);

        // Move the DAI from the wallet to the vat.

        joinDebt(_wallet, _cdpId, _amount);

        // Get the accumulated rate for the collateral type

        (, uint rate,,,) = vat.ilks(cdpManager.ilks(_cdpId));

        // Repay the debt. To avoid rounding issues we reduce the repayment by one wei

        cdpManager.frob(_cdpId, 0, -toInt(_amount.sub(1).mul(RAY).div(rate)));

    }



    /**

     * @notice Lets the owner of a vault close their vault. The method will:

     * 1) repay all debt and fee

     * 2) free all collateral

     * @param _wallet The target wallet

     * @param _cdpId The id of the CDP.

     */

    function closeVault(

        address _wallet,

        uint256 _cdpId

    )

        internal

    {

        (uint256 fullRepayment,) = debt(_cdpId);

        // Repay the debt

        if (fullRepayment > 0) {

            removeDebt(_wallet, _cdpId, fullRepayment);

        }

        // Remove the collateral

        uint256 ink = collateral(_cdpId);

        if (ink > 0) {

            removeCollateral(_wallet, _cdpId, ink);

        }

    }



}

contract MakerV2Manager is MakerV2Base, MakerV2Invest, MakerV2Loan {



    // *************** Constructor ********************** //



    constructor(

        ILockStorage _lockStorage,

        ScdMcdMigrationLike _scdMcdMigration,

        PotLike _pot,

        JugLike _jug,

        IMakerRegistry _makerRegistry,

        IUniswapFactory _uniswapFactory,

        IVersionManager _versionManager

    )

        MakerV2Base(_lockStorage, _scdMcdMigration, _versionManager)

        MakerV2Invest(_pot)

        MakerV2Loan(_jug, _makerRegistry, _uniswapFactory)

        public

    {

    }



}
