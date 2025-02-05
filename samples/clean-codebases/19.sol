pragma solidity 0.5.0;

interface IERC20 {

    function transfer(address to, uint256 value) external returns (bool);



    function approve(address spender, uint256 value) external returns (bool);



    function transferFrom(address from, address to, uint256 value) external returns (bool);



    function totalSupply() external view returns (uint256);



    function balanceOf(address who) external view returns (uint256);



    function allowance(address owner, address spender) external view returns (uint256);



    function decimals() external view returns (uint8);



    event Transfer(address indexed from, address indexed to, uint256 value);



    event Approval(address indexed owner, address indexed spender, uint256 value);

}

contract TIERC20 {

    function transfer(address to, uint value) public;

    function transferFrom(address from, address to, uint value) public;



    function balanceOf(address who) public view returns (uint);

    function allowance(address owner, address spender) public view returns (uint256);



    function decimals() external view returns (uint8);



    event Transfer(address indexed from, address indexed to, uint256 value);

    event Approval(address indexed owner, address indexed spender, uint256 value);

}

contract MultiSigWallet {



    uint constant public MAX_OWNER_COUNT = 50;



    event Confirmation(address indexed sender, uint indexed transactionId);

    event Revocation(address indexed sender, uint indexed transactionId);

    event Submission(uint indexed transactionId);

    event Execution(uint indexed transactionId);

    event ExecutionFailure(uint indexed transactionId);

    event Deposit(address indexed sender, uint value);

    event OwnerAddition(address indexed owner);

    event OwnerRemoval(address indexed owner);

    event RequirementChange(uint required);



    mapping (uint => Transaction) public transactions;

    mapping (uint => mapping (address => bool)) public confirmations;

    mapping (address => bool) public isOwner;

    address[] public owners;

    uint public required;

    uint public transactionCount;



    struct Transaction {

        address destination;

        uint value;

        bytes data;

        bool executed;

    }



    modifier onlyWallet() {

        if (msg.sender != address(this))

            revert("Unauthorized.");

        _;

    }



    modifier ownerDoesNotExist(address owner) {

        if (isOwner[owner])

            revert("Unauthorized.");

        _;

    }



    modifier ownerExists(address owner) {

        if (!isOwner[owner])

            revert("Unauthorized.");

        _;

    }



    modifier transactionExists(uint transactionId) {

        if (transactions[transactionId].destination == address(0))

            revert("Existed transaction id.");

        _;

    }



    modifier confirmed(uint transactionId, address owner) {

        if (!confirmations[transactionId][owner])

            revert("Not confirmed transaction.");

        _;

    }



    modifier notConfirmed(uint transactionId, address owner) {

        if (confirmations[transactionId][owner])

            revert("Confirmed transaction.");

        _;

    }



    modifier notExecuted(uint transactionId) {

        if (transactions[transactionId].executed)

            revert("Executed transaction.");

        _;

    }



    modifier notNull(address _address) {

        if (_address == address(0))

            revert("Address is null");

        _;

    }



    modifier validRequirement(uint ownerCount, uint _required) {

        if (   ownerCount > MAX_OWNER_COUNT

            || _required > ownerCount

            || _required == 0

            || ownerCount == 0)

            revert("Invalid requirement");

        _;

    }



    /// @dev Fallback function allows to deposit ether.

    function()

        external

        payable

    {

        if (msg.value > 0)

            emit Deposit(msg.sender, msg.value);

    }



    /*

     * Public functions

     */

    /// @dev Contract constructor sets initial owners and required number of confirmations.

    /// @param _owners List of initial owners.

    /// @param _required Number of required confirmations.

    constructor(address[] memory _owners, uint _required)

        public

        validRequirement(_owners.length, _required)

    {

        for (uint i=0; i<_owners.length; i++) {

            if (isOwner[_owners[i]] || _owners[i] == address(0))

                revert("Invalid owner");

            isOwner[_owners[i]] = true;

        }

        owners = _owners;

        required = _required;

    }



    /// @dev Allows to add a new owner. Transaction has to be sent by wallet.

    /// @param owner Address of new owner.

    function addOwner(address owner)

        public

        onlyWallet

        ownerDoesNotExist(owner)

        notNull(owner)

        validRequirement(owners.length + 1, required)

    {

        isOwner[owner] = true;

        owners.push(owner);

        emit OwnerAddition(owner);

    }



    /// @dev Allows to remove an owner. Transaction has to be sent by wallet.

    /// @param owner Address of owner.

    function removeOwner(address owner)

        public

        onlyWallet

        ownerExists(owner)

    {

        isOwner[owner] = false;

        for (uint i=0; i<owners.length - 1; i++)

            if (owners[i] == owner) {

                owners[i] = owners[owners.length - 1];

                break;

            }

        owners.length -= 1;

        if (required > owners.length)

            changeRequirement(owners.length);

        emit OwnerRemoval(owner);

    }



    /// @dev Allows to replace an owner with a new owner. Transaction has to be sent by wallet.

    /// @param owner Address of owner to be replaced.

    /// @param owner Address of new owner.

    function replaceOwner(address owner, address newOwner)

        public

        onlyWallet

        ownerExists(owner)

        ownerDoesNotExist(newOwner)

    {

        for (uint i=0; i<owners.length; i++)

            if (owners[i] == owner) {

                owners[i] = newOwner;

                break;

            }

        isOwner[owner] = false;

        isOwner[newOwner] = true;

        emit OwnerRemoval(owner);

        emit OwnerAddition(newOwner);

    }



    /// @dev Allows to change the number of required confirmations. Transaction has to be sent by wallet.

    /// @param _required Number of required confirmations.

    function changeRequirement(uint _required)

        public

        onlyWallet

        validRequirement(owners.length, _required)

    {

        required = _required;

        emit RequirementChange(_required);

    }



    /// @dev Allows an owner to submit and confirm a transaction.

    /// @param destination Transaction target address.

    /// @param value Transaction ether value.

    /// @param data Transaction data payload.

    /// @return Returns transaction ID.

    function submitTransaction(address destination, uint value, bytes memory data)

        public

        returns (uint transactionId)

    {

        transactionId = addTransaction(destination, value, data);

        confirmTransaction(transactionId);

    }



    /// @dev Allows an owner to confirm a transaction.

    /// @param transactionId Transaction ID.

    function confirmTransaction(uint transactionId)

        public

        ownerExists(msg.sender)

        transactionExists(transactionId)

        notConfirmed(transactionId, msg.sender)

    {

        confirmations[transactionId][msg.sender] = true;

        emit Confirmation(msg.sender, transactionId);

        executeTransaction(transactionId);

    }



    /// @dev Allows an owner to revoke a confirmation for a transaction.

    /// @param transactionId Transaction ID.

    function revokeConfirmation(uint transactionId)

        public

        ownerExists(msg.sender)

        confirmed(transactionId, msg.sender)

        notExecuted(transactionId)

    {

        confirmations[transactionId][msg.sender] = false;

        emit Revocation(msg.sender, transactionId);

    }



    /// @dev Allows anyone to execute a confirmed transaction.

    /// @param transactionId Transaction ID.

    function executeTransaction(uint transactionId)

        public

        notExecuted(transactionId)

    {

        if (isConfirmed(transactionId)) {

            Transaction storage txn = transactions[transactionId];

            txn.executed = true;

            (bool result, ) = txn.destination.call.value(txn.value)(txn.data);

            if (result)

                emit Execution(transactionId);

            else {

                emit ExecutionFailure(transactionId);

                txn.executed = false;

            }

        }

    }



    /// @dev Returns the confirmation status of a transaction.

    /// @param transactionId Transaction ID.

    /// @return Confirmation status.

    function isConfirmed(uint transactionId)

        public

        view

        returns (bool)

    {

        uint count = 0;

        for (uint i=0; i<owners.length; i++) {

            if (confirmations[transactionId][owners[i]])

                count += 1;

            if (count == required)

                return true;

        }

    }



    /*

     * Internal functions

     */

    /// @dev Adds a new transaction to the transaction mapping, if transaction does not exist yet.

    /// @param destination Transaction target address.

    /// @param value Transaction ether value.

    /// @param data Transaction data payload.

    /// @return Returns transaction ID.

    function addTransaction(address destination, uint value, bytes memory data)

        public

        notNull(destination)

        returns (uint transactionId)

    {

        transactionId = transactionCount;

        transactions[transactionId] = Transaction({

            destination: destination,

            value: value,

            data: data,

            executed: false

        });

        transactionCount += 1;

        emit Submission(transactionId);

    }



    /*

     * Web3 call functions

     */

    /// @dev Returns number of confirmations of a transaction.

    /// @param transactionId Transaction ID.

    /// @return Number of confirmations.

    function getConfirmationCount(uint transactionId)

        public

        view

        returns (uint count)

    {

        for (uint i=0; i<owners.length; i++)

            if (confirmations[transactionId][owners[i]])

                count += 1;

    }



    /// @dev Returns total number of transactions after filers are applied.

    /// @param pending Include pending transactions.

    /// @param executed Include executed transactions.

    /// @return Total number of transactions after filters are applied.

    function getTransactionCount(bool pending, bool executed)

        public

        view

        returns (uint count)

    {

        for (uint i=0; i<transactionCount; i++)

            if (   pending && !transactions[i].executed

                || executed && transactions[i].executed)

                count += 1;

    }



    /// @dev Returns list of owners.

    /// @return List of owner addresses.

    function getOwners()

        public

        view

        returns (address[] memory)

    {

        return owners;

    }



    /// @dev Returns array with owner addresses, which confirmed transaction.

    /// @param transactionId Transaction ID.

    /// @return Returns array of owner addresses.

    function getConfirmations(uint transactionId)

        public

        view

        returns (address[] memory _confirmations)

    {

        address[] memory confirmationsTemp = new address[](owners.length);

        uint count = 0;

        uint i;

        for (i=0; i<owners.length; i++)

            if (confirmations[transactionId][owners[i]]) {

                confirmationsTemp[count] = owners[i];

                count += 1;

            }

        _confirmations = new address[](count);

        for (i=0; i<count; i++)

            _confirmations[i] = confirmationsTemp[i];

    }



    /// @dev Returns list of transaction IDs in defined range.

    /// @param from Index start position of transaction array.

    /// @param to Index end position of transaction array.

    /// @param pending Include pending transactions.

    /// @param executed Include executed transactions.

    /// @return Returns array of transaction IDs.

    function getTransactionIds(uint from, uint to, bool pending, bool executed)

        public

        view

        returns (uint[] memory _transactionIds)

    {

        uint[] memory transactionIdsTemp = new uint[](transactionCount);

        uint count = 0;

        uint i;

        for (i=0; i<transactionCount; i++)

            if (   pending && !transactions[i].executed

                || executed && transactions[i].executed)

            {

                transactionIdsTemp[count] = i;

                count += 1;

            }

        _transactionIds = new uint[](to - from);

        for (i=from; i<to; i++)

            _transactionIds[i - from] = transactionIdsTemp[i];

    }

}

contract SafeMath {

    function safeMul(uint a, uint b) internal pure returns(uint) {

        uint c = a * b;

        assertion(a == 0 || c / a == b);

        return c;

    }



    function safeSub(uint a, uint b) internal pure returns(uint) {

        assertion(b <= a);

        return a - b;

    }



    function safeAdd(uint a, uint b) internal pure returns(uint) {

        uint c = a + b;

        assertion(c >= a && c >= b);

        return c;

    }



    function safeDiv(uint a, uint b) internal pure returns(uint) {

        require(b != 0, 'Divide by zero');



        return a / b;

    }



    function safeCeil(uint a, uint b) internal pure returns (uint) {

        require(b > 0);



        uint v = a / b;



        if(v * b == a) return v;



        return v + 1;  // b cannot be 1, so v <= a / 2

    }



    function assertion(bool flag) internal pure {

        if (!flag) revert('Assertion fail.');

    }

}

contract EthVault is MultiSigWallet{

    string public constant chain = "ETH";



    bool public isActivated = true;



    address payable public implementation;

    address public tetherAddress;



    uint public depositCount = 0;



    mapping(bytes32 => bool) public isUsedWithdrawal;



    mapping(bytes32 => address) public tokenAddr;

    mapping(address => bytes32) public tokenSummaries;



    mapping(bytes32 => bool) public isValidChain;



    constructor(address[] memory _owners, uint _required, address payable _implementation, address _tetherAddress) MultiSigWallet(_owners, _required) public {

        implementation = _implementation;

        tetherAddress = _tetherAddress;



        // klaytn valid chain default setting

        isValidChain[sha256(abi.encodePacked(address(this), "KLAYTN"))] = true;

    }



    function _setImplementation(address payable _newImp) public onlyWallet {

        require(implementation != _newImp);

        implementation = _newImp;



    }



    function () payable external {

        address impl = implementation;

        require(impl != address(0));

        assembly {

            let ptr := mload(0x40)

            calldatacopy(ptr, 0, calldatasize)

            let result := delegatecall(gas, impl, ptr, calldatasize, 0, 0)

            let size := returndatasize

            returndatacopy(ptr, 0, size)



            switch result

            case 0 { revert(ptr, size) }

            default { return(ptr, size) }

        }

    }

}

contract EthVaultImpl is EthVault, SafeMath{

    event Deposit(string fromChain, string toChain, address fromAddr, bytes toAddr, address token, uint8 decimal, uint amount, uint depositId, uint block);

    event Withdraw(address hubContract, string fromChain, string toChain, bytes fromAddr, bytes toAddr, bytes token, bytes32[] bytes32s, uint[] uints);



    modifier onlyActivated {

        require(isActivated);

        _;

    }



    constructor(address[] memory _owner) public EthVault(_owner, _owner.length, address(0), address(0)) {

    }



    function getVersion() public pure returns(string memory){

        return "1028";

    }



    function changeActivate(bool activate) public onlyWallet {

        isActivated = activate;

    }



    function setTetherAddress(address tether) public onlyWallet {

        tetherAddress = tether;

    }



    function getChainId(string memory _chain) public view returns(bytes32){

        return sha256(abi.encodePacked(address(this), _chain));

    }



    function setValidChain(string memory _chain, bool valid) public onlyWallet {

        isValidChain[getChainId(_chain)] = valid;

    }



    function deposit(string memory toChain, bytes memory toAddr) payable public onlyActivated {

        require(isValidChain[getChainId(toChain)]);

        require(msg.value > 0);



        depositCount = depositCount + 1;

        emit Deposit(chain, toChain, msg.sender, toAddr, address(0), 18, msg.value, depositCount, block.number);

    }



    function depositToken(address token, string memory toChain, bytes memory toAddr, uint amount) public onlyActivated{

        require(isValidChain[getChainId(toChain)]);

        require(token != address(0));

        require(amount > 0);



        uint8 decimal = 0;

        if(token == tetherAddress){

            TIERC20(token).transferFrom(msg.sender, address(this), amount);

            decimal = TIERC20(token).decimals();

        }else{

            if(!IERC20(token).transferFrom(msg.sender, address(this), amount)) revert();

            decimal = IERC20(token).decimals();

        }

        

        require(decimal > 0);



        depositCount = depositCount + 1;

        emit Deposit(chain, toChain, msg.sender, toAddr, token, decimal, amount, depositCount, block.number);

    }



    // Fix Data Info

    ///@param bytes32s [0]:govId, [1]:txHash

    ///@param uints [0]:amount, [1]:decimals

    function withdraw(

        address hubContract,

        string memory fromChain,

        bytes memory fromAddr,

        bytes memory toAddr,

        bytes memory token,

        bytes32[] memory bytes32s,

        uint[] memory uints,

        uint8[] memory v,

        bytes32[] memory r,

        bytes32[] memory s

    ) public onlyActivated {

        require(bytes32s.length >= 1);

        require(bytes32s[0] == sha256(abi.encodePacked(hubContract, chain, address(this))));

        require(uints.length >= 2);

        require(isValidChain[getChainId(fromChain)]);



        bytes32 whash = sha256(abi.encodePacked(hubContract, fromChain, chain, fromAddr, toAddr, token, bytes32s, uints));



        require(!isUsedWithdrawal[whash]);

        isUsedWithdrawal[whash] = true;



        uint validatorCount = _validate(whash, v, r, s);

        require(validatorCount >= required);



        address payable _toAddr = bytesToAddress(toAddr);

        address tokenAddress = bytesToAddress(token);

        if(tokenAddress == address(0)){

            if(!_toAddr.send(uints[0])) revert();

        }else{

            if(tokenAddress == tetherAddress){

                TIERC20(tokenAddress).transfer(_toAddr, uints[0]);

            }

            else{

                if(!IERC20(tokenAddress).transfer(_toAddr, uints[0])) revert();

            }

        }



        emit Withdraw(hubContract, fromChain, chain, fromAddr, toAddr, token, bytes32s, uints);

    }



    function _validate(bytes32 whash, uint8[] memory v, bytes32[] memory r, bytes32[] memory s) private view returns(uint){

        uint validatorCount = 0;

        address[] memory vaList = new address[](owners.length);



        uint i=0;

        uint j=0;



        for(i; i<v.length; i++){

            address va = ecrecover(whash,v[i],r[i],s[i]);

            if(isOwner[va]){

                for(j=0; j<validatorCount; j++){

                    require(vaList[j] != va);

                }



                vaList[validatorCount] = va;

                validatorCount += 1;

            }

        }



        return validatorCount;

    }



    function bytesToAddress(bytes memory bys) private pure returns (address payable addr) {

        assembly {

            addr := mload(add(bys,20))

        }

    }



    function () payable external{

    }

}
