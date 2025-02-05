pragma solidity 0.7.0;

interface IOwnershipTransferrable {


  function transferOwnership(address owner) external;


  event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);


}

abstract contract Ownable is IOwnershipTransferrable {


  address private _owner;





  constructor(address owner) {


    _owner = owner;


    emit OwnershipTransferred(address(0), _owner);


  }





  function owner() public view returns (address) {


    return _owner;


  }





  modifier onlyOwner() {


    require(_owner == msg.sender, "Ownable: caller is not the owner");


    _;


  }





  function transferOwnership(address newOwner) override external onlyOwner {


    require(newOwner != address(0), "Ownable: new owner is the zero address");


    emit OwnershipTransferred(_owner, newOwner);


    _owner = newOwner;


  }


}

library SafeMath {


  function add(uint256 a, uint256 b) internal pure returns (uint256) {


    uint256 c = a + b;


    require(c >= a);


    return c;


  }





  function sub(uint256 a, uint256 b) internal pure returns (uint256) {


    require(b <= a);


    uint256 c = a - b;


    return c;


  }





  function mul(uint256 a, uint256 b) internal pure returns (uint256) {


    if (a == 0) {


      return 0;


    }


    uint256 c = a * b;


    require(c / a == b);


    return c;


  }





  function div(uint256 a, uint256 b) internal pure returns (uint256) {


    require(b > 0);


    uint256 c = a / b;


    return c;


  }





  function mod(uint256 a, uint256 b) internal pure returns (uint256) {


    require(b != 0);


    return a % b;


  }


}

contract Seed is Ownable {


  using SafeMath for uint256;





  uint256 constant UINT256_MAX = ~uint256(0);





  string private _name;


  string private _symbol;


  uint8 private _decimals;





  uint256 private _totalSupply;


  mapping(address => uint256) private _balances;


  mapping(address => mapping(address => uint256)) private _allowances;





  event Transfer(address indexed from, address indexed to, uint256 value);


  event Approval(address indexed owner, address indexed spender, uint256 value);





  constructor() Ownable(msg.sender) {


    _totalSupply = 1000000 * 1e18;


    _name = "Seed";


    _symbol = "SEED";


    _decimals = 18;





    _balances[msg.sender] = _totalSupply;


    emit Transfer(address(0), msg.sender, _totalSupply);


  }





  function name() external view returns (string memory) {


    return _name;


  }





  function symbol() external view returns (string memory) {


    return _symbol;


  }





  function decimals() external view returns (uint8) {


    return _decimals;


  }





  function totalSupply() external view returns (uint256) {


    return _totalSupply;


  }





  function balanceOf(address account) external view returns (uint256) {


    return _balances[account];


  }





  function allowance(address owner, address spender) external view returns (uint256) {


    return _allowances[owner][spender];


  }





  function transfer(address recipient, uint256 amount) external returns (bool) {


    _transfer(msg.sender, recipient, amount);


    return true;


  }





  function approve(address spender, uint256 amount) external returns (bool) {


    _approve(msg.sender, spender, amount);


    return true;


  }





  function transferFrom(address sender, address recipient, uint256 amount) external returns (bool) {


    _transfer(sender, recipient, amount);


    if (_allowances[msg.sender][sender] != UINT256_MAX) {


      _approve(sender, msg.sender, _allowances[sender][msg.sender].sub(amount));


    }


    return true;


  }


  


  function _transfer(address sender, address recipient, uint256 amount) internal {


    require(sender != address(0));


    require(recipient != address(0));





    _balances[sender] = _balances[sender].sub(amount);


    _balances[recipient] = _balances[recipient].add(amount);


    emit Transfer(sender, recipient, amount);


  }


  


  function mint(address account, uint256 amount) external onlyOwner {


    _totalSupply = _totalSupply.add(amount);


    _balances[account] = _balances[account].add(amount);


    emit Transfer(address(0), account, amount);


  }  





  function increaseAllowance(address spender, uint256 addedValue) external returns (bool) {


    _approve(msg.sender, spender, _allowances[msg.sender][spender].add(addedValue));


    return true;


  }





  function decreaseAllowance(address spender, uint256 subtractedValue) external returns (bool) {


    _approve(msg.sender, spender, _allowances[msg.sender][spender].sub(subtractedValue));


    return true;


  }





  function _approve(address owner, address spender, uint256 amount) internal {


    require(owner != address(0));


    require(spender != address(0));





    _allowances[owner][spender] = amount;


    emit Approval(owner, spender, amount);


  }





  function burn(uint256 amount) external returns (bool) {


    _balances[msg.sender] = _balances[msg.sender].sub(amount);


    _totalSupply = _totalSupply.sub(amount);


    emit Transfer(msg.sender, address(0), amount);


    return true;


  }


}

abstract contract ReentrancyGuard {


  bool private _entered;





  modifier noReentrancy() {


    require(!_entered);


    _entered = true;


    _;


    _entered = false;


  }


}

interface ISeedStake is IOwnershipTransferrable {


  event StakeIncreased(address indexed staker, uint256 amount);


  event StakeDecreased(address indexed staker, uint256 amount);


  event Rewards(address indexed staker, uint256 mintage, uint256 developerFund);


  event MelodyAdded(address indexed melody);


  event MelodyRemoved(address indexed melody);





  function seed() external returns (address);


  function totalStaked() external returns (uint256);


  function staked(address staker) external returns (uint256);


  function lastClaim(address staker) external returns (uint256);





  function addMelody(address melody) external;


  function removeMelody(address melody) external;


  function upgrade(address owned, address upgraded) external;


}

contract SeedDAO is ReentrancyGuard {


  using SafeMath for uint256;





  // Proposal fee of 10 SEED. Used to prevent spam


  uint256 constant PROPOSAL_FEE = 10 * 1e18;





  event NewProposal(uint64 indexed proposal);





  event FundProposed(uint64 indexed proposal, address indexed destination, uint256 amount);


  event MelodyAdditionProposed(uint64 indexed proposal, address melody);


  event MelodyRemovalProposed(uint64 indexed proposal, address melody);


  event StakeUpgradeProposed(uint64 indexed proposal, address newStake);


  event DAOUpgradeProposed(uint64 indexed proposal, address newDAO);





  event ProposalVoteAdded(uint64 indexed proposal, address indexed staker);


  event ProposalVoteRemoved(uint64 indexed proposal, address indexed staker);





  event ProposalPassed(uint64 indexed proposal);


  event ProposalRemoved(uint64 indexed proposal);





  enum ProposalType { Null, Fund, MelodyAddition, MelodyRemoval, StakeUpgrade, DAOUpgrade }


  struct ProposalMetadata {


    ProposalType pType;


    // Allows the creator to withdraw the proposal


    address creator;


    // Used to mark proposals older than 30 days as invalid


    uint256 submitted;


    // Stakers who voted yes


    mapping(address => bool) stakers;


    // Whether or not the proposal is completed


    // Stops it from being acted on multiple times


    bool completed;


  }





  // The info string is intended for an URL to describe the proposal


  struct FundProposal {


    address destination;


    uint256 amount;


    string info;


  }





  struct MelodyAdditionProposal {


    address melody;


    string info;


  }





  struct MelodyRemovalProposal {


    address melody;


    string info;


  }





  struct StakeUpgradeProposal {


    address newStake;


    // List of addresses owned by the Stake contract


    address[] owned;


    string info;


  }





  struct DAOUpgradeProposal {


    address newDAO;


    string info;


  }





  mapping(uint64 => ProposalMetadata) public proposals;


  mapping(uint64 => mapping(address => bool)) public used;


  mapping(uint64 => FundProposal) public _fundProposals;


  mapping(uint64 => MelodyAdditionProposal) public _melodyAdditionProposals;


  mapping(uint64 => MelodyRemovalProposal) public _melodyRemovalProposals;


  mapping(uint64 => StakeUpgradeProposal) public _stakeUpgradeProposals;


  mapping(uint64 => DAOUpgradeProposal) public _daoUpgradeProposals;





  // Address of the DAO we upgraded to


  address _upgrade;


  // ID to use for the next proposal


  uint64 _nextProposalID;


  ISeedStake private _stake;


  Seed private _SEED;





  // Check the proposal is valid


  modifier pendingProposal(uint64 proposal) {


    require(proposals[proposal].pType != ProposalType.Null);


    require(!proposals[proposal].completed);


    // Don't allow old proposals to suddenly be claimed


    require(proposals[proposal].submitted + 30 days > block.timestamp);


    _;


  }





  // Check this contract hasn't been replaced


  modifier active() {


    require(_upgrade == address(0));


    _;


  }





  constructor(address stake) {


    _stake = ISeedStake(stake);


    _SEED = Seed(_stake.seed());


  }





  function upgraded() external view returns (bool) {


    return _upgrade != address(0);


  }





  function upgrade() external view returns (address) {


    return _upgrade;


  }





  function stake() external view returns (address) {


    return address(_stake);


  }





  function _createNewProposal(ProposalType pType) internal active returns (uint64) {


    // Make sure this isn't spam by transferring the proposal fee


    require(_SEED.transferFrom(msg.sender, address(this), PROPOSAL_FEE));





    // Increment the next proposal ID now


    // Means we don't have to return a value we subtract one from later


    _nextProposalID += 1;


    emit NewProposal(_nextProposalID);





    // Set up the proposal's metadata


    ProposalMetadata storage meta = proposals[_nextProposalID];


    meta.pType = pType;


    meta.creator = msg.sender;


    meta.submitted = block.timestamp;


    // Automatically vote for the proposal's creator


    meta.stakers[msg.sender] = true;


    emit ProposalVoteAdded(_nextProposalID, msg.sender);





    return _nextProposalID;


  }





  function proposeFund(address destination, uint256 amount, string calldata info) external returns (uint64) {


    uint64 proposalID = _createNewProposal(ProposalType.Fund);


    _fundProposals[proposalID] = FundProposal(destination, amount, info);


    emit FundProposed(proposalID, destination, amount);


    return proposalID;


  }





  function proposeMelodyAddition(address melody, string calldata info) external returns (uint64) {


    uint64 proposalID = _createNewProposal(ProposalType.MelodyAddition);


    _melodyAdditionProposals[proposalID] = MelodyAdditionProposal(melody, info);


    emit MelodyAdditionProposed(proposalID, melody);


    return proposalID;


  }





  function proposeMelodyRemoval(address melody, string calldata info) external returns (uint64) {


    uint64 proposalID = _createNewProposal(ProposalType.MelodyRemoval);


    _melodyRemovalProposals[proposalID] = MelodyRemovalProposal(melody, info);


    emit MelodyRemovalProposed(proposalID, melody);


    return proposalID;


  }





  function proposeStakeUpgrade(address newStake, address[] calldata owned, string calldata info) external returns (uint64) {


    uint64 proposalID = _createNewProposal(ProposalType.StakeUpgrade);





    // Ensure the SEED token was included as an owned contract


    for (uint i = 0; i < owned.length; i++) {


      if (owned[i] == address(_SEED)) {


        break;


      }


      require(i != owned.length - 1);


    }


    _stakeUpgradeProposals[proposalID] = StakeUpgradeProposal(newStake, owned, info);


    emit StakeUpgradeProposed(proposalID, newStake);


    return proposalID;


  }





  function proposeDAOUpgrade(address newDAO, string calldata info) external returns (uint64) {


    uint64 proposalID = _createNewProposal(ProposalType.DAOUpgrade);


    _daoUpgradeProposals[proposalID] = DAOUpgradeProposal(newDAO, info);


    emit DAOUpgradeProposed(proposalID, newDAO);


    return proposalID;


  }





  function addVote(uint64 proposalID) external active pendingProposal(proposalID) {


    proposals[proposalID].stakers[msg.sender] = true;


    emit ProposalVoteAdded(proposalID, msg.sender);


  }





  function removeVote(uint64 proposalID) external active pendingProposal(proposalID) {


    proposals[proposalID].stakers[msg.sender] = false;


    emit ProposalVoteRemoved(proposalID, msg.sender);


  }





  // Send the SEED held by this contract to what it upgraded to


  // Intended to enable a contract like the timelock, if transferred to this


  // Without this, it'd be trapped here, forever


  function forwardSEED() public {


    require(_upgrade != address(0));


    require(_SEED.transfer(_upgrade, _SEED.balanceOf(address(this))));


  }





  // Complete a proposal


  // Takes in a list of stakers so this contract doesn't have to track them all in an array


  // This would be extremely expensive as a stakers vote weight can drop to 0


  // This selective process allows only counting meaningful votes


  function completeProposal(uint64 proposalID, address[] calldata stakers) external active pendingProposal(proposalID) noReentrancy {


    ProposalMetadata storage meta = proposals[proposalID];





    uint256 requirement;


    // Only require a majority vote for a funding request/to remove a melody


    if ((meta.pType == ProposalType.Fund) || (meta.pType == ProposalType.MelodyRemoval)) {


      requirement = _stake.totalStaked().div(2).add(1);





    // Require >66% to add a new melody


    // Adding an insecure or malicious melody will cause the staking pool to be drained


    } else if (meta.pType == ProposalType.MelodyAddition) {


      requirement = _stake.totalStaked().div(3).mul(2).add(1);





    // Require >80% to upgrade the stake/DAO contract


    // Upgrading to an insecure or malicious contract risks unlimited minting


    } else if ((meta.pType == ProposalType.StakeUpgrade) || (meta.pType == ProposalType.DAOUpgrade)) {


      requirement = _stake.totalStaked().div(5).mul(4).add(1);





    // Panic in case the enum is expanded and not properly handled here


    } else {


      require(false);


    }





    // Make sure there's enough vote weight behind this proposal


    uint256 votes = 0;


    for (uint i = 0; i < stakers.length; i++) {


      // Don't allow people to vote with flash loans


      if (_stake.lastClaim(stakers[i]) == block.timestamp) {


        continue;


      }


      require(meta.stakers[stakers[i]]);


      require(!used[proposalID][stakers[i]]);


      used[proposalID][stakers[i]] = true;


      votes = votes.add(_stake.staked(stakers[i]));


    }


    require(votes >= requirement);


    meta.completed = true;


    emit ProposalPassed(proposalID);





    if (meta.pType == ProposalType.Fund) {


      FundProposal memory proposal = _fundProposals[proposalID];


      require(_SEED.transfer(proposal.destination, proposal.amount));





    } else if (meta.pType == ProposalType.MelodyAddition) {


      _stake.addMelody(_melodyAdditionProposals[proposalID].melody);





    } else if (meta.pType == ProposalType.MelodyRemoval) {


      _stake.removeMelody(_melodyRemovalProposals[proposalID].melody);





    } else if (meta.pType == ProposalType.StakeUpgrade) {


      StakeUpgradeProposal memory proposal = _stakeUpgradeProposals[proposalID];


      for (uint i = 0; i < proposal.owned.length; i++) {


        _stake.upgrade(proposal.owned[i], proposal.newStake);


      }





      // Register the new staking contract as a melody so it can move the funds over


      _stake.addMelody(address(proposal.newStake));





      _stake = ISeedStake(proposal.newStake);





    } else if (meta.pType == ProposalType.DAOUpgrade) {


      _upgrade = _daoUpgradeProposals[proposalID].newDAO;


      _stake.transferOwnership(_upgrade);


      forwardSEED();





    } else {


      require(false);


    }


  }





  // Voluntarily withdraw a proposal


  function withdrawProposal(uint64 proposalID) external active pendingProposal(proposalID) {


    require(proposals[proposalID].creator == msg.sender);


    proposals[proposalID].completed = true;


    emit ProposalRemoved(proposalID);


  }


}
