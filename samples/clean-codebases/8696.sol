// SPDX-License-Identifier: MIT

/**
                                  :. .                                                    
                                -==*#%*+=-.                                               
                                +=+#@*++*##%%#+=:.        .:-.                            
                                 .%*%%**+++++++*@@= .+=:  *.+%                            
                                 ++++#%#*******#=#==*+*#%#%%+-                            
                                :*=+++*%%#*#***%#@#*****###%#+...                         
                    .-+=       :#-=+++++*%@%*##[email protected]#**%#[email protected]*++##-                         
                    .=##=     .+-===++++++*#%#[email protected]#*-::=*@***+=+#+.                      
          .:+=        -+-++=.-*-====+++++++++*#*+=++----+#%*****+==##-                    
          .-*%         #..:-+*+======+++++++++++====---=+%##*******%@##-                  
            .:*%++====-*=.:::-=======+++++++++++=====--++%@#******#**==##.                
               .*+:--:--: .:::-=======+++++++++++====--++#%###********[email protected]*:..            
                 -*::::::...::-=======+++++++++++====+*##%@%%##**###****+=%%=:.           
                  .**@*-:: .:::-======++++++++=++*##%%#**##*%%%%%#*******+=%#             
                    [email protected]@@=::..::-=======+**%@@%###*++++#+#*#*#**%%##*******+=%#            
                  .  +*#@=:.::-=******#@@%#**===%====+++*===+#*#%@%##******[email protected]+           
                  *:.#[email protected]#***++====+##*+===++**#*======+===+***#*#@%%###***=#@.          
                  #=**+=-+*=========++===+**+===**======+==+++*+####@##****#**@+          
                  *+=-*##+=============**++*%=-=#*=========+*+*+*##*#@##***#*+:           
                  .%+ *@+##+=========***#@= %:==%+============++=****%%#*****+%#          
                  =**+:@++%#=======+#+- %@*[email protected]*#+=============++=+*#%#@%#*****@*          
                  *=:[email protected]@+=*=====**:   #@@@*+*+==========++=====+*##*@#*****%@.          
                  *-:-===+:.=====++:....:*#*++=++++++====*+#===+#++***@#****#@=           
                  +=:-========================+*+###*+=+**##====+++*#%@#***#@-            
                  :#:===========================#@@#**+++*%+====*****%%*#*%%=-            
                   *-=========================*%@@@#++++**+====+%####%#*%@+               
                   -*=====================+*%@@@@@#+==+++=====+*######*#%.                
                  *+=================+*#%@@@@@@@@#+==========++***%####**:                
                  ++=========++**##%@@@@@@@@@@@%*+==========+***#@%%##**+#                
   .::         .:--++-=*#%%%@@@@@@@@@@*=---=#%#++========++***#%%%@%*##**+-               
  =+-      .:+=::-#***:::-+#%@%@@*-:=-:::-+**+=========++***#%%%%+-#****++-               
 =+=     ++==#+:::#**%***###%@=:=*****##**+==========++**#%%%%#=  ******=#                
 :*+    -*+++#====###%***####%+-===================++*#%%%%%+=:   ******+                 
  :+*--=**=  -**+*%%%%%%%%#+::*-=================+*#%@@%*=.     ...=++=:                  
     .::.      .-=++: ..      %:==============++##*+=::  ..==++++++*+++=:.                
                              +=-===========+*%*:=--=.*+++#=++****#****@%+                
                               #:=========+*%*.  #==+#+++******###*****#-                 
                               -*-=======+*%:   .#*****%*****#%#*****#+                   
                                ++-======+%-     -#***#%*#**%%###**#*.                    
                                 ++-=====+%:       :=+**%##%#%%%#*=.                      
                                  =*-====+*%.         :=**@%*=-:                          
                                   .#+=====+#*-:.:-=+*++*=.                               
                                     -#*======+***++=+*#.                                 
                                       :+##*+====++*#*:                                   
                                           :-=====-:     

 * Date: March 17th, 2022
 * 
 * ☘️Happy Saint Patrick's Day!
 *
 * The Aimless Fish Dynasty is dedicated to my ever beautiful Wife, Stephanie, and our three amazing children. Hi Steph! I love you with all my heart.
 * ❤️ LHK FOREVER
 *
 * As I move on from a family business which I personally experienced as toxic to my mental health (ultimately affecting my wife and kids), I want to make all who
 * may see this aware, that Stephanie has helped me climb out of the darkness with her energy, resilience, motivation, and get-it-done attitude.
 * She has shown me strength in all areas of life, and taught me to see beyond the darkness that had surrounded me in my professional life.
 * I am forever grateful to her for this and can't express it enough. I believe everyone needs a Stephanie!
 *
 * Life is mainly about creating yourself. Who are you going to be? How will others think of you? Have you perhaps lost the plot?
 * Surround yourself with inspiring, joyful people, like my Wife, and learn from them. I think this is how you live your best life.
 *
 * Finally, within this contract I have tried to share and be as open as possible with where we are going with the Aimless Fish Dynasty project.
 * I hard coded as much as my current knowledge allowed. Where my knowledge was lacking, I tried to leave fingerprints so you could make sure things occur as they should.
 * I hope you join on me and my family on this exciting new journey!
 * This is just the beginning.
 *
 * Founded, developed, and art by: @kenleybrowne
 * 
 * AFD Dynasty  DAO: 0x4c5260637C9D39919347C961fAb0fE4CEB79bCdf
 * AFD Genesis Fund: 0x23d5041C65151E80E13380f9266EA65FA6E37a8f
 * AFD Charity Fund: 0xE88d4a2c86094197036B3D7B7e22275a3A7C0b28
 * 
 */

pragma solidity ^0.8.7;

import './ERC721Enumerable.sol';
import '@openzeppelin/contracts/access/Ownable.sol';

contract AimlessFishDynasty is ERC721Enumerable, Ownable {  
    string public AFD_PROVENANCE;    
    using Address for address;

    // This will help the starting and stopping of the sale and presale.
    bool public saleActive = false;
    bool public presaleActive = false;

    // This is the amount of tokens reserved for Free-minting, the team, giveaways, collabs and so forth.
    uint256 public reserved = 225;
    uint256 public tgcReserved = 30;

    // This is the price of each Aimless Fish Dynasty token.
    // Up to 28 Aimless Fish Dynasty tokens or 1% of all tokens may be minted at a time.
    uint256 public price = 0.035 ether;
    uint256 public freePrice = 0.0 ether;    

    // Max Supply limits the maximum supply of Aimless Fish Dynasty tokens that can exist.
    // Free Max Supply allows up to 220 free mints to the community & public.
    uint256 constant max_SUPPLY = 2750;
    uint256 constant freeMAX_SUPPLY = 255; // Up to 220 for Free Mint + 30 Reserved + 5 tokens for the Founder, his wife, and their three little kiddos.

    // This is the base link that leads to the images of the Aimless Fish tokens.
    // This will be transitioned to IPFS after minting is complete. 
    string public baseURI;
 
    // Allows us to set the provenance for the entire collection.
    function setProvenance(string memory provenance) public onlyOwner {
        AFD_PROVENANCE = provenance;
    }

    // This allows for gasless Opensea Listing.
    address public proxyRegistryAddress;  

    // The following are the addresses for withdrawals.
    address public a1_DAO = 0x4c5260637C9D39919347C961fAb0fE4CEB79bCdf; // Aimless Fish Dynasty DAO
    address public a2_OMM = 0x3097617CbA85A26AdC214A1F87B680bE4b275cD0; // OMM&S Consulting and Marketing Team
    address public a3_DTC = 0xE88d4a2c86094197036B3D7B7e22275a3A7C0b28; // The AFD Charity Fund to Be Donated
    address public a4_ADT = 0xf770C9AC6bE46FF9D02e59945Ae54030A8A92d3F; // Founder @kenleybrowne
        // Additionally, the AFD Genesis Fund:0x23d5041C65151E80E13380f9266EA65FA6E37a8f will be set to receive secondary sales royalities on OS & LR.
        // 60% of the Genesis Fund will be forwarded to the DAO, while the final 40% will be used to further the project’s growth and development.

    // This is for reserved presale tokens.
    mapping (address => uint256) public presaleReserved;

    // This makes sure if someone already did a FREE mint, then they can no longer do so. We would love if you purchased one as well :)
    mapping(address => uint256) private _claimed;

    // This allows for gasless Opensea Listing.
    mapping(address => bool) public projectProxy;

    // This allows for gas(less) future collection approval for cross-collection interaction.
    mapping(address => bool) public proxyToApproved;

    // This initializes The Aimless Fish Dynasty contract and designates the name and symbol.
    constructor (string memory _baseURI, address _proxyRegistryAddress) ERC721("Aimless Fish Dynasty", "AFD") {
        baseURI = _baseURI;
        proxyRegistryAddress = _proxyRegistryAddress;

        // Kenley, the founder is gifting his Wife & three young kiddos the first four fish, plus retaining one for his continued access to the Dynasty.
        // These will be held in the his wallet and transfered to them in the future so they may access the Dynasty.
        _safeMint( a4_ADT, 0);
        _safeMint( a4_ADT, 1);
        _safeMint( a4_ADT, 2);
        _safeMint( a4_ADT, 3);
        _safeMint( a4_ADT, 4);
    }

    // To update the tokenURI.
    // All metadata & images will be on IPFS once mint is complete.
    function setBaseURI(string memory _baseURI) public onlyOwner {
        baseURI = _baseURI;
    }

    // 
    function tokenURI(uint256 _tokenId) public view override returns (string memory) {
        require(_exists(_tokenId), "Token does not exist.");
        return string(abi.encodePacked(baseURI, Strings.toString(_tokenId)));
    }

    // This helps see which address owns which tokens.
    function tokensOfOwner(address addr) public view returns(uint256[] memory) {
        uint256 tokenCount = balanceOf(addr);
        uint256[] memory tokensId = new uint256[](tokenCount);
        for(uint256 i; i < tokenCount; i++){
            tokensId[i] = tokenOfOwnerByIndex(addr, i);
        }
        return tokensId;
    }

    // This allows for gasless Opensea Listing.
    function setProxyRegistryAddress(address _proxyRegistryAddress) external onlyOwner {
        proxyRegistryAddress = _proxyRegistryAddress;
    }

    // This allows for gas(less) future collection approval for cross-collection interaction.
    function flipProxyState(address proxyAddress) public onlyOwner {
        projectProxy[proxyAddress] = !projectProxy[proxyAddress];
    }

    // This is for the exclusive FREE-sale/Reserved presale minting ability.
    function mintPresale(uint256 _amount) public payable {
        uint256 supply = totalSupply();
        uint256 reservedAmt = presaleReserved[msg.sender];
        require( presaleActive,                      "The AFD presale isn't active yet." );
        require( reservedAmt > 0,                    "There are no tokens reserved for your address." );
        require( _amount <= reservedAmt,             "You are not able to mint more than what is reserved to you." );
        require( supply + _amount <= freeMAX_SUPPLY, "You are not able to mint more than the max supply of FREE Aimless Fish." );
        require( msg.value == freePrice * _amount,   "Opps! You sent the wrong amount of ETH." );
        presaleReserved[msg.sender] = reservedAmt - _amount;
        for(uint256 i; i < _amount; i++){
            _safeMint( msg.sender, supply + i );
        }
    }

    // This is for the Public minting ability.
    function mintToken(uint256 _amount) public payable {
        uint256 supply = totalSupply();
        require( saleActive,                     "The AFD public sale isn't active." );
        require( supply + _amount <= max_SUPPLY, "You are not able to mint more than max supply of total Aimless Fish." );
        require( _amount > 0 && _amount < 29,    "You are able to mint between 1-28 AFD tokens at the same time." );
        require( supply + _amount <= max_SUPPLY, "You are not able to mint more than max supply of total Aimless Fish." );
        require( msg.value == price * _amount,   "Opps! You sent the wrong amount of ETH." );
        for(uint256 i; i < _amount; i++){
            _safeMint( msg.sender, supply + i );
        }
    }

    // This is for the FREE minting ability during public sale.
    // Important: The fish will no longer be free when the total fish minted, including paid mints, passes 255. Don't try or you risk losing your gas!
    function mintFREEToken(uint256 _amount) public payable {
        uint256 supply = totalSupply();
        require( saleActive,                         "The AFD public sale isn't active." );
        require( _claimed[msg.sender] == 0,          "Your Free token is already claimed.");
        require( _amount > 0 && _amount < 2,         "You are able to mint one (1) Free AFD token." );
        require( supply + _amount <= freeMAX_SUPPLY, "You are not able to mint more than max supply of FREE Aimless Fish." );
        require( msg.value == freePrice * _amount,   "Opps! You sent the wrong amount of ETH." );
        for(uint256 i; i < _amount; i++){
            _claimed[msg.sender] += 1;
            _safeMint( msg.sender, supply + i );
        }
    }

    // Admin minting function to reserve tokens for the team, collabs, customs and giveaways.
    function mintReserved(uint256 _amount) public onlyOwner {
        // Limited to a publicly set amount as shown above.
        require( _amount <= tgcReserved, "You are not able to reserve more than the set amount." );
        tgcReserved -= _amount;
        uint256 supply = totalSupply();
        for(uint256 i; i < _amount; i++){
            _safeMint( msg.sender, supply + i );
        }
    }
    
    // This lets us add to and edit reserved presale spots.
    function editPresaleReserved(address[] memory _a, uint256[] memory _amount) public onlyOwner {
        for(uint256 i; i < _a.length; i++){
            presaleReserved[_a[i]] = _amount[i];
        }
    }

    // This allows us to start and stop the AFD presale.
    function setPresaleActive(bool val) public onlyOwner {
        presaleActive = val;
    }

    // This allows us to start and stop the AFD Public sale.
    function setSaleActive(bool val) public onlyOwner {
        saleActive = val;
    }

    // This allows us to set a different selling price in case ETH changes drastically.
    function setPrice(uint256 newPrice) public onlyOwner {
        price = newPrice;
    }

    // Withdraw funds from inital sales for the team, DAO, Charity and founder.
    function withdrawTeam(uint256 amount) public payable onlyOwner {
        uint256 percent = amount / 100;
        require(payable(a1_DAO).send(percent * 33)); // 33% for the community-lead Aimless Fish Dynasty DAO.
        require(payable(a2_OMM).send(percent * 25)); // 25% for the OMM&S Consulting and Marketing Team.
        require(payable(a3_DTC).send(percent * 5));  // 5% to be Distributed to Charities that support Earth and Ocean conservation.
        require(payable(a4_ADT).send(percent * 38)); // 38% to further the project’s growth & development plus initial founders dev & marketing expenses.
    }

    // Allows gasless listing on Opensea and LooksRare.
    // Sumitted during Deployment of contract OS Mainnet: 0xa5409ec958c83c3f309868babaca7c86dcb077c1
    // NOT CODED (added after contract is deployed) LooksRare Mainnet: 0xf42aa99F011A1fA7CDA90E5E98b277E306BcA83e
    // Also allows gas(less) future collection approval for cross-collection interaction including LooksRare.
    function isApprovedForAll(address _owner, address operator) public view override returns (bool) {
        OpenSeaProxyRegistry proxyRegistry = OpenSeaProxyRegistry(proxyRegistryAddress);
        if (address(proxyRegistry.proxies(_owner)) == operator || projectProxy[operator]) return true;
        return super.isApprovedForAll(_owner, operator);
    }

}

contract OwnableDelegateProxy { }
contract OpenSeaProxyRegistry {
    mapping(address => OwnableDelegateProxy) public proxies;
}
/**
*
* Wherever you happen to be in the world, together, greater collective enlightenment is what we must strive for.
* Thank you for joining me and my family on this journey.
* Let's raise each other up.
*
* Cheers,
* Kenley
* 
*/

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts v4.4.1 (access/Ownable.sol)

pragma solidity ^0.8.0;

import "../utils/Context.sol";

/**
 * @dev Contract module which provides a basic access control mechanism, where
 * there is an account (an owner) that can be granted exclusive access to
 * specific functions.
 *
 * By default, the owner account will be the one that deploys the contract. This
 * can later be changed with {transferOwnership}.
 *
 * This module is used through inheritance. It will make available the modifier
 * `onlyOwner`, which can be applied to your functions to restrict their use to
 * the owner.
 */
abstract contract Ownable is Context {
    address private _owner;

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    /**
     * @dev Initializes the contract setting the deployer as the initial owner.
     */
    constructor() {
        _transferOwnership(_msgSender());
    }

    /**
     * @dev Returns the address of the current owner.
     */
    function owner() public view virtual returns (address) {
        return _owner;
    }

    /**
     * @dev Throws if called by any account other than the owner.
     */
    modifier onlyOwner() {
        require(owner() == _msgSender(), "Ownable: caller is not the owner");
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
        _transferOwnership(address(0));
    }

    /**
     * @dev Transfers ownership of the contract to a new account (`newOwner`).
     * Can only be called by the current owner.
     */
    function transferOwnership(address newOwner) public virtual onlyOwner {
        require(newOwner != address(0), "Ownable: new owner is the zero address");
        _transferOwnership(newOwner);
    }

    /**
     * @dev Transfers ownership of the contract to a new account (`newOwner`).
     * Internal function without access restriction.
     */
    function _transferOwnership(address newOwner) internal virtual {
        address oldOwner = _owner;
        _owner = newOwner;
        emit OwnershipTransferred(oldOwner, newOwner);
    }
}

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.7;

import "./ERC721.sol";
import "@openzeppelin/contracts/token/ERC721/extensions/IERC721Enumerable.sol";

/**
 * @dev This implements an optional extension of {ERC721} defined in the EIP that adds
 * enumerability of all the token ids in the contract as well as all token ids owned by each
 * account but rips out the core of the gas-wasting processing that comes from OpenZeppelin.
 */
abstract contract ERC721Enumerable is ERC721, IERC721Enumerable {
    /**
     * @dev See {IERC165-supportsInterface}.
     */
    function supportsInterface(bytes4 interfaceId) public view virtual override(IERC165, ERC721) returns (bool) {
        return interfaceId == type(IERC721Enumerable).interfaceId || super.supportsInterface(interfaceId);
    }

    /**
     * @dev See {IERC721Enumerable-totalSupply}.
     */
    function totalSupply() public view virtual override returns (uint256) {
        return _owners.length;
    }

    /**
     * @dev See {IERC721Enumerable-tokenByIndex}.
     */
    function tokenByIndex(uint256 index) public view virtual override returns (uint256) {
        require(index < _owners.length, "ERC721Enumerable: global index out of bounds");
        return index;
    }

    /**
     * @dev See {IERC721Enumerable-tokenOfOwnerByIndex}.
     */
    function tokenOfOwnerByIndex(address owner, uint256 index) public view virtual override returns (uint256 tokenId) {
        require(index < balanceOf(owner), "ERC721Enumerable: owner index out of bounds");

        uint count;
        for(uint i; i < _owners.length; i++){
            if(owner == _owners[i]){
                if(count == index) return i;
                else count++;
            }
        }

        revert("ERC721Enumerable: owner index out of bounds");
    }
}

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v4.5.0) (token/ERC721/extensions/IERC721Enumerable.sol)

pragma solidity ^0.8.0;

import "../IERC721.sol";

/**
 * @title ERC-721 Non-Fungible Token Standard, optional enumeration extension
 * @dev See https://eips.ethereum.org/EIPS/eip-721
 */
interface IERC721Enumerable is IERC721 {
    /**
     * @dev Returns the total amount of tokens stored by the contract.
     */
    function totalSupply() external view returns (uint256);

    /**
     * @dev Returns a token ID owned by `owner` at a given `index` of its token list.
     * Use along with {balanceOf} to enumerate all of ``owner``'s tokens.
     */
    function tokenOfOwnerByIndex(address owner, uint256 index) external view returns (uint256);

    /**
     * @dev Returns a token ID at a given `index` of all the tokens stored by the contract.
     * Use along with {totalSupply} to enumerate all tokens.
     */
    function tokenByIndex(uint256 index) external view returns (uint256);
}

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.7;

import "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";
import "@openzeppelin/contracts/token/ERC721/extensions/IERC721Metadata.sol";
import "@openzeppelin/contracts/utils/Context.sol";
import "@openzeppelin/contracts/utils/Strings.sol";
import "@openzeppelin/contracts/utils/introspection/ERC165.sol";
import "./Address.sol";

abstract contract ERC721 is Context, ERC165, IERC721, IERC721Metadata {
    using Address for address;
    using Strings for uint256;
    
    string private _name;
    string private _symbol;

    // Mapping from token ID to owner address
    address[] internal _owners;

    mapping(uint256 => address) private _tokenApprovals;
    mapping(address => mapping(address => bool)) private _operatorApprovals;

    /**
     * @dev Initializes the contract by setting a `name` and a `symbol` to the token collection.
     */
    constructor(string memory name_, string memory symbol_) {
        _name = name_;
        _symbol = symbol_;
    }

    /**
     * @dev See {IERC165-supportsInterface}.
     */
    function supportsInterface(bytes4 interfaceId)
        public
        view
        virtual
        override(ERC165, IERC165)
        returns (bool)
    {
        return
            interfaceId == type(IERC721).interfaceId ||
            interfaceId == type(IERC721Metadata).interfaceId ||
            super.supportsInterface(interfaceId);
    }

    /**
     * @dev See {IERC721-balanceOf}.
     */
    function balanceOf(address owner) 
        public 
        view 
        virtual 
        override 
        returns (uint) 
    {
        require(owner != address(0), "ERC721: balance query for the zero address");

        uint count;
        for( uint i; i < _owners.length; ++i ){
          if( owner == _owners[i] )
            ++count;
        }
        return count;
    }

    /**
     * @dev See {IERC721-ownerOf}.
     */
    function ownerOf(uint256 tokenId)
        public
        view
        virtual
        override
        returns (address)
    {
        address owner = _owners[tokenId];
        require(
            owner != address(0),
            "ERC721: owner query for nonexistent token"
        );
        return owner;
    }

    /**
     * @dev See {IERC721Metadata-name}.
     */
    function name() public view virtual override returns (string memory) {
        return _name;
    }

    /**
     * @dev See {IERC721Metadata-symbol}.
     */
    function symbol() public view virtual override returns (string memory) {
        return _symbol;
    }

    /**
     * @dev See {IERC721-approve}.
     */
    function approve(address to, uint256 tokenId) public virtual override {
        address owner = ERC721.ownerOf(tokenId);
        require(to != owner, "ERC721: approval to current owner");

        require(
            _msgSender() == owner || isApprovedForAll(owner, _msgSender()),
            "ERC721: approve caller is not owner nor approved for all"
        );

        _approve(to, tokenId);
    }

    /**
     * @dev See {IERC721-getApproved}.
     */
    function getApproved(uint256 tokenId)
        public
        view
        virtual
        override
        returns (address)
    {
        require(
            _exists(tokenId),
            "ERC721: approved query for nonexistent token"
        );

        return _tokenApprovals[tokenId];
    }

    /**
     * @dev See {IERC721-setApprovalForAll}.
     */
    function setApprovalForAll(address operator, bool approved)
        public
        virtual
        override
    {
        require(operator != _msgSender(), "ERC721: approve to caller");

        _operatorApprovals[_msgSender()][operator] = approved;
        emit ApprovalForAll(_msgSender(), operator, approved);
    }

    /**
     * @dev See {IERC721-isApprovedForAll}.
     */
    function isApprovedForAll(address owner, address operator)
        public
        view
        virtual
        override
        returns (bool)
    {
        return _operatorApprovals[owner][operator];
    }

    /**
     * @dev See {IERC721-transferFrom}.
     */
    function transferFrom(
        address from,
        address to,
        uint256 tokenId
    ) public virtual override {
        //solhint-disable-next-line max-line-length
        require(
            _isApprovedOrOwner(_msgSender(), tokenId),
            "ERC721: transfer caller is not owner nor approved"
        );

        _transfer(from, to, tokenId);
    }

    /**
     * @dev See {IERC721-safeTransferFrom}.
     */
    function safeTransferFrom(
        address from,
        address to,
        uint256 tokenId
    ) public virtual override {
        safeTransferFrom(from, to, tokenId, "");
    }

    /**
     * @dev See {IERC721-safeTransferFrom}.
     */
    function safeTransferFrom(
        address from,
        address to,
        uint256 tokenId,
        bytes memory _data
    ) public virtual override {
        require(
            _isApprovedOrOwner(_msgSender(), tokenId),
            "ERC721: transfer caller is not owner nor approved"
        );
        _safeTransfer(from, to, tokenId, _data);
    }

    /**
     * @dev Safely transfers `tokenId` token from `from` to `to`, checking first that contract recipients
     * are aware of the ERC721 protocol to prevent tokens from being forever locked.
     *
     * `_data` is additional data, it has no specified format and it is sent in call to `to`.
     *
     * This internal function is equivalent to {safeTransferFrom}, and can be used to e.g.
     * implement alternative mechanisms to perform token transfer, such as signature-based.
     *
     * Requirements:
     *
     * - `from` cannot be the zero address.
     * - `to` cannot be the zero address.
     * - `tokenId` token must exist and be owned by `from`.
     * - If `to` refers to a smart contract, it must implement {IERC721Receiver-onERC721Received}, which is called upon a safe transfer.
     *
     * Emits a {Transfer} event.
     */
    function _safeTransfer(
        address from,
        address to,
        uint256 tokenId,
        bytes memory _data
    ) internal virtual {
        _transfer(from, to, tokenId);
        require(
            _checkOnERC721Received(from, to, tokenId, _data),
            "ERC721: transfer to non ERC721Receiver implementer"
        );
    }

    /**
     * @dev Returns whether `tokenId` exists.
     *
     * Tokens can be managed by their owner or approved accounts via {approve} or {setApprovalForAll}.
     *
     * Tokens start existing when they are minted (`_mint`),
     * and stop existing when they are burned (`_burn`).
     */
    function _exists(uint256 tokenId) internal view virtual returns (bool) {
        return tokenId < _owners.length && _owners[tokenId] != address(0);
    }

    /**
     * @dev Returns whether `spender` is allowed to manage `tokenId`.
     *
     * Requirements:
     *
     * - `tokenId` must exist.
     */
    function _isApprovedOrOwner(address spender, uint256 tokenId)
        internal
        view
        virtual
        returns (bool)
    {
        require(
            _exists(tokenId),
            "ERC721: operator query for nonexistent token"
        );
        address owner = ERC721.ownerOf(tokenId);
        return (spender == owner ||
            getApproved(tokenId) == spender ||
            isApprovedForAll(owner, spender));
    }

    /**
     * @dev Safely mints `tokenId` and transfers it to `to`.
     *
     * Requirements:
     *
     * - `tokenId` must not exist.
     * - If `to` refers to a smart contract, it must implement {IERC721Receiver-onERC721Received}, which is called upon a safe transfer.
     *
     * Emits a {Transfer} event.
     */
    function _safeMint(address to, uint256 tokenId) internal virtual {
        _safeMint(to, tokenId, "");
    }

    /**
     * @dev Same as {xref-ERC721-_safeMint-address-uint256-}[`_safeMint`], with an additional `data` parameter which is
     * forwarded in {IERC721Receiver-onERC721Received} to contract recipients.
     */
    function _safeMint(
        address to,
        uint256 tokenId,
        bytes memory _data
    ) internal virtual {
        _mint(to, tokenId);
        require(
            _checkOnERC721Received(address(0), to, tokenId, _data),
            "ERC721: transfer to non ERC721Receiver implementer"
        );
    }

    /**
     * @dev Mints `tokenId` and transfers it to `to`.
     *
     * WARNING: Usage of this method is discouraged, use {_safeMint} whenever possible
     *
     * Requirements:
     *
     * - `tokenId` must not exist.
     * - `to` cannot be the zero address.
     *
     * Emits a {Transfer} event.
     */
    function _mint(address to, uint256 tokenId) internal virtual {
        require(to != address(0), "ERC721: mint to the zero address");
        require(!_exists(tokenId), "ERC721: token already minted");

        _beforeTokenTransfer(address(0), to, tokenId);
        _owners.push(to);

        emit Transfer(address(0), to, tokenId);
    }

    /**
     * @dev Destroys `tokenId`.
     * The approval is cleared when the token is burned.
     *
     * Requirements:
     *
     * - `tokenId` must exist.
     *
     * Emits a {Transfer} event.
     */
    function _burn(uint256 tokenId) internal virtual {
        address owner = ERC721.ownerOf(tokenId);

        _beforeTokenTransfer(owner, address(0), tokenId);

        // Clear approvals
        _approve(address(0), tokenId);
        _owners[tokenId] = address(0);

        emit Transfer(owner, address(0), tokenId);
    }

    /**
     * @dev Transfers `tokenId` from `from` to `to`.
     *  As opposed to {transferFrom}, this imposes no restrictions on msg.sender.
     *
     * Requirements:
     *
     * - `to` cannot be the zero address.
     * - `tokenId` token must be owned by `from`.
     *
     * Emits a {Transfer} event.
     */
    function _transfer(
        address from,
        address to,
        uint256 tokenId
    ) internal virtual {
        require(
            ERC721.ownerOf(tokenId) == from,
            "ERC721: transfer of token that is not own"
        );
        require(to != address(0), "ERC721: transfer to the zero address");

        _beforeTokenTransfer(from, to, tokenId);

        // Clear approvals from the previous owner
        _approve(address(0), tokenId);
        _owners[tokenId] = to;

        emit Transfer(from, to, tokenId);
    }

    /**
     * @dev Approve `to` to operate on `tokenId`
     *
     * Emits a {Approval} event.
     */
    function _approve(address to, uint256 tokenId) internal virtual {
        _tokenApprovals[tokenId] = to;
        emit Approval(ERC721.ownerOf(tokenId), to, tokenId);
    }

    /**
     * @dev Internal function to invoke {IERC721Receiver-onERC721Received} on a target address.
     * The call is not executed if the target address is not a contract.
     *
     * @param from address representing the previous owner of the given token ID
     * @param to target address that will receive the tokens
     * @param tokenId uint256 ID of the token to be transferred
     * @param _data bytes optional data to send along with the call
     * @return bool whether the call correctly returned the expected magic value
     */
    function _checkOnERC721Received(
        address from,
        address to,
        uint256 tokenId,
        bytes memory _data
    ) private returns (bool) {
        if (to.isContract()) {
            try
                IERC721Receiver(to).onERC721Received(
                    _msgSender(),
                    from,
                    tokenId,
                    _data
                )
            returns (bytes4 retval) {
                return retval == IERC721Receiver.onERC721Received.selector;
            } catch (bytes memory reason) {
                if (reason.length == 0) {
                    revert(
                        "ERC721: transfer to non ERC721Receiver implementer"
                    );
                } else {
                    assembly {
                        revert(add(32, reason), mload(reason))
                    }
                }
            }
        } else {
            return true;
        }
    }

    /**
     * @dev Hook that is called before any token transfer. This includes minting
     * and burning.
     *
     * Calling conditions:
     *
     * - When `from` and `to` are both non-zero, ``from``'s `tokenId` will be
     * transferred to `to`.
     * - When `from` is zero, `tokenId` will be minted for `to`.
     * - When `to` is zero, ``from``'s `tokenId` will be burned.
     * - `from` and `to` are never both zero.
     *
     * To learn more about hooks, head to xref:ROOT:extending-contracts.adoc#using-hooks[Using Hooks].
     */
    function _beforeTokenTransfer(
        address from,
        address to,
        uint256 tokenId
    ) internal virtual {}
}

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts v4.4.1 (utils/Context.sol)

pragma solidity ^0.8.0;

/**
 * @dev Provides information about the current execution context, including the
 * sender of the transaction and its data. While these are generally available
 * via msg.sender and msg.data, they should not be accessed in such a direct
 * manner, since when dealing with meta-transactions the account sending and
 * paying for execution may not be the actual sender (as far as an application
 * is concerned).
 *
 * This contract is only required for intermediate, library-like contracts.
 */
abstract contract Context {
    function _msgSender() internal view virtual returns (address) {
        return msg.sender;
    }

    function _msgData() internal view virtual returns (bytes calldata) {
        return msg.data;
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.6;

library Address {
    function isContract(address account) internal view returns (bool) {
        uint size;
        assembly {
            size := extcodesize(account)
        }
        return size > 0;
    }
}

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts v4.4.1 (utils/introspection/ERC165.sol)

pragma solidity ^0.8.0;

import "./IERC165.sol";

/**
 * @dev Implementation of the {IERC165} interface.
 *
 * Contracts that want to implement ERC165 should inherit from this contract and override {supportsInterface} to check
 * for the additional interface id that will be supported. For example:
 *
 * ```solidity
 * function supportsInterface(bytes4 interfaceId) public view virtual override returns (bool) {
 *     return interfaceId == type(MyInterface).interfaceId || super.supportsInterface(interfaceId);
 * }
 * ```
 *
 * Alternatively, {ERC165Storage} provides an easier to use but more expensive implementation.
 */
abstract contract ERC165 is IERC165 {
    /**
     * @dev See {IERC165-supportsInterface}.
     */
    function supportsInterface(bytes4 interfaceId) public view virtual override returns (bool) {
        return interfaceId == type(IERC165).interfaceId;
    }
}

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts v4.4.1 (utils/Strings.sol)

pragma solidity ^0.8.0;

/**
 * @dev String operations.
 */
library Strings {
    bytes16 private constant _HEX_SYMBOLS = "0123456789abcdef";

    /**
     * @dev Converts a `uint256` to its ASCII `string` decimal representation.
     */
    function toString(uint256 value) internal pure returns (string memory) {
        // Inspired by OraclizeAPI's implementation - MIT licence
        // https://github.com/oraclize/ethereum-api/blob/b42146b063c7d6ee1358846c198246239e9360e8/oraclizeAPI_0.4.25.sol

        if (value == 0) {
            return "0";
        }
        uint256 temp = value;
        uint256 digits;
        while (temp != 0) {
            digits++;
            temp /= 10;
        }
        bytes memory buffer = new bytes(digits);
        while (value != 0) {
            digits -= 1;
            buffer[digits] = bytes1(uint8(48 + uint256(value % 10)));
            value /= 10;
        }
        return string(buffer);
    }

    /**
     * @dev Converts a `uint256` to its ASCII `string` hexadecimal representation.
     */
    function toHexString(uint256 value) internal pure returns (string memory) {
        if (value == 0) {
            return "0x00";
        }
        uint256 temp = value;
        uint256 length = 0;
        while (temp != 0) {
            length++;
            temp >>= 8;
        }
        return toHexString(value, length);
    }

    /**
     * @dev Converts a `uint256` to its ASCII `string` hexadecimal representation with fixed length.
     */
    function toHexString(uint256 value, uint256 length) internal pure returns (string memory) {
        bytes memory buffer = new bytes(2 * length + 2);
        buffer[0] = "0";
        buffer[1] = "x";
        for (uint256 i = 2 * length + 1; i > 1; --i) {
            buffer[i] = _HEX_SYMBOLS[value & 0xf];
            value >>= 4;
        }
        require(value == 0, "Strings: hex length insufficient");
        return string(buffer);
    }
}

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts v4.4.1 (token/ERC721/extensions/IERC721Metadata.sol)

pragma solidity ^0.8.0;

import "../IERC721.sol";

/**
 * @title ERC-721 Non-Fungible Token Standard, optional metadata extension
 * @dev See https://eips.ethereum.org/EIPS/eip-721
 */
interface IERC721Metadata is IERC721 {
    /**
     * @dev Returns the token collection name.
     */
    function name() external view returns (string memory);

    /**
     * @dev Returns the token collection symbol.
     */
    function symbol() external view returns (string memory);

    /**
     * @dev Returns the Uniform Resource Identifier (URI) for `tokenId` token.
     */
    function tokenURI(uint256 tokenId) external view returns (string memory);
}

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts v4.4.1 (token/ERC721/IERC721Receiver.sol)

pragma solidity ^0.8.0;

/**
 * @title ERC721 token receiver interface
 * @dev Interface for any contract that wants to support safeTransfers
 * from ERC721 asset contracts.
 */
interface IERC721Receiver {
    /**
     * @dev Whenever an {IERC721} `tokenId` token is transferred to this contract via {IERC721-safeTransferFrom}
     * by `operator` from `from`, this function is called.
     *
     * It must return its Solidity selector to confirm the token transfer.
     * If any other value is returned or the interface is not implemented by the recipient, the transfer will be reverted.
     *
     * The selector can be obtained in Solidity with `IERC721.onERC721Received.selector`.
     */
    function onERC721Received(
        address operator,
        address from,
        uint256 tokenId,
        bytes calldata data
    ) external returns (bytes4);
}

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts v4.4.1 (token/ERC721/IERC721.sol)

pragma solidity ^0.8.0;

import "../../utils/introspection/IERC165.sol";

/**
 * @dev Required interface of an ERC721 compliant contract.
 */
interface IERC721 is IERC165 {
    /**
     * @dev Emitted when `tokenId` token is transferred from `from` to `to`.
     */
    event Transfer(address indexed from, address indexed to, uint256 indexed tokenId);

    /**
     * @dev Emitted when `owner` enables `approved` to manage the `tokenId` token.
     */
    event Approval(address indexed owner, address indexed approved, uint256 indexed tokenId);

    /**
     * @dev Emitted when `owner` enables or disables (`approved`) `operator` to manage all of its assets.
     */
    event ApprovalForAll(address indexed owner, address indexed operator, bool approved);

    /**
     * @dev Returns the number of tokens in ``owner``'s account.
     */
    function balanceOf(address owner) external view returns (uint256 balance);

    /**
     * @dev Returns the owner of the `tokenId` token.
     *
     * Requirements:
     *
     * - `tokenId` must exist.
     */
    function ownerOf(uint256 tokenId) external view returns (address owner);

    /**
     * @dev Safely transfers `tokenId` token from `from` to `to`, checking first that contract recipients
     * are aware of the ERC721 protocol to prevent tokens from being forever locked.
     *
     * Requirements:
     *
     * - `from` cannot be the zero address.
     * - `to` cannot be the zero address.
     * - `tokenId` token must exist and be owned by `from`.
     * - If the caller is not `from`, it must be have been allowed to move this token by either {approve} or {setApprovalForAll}.
     * - If `to` refers to a smart contract, it must implement {IERC721Receiver-onERC721Received}, which is called upon a safe transfer.
     *
     * Emits a {Transfer} event.
     */
    function safeTransferFrom(
        address from,
        address to,
        uint256 tokenId
    ) external;

    /**
     * @dev Transfers `tokenId` token from `from` to `to`.
     *
     * WARNING: Usage of this method is discouraged, use {safeTransferFrom} whenever possible.
     *
     * Requirements:
     *
     * - `from` cannot be the zero address.
     * - `to` cannot be the zero address.
     * - `tokenId` token must be owned by `from`.
     * - If the caller is not `from`, it must be approved to move this token by either {approve} or {setApprovalForAll}.
     *
     * Emits a {Transfer} event.
     */
    function transferFrom(
        address from,
        address to,
        uint256 tokenId
    ) external;

    /**
     * @dev Gives permission to `to` to transfer `tokenId` token to another account.
     * The approval is cleared when the token is transferred.
     *
     * Only a single account can be approved at a time, so approving the zero address clears previous approvals.
     *
     * Requirements:
     *
     * - The caller must own the token or be an approved operator.
     * - `tokenId` must exist.
     *
     * Emits an {Approval} event.
     */
    function approve(address to, uint256 tokenId) external;

    /**
     * @dev Returns the account approved for `tokenId` token.
     *
     * Requirements:
     *
     * - `tokenId` must exist.
     */
    function getApproved(uint256 tokenId) external view returns (address operator);

    /**
     * @dev Approve or remove `operator` as an operator for the caller.
     * Operators can call {transferFrom} or {safeTransferFrom} for any token owned by the caller.
     *
     * Requirements:
     *
     * - The `operator` cannot be the caller.
     *
     * Emits an {ApprovalForAll} event.
     */
    function setApprovalForAll(address operator, bool _approved) external;

    /**
     * @dev Returns if the `operator` is allowed to manage all of the assets of `owner`.
     *
     * See {setApprovalForAll}
     */
    function isApprovedForAll(address owner, address operator) external view returns (bool);

    /**
     * @dev Safely transfers `tokenId` token from `from` to `to`.
     *
     * Requirements:
     *
     * - `from` cannot be the zero address.
     * - `to` cannot be the zero address.
     * - `tokenId` token must exist and be owned by `from`.
     * - If the caller is not `from`, it must be approved to move this token by either {approve} or {setApprovalForAll}.
     * - If `to` refers to a smart contract, it must implement {IERC721Receiver-onERC721Received}, which is called upon a safe transfer.
     *
     * Emits a {Transfer} event.
     */
    function safeTransferFrom(
        address from,
        address to,
        uint256 tokenId,
        bytes calldata data
    ) external;
}

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts v4.4.1 (utils/introspection/IERC165.sol)

pragma solidity ^0.8.0;

/**
 * @dev Interface of the ERC165 standard, as defined in the
 * https://eips.ethereum.org/EIPS/eip-165[EIP].
 *
 * Implementers can declare support of contract interfaces, which can then be
 * queried by others ({ERC165Checker}).
 *
 * For an implementation, see {ERC165}.
 */
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