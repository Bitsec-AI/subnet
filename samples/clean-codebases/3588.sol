/**
 *Submitted for verification at Etherscan.io on 2021-10-20
*/

// File: GenesisRocks10000_flat.sol


// File: base64-sol/base64.sol



pragma solidity >=0.6.0;

/// @title Base64
/// @author Brecht Devos - <[email protected]>
/// @notice Provides functions for encoding/decoding base64
library Base64 {
    string internal constant TABLE_ENCODE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    bytes  internal constant TABLE_DECODE = hex"0000000000000000000000000000000000000000000000000000000000000000"
                                            hex"00000000000000000000003e0000003f3435363738393a3b3c3d000000000000"
                                            hex"00000102030405060708090a0b0c0d0e0f101112131415161718190000000000"
                                            hex"001a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132330000000000";

    function encode(bytes memory data) internal pure returns (string memory) {
        if (data.length == 0) return '';

        // load the table into memory
        string memory table = TABLE_ENCODE;

        // multiply by 4/3 rounded up
        uint256 encodedLen = 4 * ((data.length + 2) / 3);

        // add some extra buffer at the end required for the writing
        string memory result = new string(encodedLen + 32);

        assembly {
            // set the actual output length
            mstore(result, encodedLen)

            // prepare the lookup table
            let tablePtr := add(table, 1)

            // input ptr
            let dataPtr := data
            let endPtr := add(dataPtr, mload(data))

            // result ptr, jump over length
            let resultPtr := add(result, 32)

            // run over the input, 3 bytes at a time
            for {} lt(dataPtr, endPtr) {}
            {
                // read 3 bytes
                dataPtr := add(dataPtr, 3)
                let input := mload(dataPtr)

                // write 4 characters
                mstore8(resultPtr, mload(add(tablePtr, and(shr(18, input), 0x3F))))
                resultPtr := add(resultPtr, 1)
                mstore8(resultPtr, mload(add(tablePtr, and(shr(12, input), 0x3F))))
                resultPtr := add(resultPtr, 1)
                mstore8(resultPtr, mload(add(tablePtr, and(shr( 6, input), 0x3F))))
                resultPtr := add(resultPtr, 1)
                mstore8(resultPtr, mload(add(tablePtr, and(        input,  0x3F))))
                resultPtr := add(resultPtr, 1)
            }

            // padding with '='
            switch mod(mload(data), 3)
            case 1 { mstore(sub(resultPtr, 2), shl(240, 0x3d3d)) }
            case 2 { mstore(sub(resultPtr, 1), shl(248, 0x3d)) }
        }

        return result;
    }

    function decode(string memory _data) internal pure returns (bytes memory) {
        bytes memory data = bytes(_data);

        if (data.length == 0) return new bytes(0);
        require(data.length % 4 == 0, "invalid base64 decoder input");

        // load the table into memory
        bytes memory table = TABLE_DECODE;

        // every 4 characters represent 3 bytes
        uint256 decodedLen = (data.length / 4) * 3;

        // add some extra buffer at the end required for the writing
        bytes memory result = new bytes(decodedLen + 32);

        assembly {
            // padding with '='
            let lastBytes := mload(add(data, mload(data)))
            if eq(and(lastBytes, 0xFF), 0x3d) {
                decodedLen := sub(decodedLen, 1)
                if eq(and(lastBytes, 0xFFFF), 0x3d3d) {
                    decodedLen := sub(decodedLen, 1)
                }
            }

            // set the actual output length
            mstore(result, decodedLen)

            // prepare the lookup table
            let tablePtr := add(table, 1)

            // input ptr
            let dataPtr := data
            let endPtr := add(dataPtr, mload(data))

            // result ptr, jump over length
            let resultPtr := add(result, 32)

            // run over the input, 4 characters at a time
            for {} lt(dataPtr, endPtr) {}
            {
               // read 4 characters
               dataPtr := add(dataPtr, 4)
               let input := mload(dataPtr)

               // write 3 bytes
               let output := add(
                   add(
                       shl(18, and(mload(add(tablePtr, and(shr(24, input), 0xFF))), 0xFF)),
                       shl(12, and(mload(add(tablePtr, and(shr(16, input), 0xFF))), 0xFF))),
                   add(
                       shl( 6, and(mload(add(tablePtr, and(shr( 8, input), 0xFF))), 0xFF)),
                               and(mload(add(tablePtr, and(        input , 0xFF))), 0xFF)
                    )
                )
                mstore(resultPtr, shl(232, output))
                resultPtr := add(resultPtr, 3)
            }
        }

        return result;
    }
}

// File: @openzeppelin/contracts/utils/Strings.sol



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

// File: @openzeppelin/contracts/utils/Context.sol



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

// File: @openzeppelin/contracts/access/Ownable.sol



pragma solidity ^0.8.0;


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
        _setOwner(_msgSender());
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
        _setOwner(address(0));
    }

    /**
     * @dev Transfers ownership of the contract to a new account (`newOwner`).
     * Can only be called by the current owner.
     */
    function transferOwnership(address newOwner) public virtual onlyOwner {
        require(newOwner != address(0), "Ownable: new owner is the zero address");
        _setOwner(newOwner);
    }

    function _setOwner(address newOwner) private {
        address oldOwner = _owner;
        _owner = newOwner;
        emit OwnershipTransferred(oldOwner, newOwner);
    }
}

// File: @openzeppelin/contracts/utils/Address.sol



pragma solidity ^0.8.0;

/**
 * @dev Collection of functions related to the address type
 */
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
        // This method relies on extcodesize, which returns 0 for contracts in
        // construction, since the code is only stored at the end of the
        // constructor execution.

        uint256 size;
        assembly {
            size := extcodesize(account)
        }
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

        (bool success, ) = recipient.call{value: amount}("");
        require(success, "Address: unable to send value, recipient may have reverted");
    }

    /**
     * @dev Performs a Solidity function call using a low level `call`. A
     * plain `call` is an unsafe replacement for a function call: use this
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
    function functionCall(
        address target,
        bytes memory data,
        string memory errorMessage
    ) internal returns (bytes memory) {
        return functionCallWithValue(target, data, 0, errorMessage);
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
    function functionCallWithValue(
        address target,
        bytes memory data,
        uint256 value
    ) internal returns (bytes memory) {
        return functionCallWithValue(target, data, value, "Address: low-level call with value failed");
    }

    /**
     * @dev Same as {xref-Address-functionCallWithValue-address-bytes-uint256-}[`functionCallWithValue`], but
     * with `errorMessage` as a fallback revert reason when `target` reverts.
     *
     * _Available since v3.1._
     */
    function functionCallWithValue(
        address target,
        bytes memory data,
        uint256 value,
        string memory errorMessage
    ) internal returns (bytes memory) {
        require(address(this).balance >= value, "Address: insufficient balance for call");
        require(isContract(target), "Address: call to non-contract");

        (bool success, bytes memory returndata) = target.call{value: value}(data);
        return verifyCallResult(success, returndata, errorMessage);
    }

    /**
     * @dev Same as {xref-Address-functionCall-address-bytes-}[`functionCall`],
     * but performing a static call.
     *
     * _Available since v3.3._
     */
    function functionStaticCall(address target, bytes memory data) internal view returns (bytes memory) {
        return functionStaticCall(target, data, "Address: low-level static call failed");
    }

    /**
     * @dev Same as {xref-Address-functionCall-address-bytes-string-}[`functionCall`],
     * but performing a static call.
     *
     * _Available since v3.3._
     */
    function functionStaticCall(
        address target,
        bytes memory data,
        string memory errorMessage
    ) internal view returns (bytes memory) {
        require(isContract(target), "Address: static call to non-contract");

        (bool success, bytes memory returndata) = target.staticcall(data);
        return verifyCallResult(success, returndata, errorMessage);
    }

    /**
     * @dev Same as {xref-Address-functionCall-address-bytes-}[`functionCall`],
     * but performing a delegate call.
     *
     * _Available since v3.4._
     */
    function functionDelegateCall(address target, bytes memory data) internal returns (bytes memory) {
        return functionDelegateCall(target, data, "Address: low-level delegate call failed");
    }

    /**
     * @dev Same as {xref-Address-functionCall-address-bytes-string-}[`functionCall`],
     * but performing a delegate call.
     *
     * _Available since v3.4._
     */
    function functionDelegateCall(
        address target,
        bytes memory data,
        string memory errorMessage
    ) internal returns (bytes memory) {
        require(isContract(target), "Address: delegate call to non-contract");

        (bool success, bytes memory returndata) = target.delegatecall(data);
        return verifyCallResult(success, returndata, errorMessage);
    }

    /**
     * @dev Tool to verifies that a low level call was successful, and revert if it wasn't, either by bubbling the
     * revert reason using the provided one.
     *
     * _Available since v4.3._
     */
    function verifyCallResult(
        bool success,
        bytes memory returndata,
        string memory errorMessage
    ) internal pure returns (bytes memory) {
        if (success) {
            return returndata;
        } else {
            // Look for revert reason and bubble it up if present
            if (returndata.length > 0) {
                // The easiest way to bubble the revert reason is using memory via assembly

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

// File: @openzeppelin/contracts/token/ERC721/IERC721Receiver.sol



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

// File: @openzeppelin/contracts/utils/introspection/IERC165.sol



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

// File: @openzeppelin/contracts/utils/introspection/ERC165.sol



pragma solidity ^0.8.0;


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

// File: @openzeppelin/contracts/token/ERC721/IERC721.sol



pragma solidity ^0.8.0;


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

// File: @openzeppelin/contracts/token/ERC721/extensions/IERC721Metadata.sol



pragma solidity ^0.8.0;


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

// File: @openzeppelin/contracts/token/ERC721/ERC721.sol



pragma solidity ^0.8.0;








/**
 * @dev Implementation of https://eips.ethereum.org/EIPS/eip-721[ERC721] Non-Fungible Token Standard, including
 * the Metadata extension, but not including the Enumerable extension, which is available separately as
 * {ERC721Enumerable}.
 */
contract ERC721 is Context, ERC165, IERC721, IERC721Metadata {
    using Address for address;
    using Strings for uint256;

    // Token name
    string private _name;

    // Token symbol
    string private _symbol;

    // Mapping from token ID to owner address
    mapping(uint256 => address) private _owners;

    // Mapping owner address to token count
    mapping(address => uint256) private _balances;

    // Mapping from token ID to approved address
    mapping(uint256 => address) private _tokenApprovals;

    // Mapping from owner to operator approvals
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
    function supportsInterface(bytes4 interfaceId) public view virtual override(ERC165, IERC165) returns (bool) {
        return
            interfaceId == type(IERC721).interfaceId ||
            interfaceId == type(IERC721Metadata).interfaceId ||
            super.supportsInterface(interfaceId);
    }

    /**
     * @dev See {IERC721-balanceOf}.
     */
    function balanceOf(address owner) public view virtual override returns (uint256) {
        require(owner != address(0), "ERC721: balance query for the zero address");
        return _balances[owner];
    }

    /**
     * @dev See {IERC721-ownerOf}.
     */
    function ownerOf(uint256 tokenId) public view virtual override returns (address) {
        address owner = _owners[tokenId];
        require(owner != address(0), "ERC721: owner query for nonexistent token");
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
     * @dev See {IERC721Metadata-tokenURI}.
     */
    function tokenURI(uint256 tokenId) public view virtual override returns (string memory) {
        require(_exists(tokenId), "ERC721Metadata: URI query for nonexistent token");

        string memory baseURI = _baseURI();
        return bytes(baseURI).length > 0 ? string(abi.encodePacked(baseURI, tokenId.toString())) : "";
    }

    /**
     * @dev Base URI for computing {tokenURI}. If set, the resulting URI for each
     * token will be the concatenation of the `baseURI` and the `tokenId`. Empty
     * by default, can be overriden in child contracts.
     */
    function _baseURI() internal view virtual returns (string memory) {
        return "";
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
    function getApproved(uint256 tokenId) public view virtual override returns (address) {
        require(_exists(tokenId), "ERC721: approved query for nonexistent token");

        return _tokenApprovals[tokenId];
    }

    /**
     * @dev See {IERC721-setApprovalForAll}.
     */
    function setApprovalForAll(address operator, bool approved) public virtual override {
        require(operator != _msgSender(), "ERC721: approve to caller");

        _operatorApprovals[_msgSender()][operator] = approved;
        emit ApprovalForAll(_msgSender(), operator, approved);
    }

    /**
     * @dev See {IERC721-isApprovedForAll}.
     */
    function isApprovedForAll(address owner, address operator) public view virtual override returns (bool) {
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
        require(_isApprovedOrOwner(_msgSender(), tokenId), "ERC721: transfer caller is not owner nor approved");

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
        require(_isApprovedOrOwner(_msgSender(), tokenId), "ERC721: transfer caller is not owner nor approved");
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
        require(_checkOnERC721Received(from, to, tokenId, _data), "ERC721: transfer to non ERC721Receiver implementer");
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
        return _owners[tokenId] != address(0);
    }

    /**
     * @dev Returns whether `spender` is allowed to manage `tokenId`.
     *
     * Requirements:
     *
     * - `tokenId` must exist.
     */
    function _isApprovedOrOwner(address spender, uint256 tokenId) internal view virtual returns (bool) {
        require(_exists(tokenId), "ERC721: operator query for nonexistent token");
        address owner = ERC721.ownerOf(tokenId);
        return (spender == owner || getApproved(tokenId) == spender || isApprovedForAll(owner, spender));
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

        _balances[to] += 1;
        _owners[tokenId] = to;

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

        _balances[owner] -= 1;
        delete _owners[tokenId];

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
        require(ERC721.ownerOf(tokenId) == from, "ERC721: transfer of token that is not own");
        require(to != address(0), "ERC721: transfer to the zero address");

        _beforeTokenTransfer(from, to, tokenId);

        // Clear approvals from the previous owner
        _approve(address(0), tokenId);

        _balances[from] -= 1;
        _balances[to] += 1;
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
            try IERC721Receiver(to).onERC721Received(_msgSender(), from, tokenId, _data) returns (bytes4 retval) {
                return retval == IERC721Receiver.onERC721Received.selector;
            } catch (bytes memory reason) {
                if (reason.length == 0) {
                    revert("ERC721: transfer to non ERC721Receiver implementer");
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

// File: GenesisRocks10000.sol



pragma solidity ^0.8.0;






interface EtherRock {
  function sellRock (uint rockNumber, uint price) external;
  function giftRock (uint rockNumber, address receiver) external;
}

contract RockWarden is Ownable {
  function claim(uint256 id, EtherRock rocks) public onlyOwner {
    rocks.sellRock(id, type(uint256).max);
    rocks.giftRock(id, owner());
  }
  
  function withdraw(uint256 id, EtherRock rocks, address recipient) public onlyOwner {
    rocks.giftRock(id, recipient);
  }
}

contract GenesisRocks10000 is ERC721, Ownable {
  EtherRock public rocks = EtherRock(0x37504AE0282f5f334ED29b4548646f887977b7cC);

  using Address for address;
  using Strings for uint256;

  string private _baseTokenURI;
  uint256 private _totalSupply;

  mapping(address => address) public wardens;
  
  string[] hashes = [
    "bafybeibkx5swmemvqkc6n3umzuaplcssrq6bp2uyh3n2vhdywzv6lszv3q/0.png",
    "bafybeid6g2ue77ioxviruwhbz77nz7fyyomf7c24c2ya7i725uto7plpxe/1.png",
    "bafybeigwsvacvsu7puct5p2wyenietreui6yealsshmc4w3cnlx2vtwgai/2.png",
    "bafybeihaszjogt4ksjzcx5abvqsfcxc4ow35nb33idqrzelbwget7sxtzi/3.png",
    "bafybeicll7pdbhxfsnejqjgsgjfspnxpv5g6rmkqrkty7mnfbgztlhnnxe/4.png",
    "bafybeiazo5mjnq5ot6l3msgbrwsqo3qc43czdzyc7goe4vxjlk4ciwan34/5.png",
    "bafybeie62no5b4pwobhcs2ritotdf2baiiw65sjraxyeabxr4ewtqu5534/6.png",
    "bafybeibrtcuqfuredutyvezpx4jixl34zps5tx54j4x23b56bhre4l4bmq/7.png",
    "bafybeihjtbnrkbsks4xjqyqniginmhxi4miwwq7cfderohicec3tsjnojq/8.png",
    "bafybeifjmbzw4623nkbrji5vmahgygtkeikl2id23fddym4fovspeargle/9.png",
    "bafybeibljith3s2p7bhewtfjabpssvsxchhr7peuok3ovksedai24steca/10.png",
    "bafybeihyg4rr22joidsj3iabhakrtzccfw7yu4e4jivi5k2g6dxzx37cji/11.png",
    "bafybeidl4vfgozexxpnd2f6jlrvzukg57w6rx7hsp4mqyhonfe2jqsofk4/12.png",
    "bafybeiegqsp5fhjfxjlxn4pz7mjyqrfufujl7q5b7tc4m6c54qwiui56dq/13.png",
    "bafybeibnfylvb5wt52snk4ysjpjva375qrsfuefmpazjips57vqh7qotue/14.png",
    "bafybeienhpn3mmhz6thd4fsompabimm5nrckkdmee5dmbttwoenscvq35a/15.png",
    "bafybeih2nzl4whby3boqyhmxduurcpxc42swsnrdclvlnkymm3e5sazb3q/16.png",
    "bafybeiefla4dqvtitzc5gcxzkfjsyqeglrmgiqf7otvb3fyfulycg6slbi/17.png",
    "bafybeicmbsfmms2uou2j2bnkk4zclwoame4g3gfrtf3uqldc7wynvjixdy/18.png",
    "bafybeid55k5gcprfldsm6up4gn2zit2yxkiulub2dj4ch2u3cvyyvi5spm/19.png",
    "bafybeieyvsycayibpt6ba2sheynybvwspdp4hmpd5korwan62d7xh4ifoi/20.png",
    "bafybeidgyyy7uyjdszhjmjdxydjvv2ml4yubkkoszhw7jqk5cnq4q5p5ku/21.png",
    "bafybeiabef6qwjur72567ontn2enb6q6a6y2nmrxe22dptvkjmekboqxbq/22.png",
    "bafybeiaky5urvqxfbqgw7cdnz3y2jfgmmn5etkdiyststppncjt4obmsem/23.png",
    "bafybeihzdaz2zdybzruzaylgodrc5wnc4ovdgxecd5vr6cnmxiwa6bsznu/24.png",
    "bafybeid4k5owwkp2iwpwysx2fkrm22cw3uocpibiayefbyq3djndckehky/25.png",
    "bafybeidisyhllcubgt7fonj75wba5pd5fav5ouyp2pfobknj65ddt77gtu/26.png",
    "bafybeihy5ebpxx66nrit6ab37di4o4fnudxuo6uynyfyw6usqeomty53yi/27.png",
    "bafybeie7p3vv2mife23ny32sryybfvkthvtkhhr3odaz6ez3yxkztchylq/28.png",
    "bafybeidi7fynufmcpf62icnl353cpthyvlccvzmiagb347wjpkaeszm2uy/29.png",
    "bafybeiggt4qctt4zc4ok2xrabbbdiftod2mk2keaq3fedtvlfomjqwvsri/30.png",
    "bafybeihp7dluwbvde5xhcsde4n7tfhjkumpk7fkowslrhgwjsciykyxv2e/31.png",
    "bafybeiepuyb3muwc4cktrehvy7evqh2b742gshrukvvpas33kxvsubmihy/32.png",
    "bafybeicmdrbgecx74o4a6vxqa46xdiw3skhtkgi45c5wu2psj6posdqcii/33.png",
    "bafybeigcfno3crdjkorj4zrmb7ljqzjmeazycvyk7xxigufmdtabrnzlqi/34.png",
    "bafybeibqhj4w7vpeylpbmsoea2tfcxhnc64vwirdzrede2qoi4aj2h55om/35.png",
    "bafybeib2hmg65ee3vu7wz27sb42lknkv3olu23qhemqticymqnfzmkn54e/36.png",
    "bafybeifs2ebu6abo735ju7j4md6t3hkadxz645k57ucdizvqgciy4ps62i/37.png",
    "bafybeif35al6hft2zxiclyht4o67q6ikyky7h3mhfo5hutbyfzynolne4m/38.png",
    "bafybeibq6vhh3ow6ttibcbv4aepdl4m4rptf5zjsss2fhtjedecskzkhpy/39.png",
    "bafybeihtdemergxlzro3gqbnw6lnrwsv5egk5c4byhgg53645hbyztnifu/40.png",
    "bafybeigsv55x7wl3ylvxgsocjlbuacl6msd25uivlgnvnan5imosxs72ue/41.png",
    "bafybeidmjlrgqnw5jbyaugdnqoznfd5nhbmideuzisc3pihevofanvcf7m/42.png",
    "bafybeiaho2ryguxp4kikrx6l4qqnmioilvlxtzukdzazl2e2sjanjg3j5i/43.png",
    "bafybeigyxtw4sflpjzhqojrceazskx7r7di2pzm6lmm5574pkjvlu5wprq/44.png",
    "bafybeibhstjoxjpb3ifqg2pkjbjt2begv7o6yyqv2nvq6mytmpyx63pu2q/45.png",
    "bafybeibd2a22uu5nwogbnbcd2j63jhoxzebx7jiw2mz4of5eipimp3vlfm/46.png",
    "bafybeihej5csmxgut63guxwpcmjlpcqydeswac3ml3daxsxyaool5ubqrm/47.png",
    "bafybeifv25l3j7vuio4fpibldnz6pnc7ulcpjpkm56uiy34ix4xhayhrea/48.png",
    "bafybeidavpbhl5kmw2tw5m77wdadvyii4cn3kj2qa774kzqxt5hhlfk6de/49.png",
    "bafybeih3myim7cot6qgkufpf4qax4jwfosb3ay2j7ngnp23nlndbak7gbu/50.png",
    "bafybeibjr4isxcym3br4dw3qyhg2lqfxs7swnej6leovld7o6j4caiv2eq/51.png",
    "bafybeifbctyqcaw7omczjuhtusrqj6inph7duxrummkjwu54aeljenjyea/52.png",
    "bafybeihtrcyp5dvmtlrumyarinhkplroynd2mhqprbpkml6pjrhjh5jqby/53.png",
    "bafybeie3bjbnkrzz6qxm6prwkzbqson6mioo2sugkb3x5yrihad34s3jyy/54.png",
    "bafybeib7sv5z7imkhpaooyrczhpblbupqlt3gqbcwq2qxpqikbdruhj7h4/55.png",
    "bafybeifmlm6mrnyulltqnteod7gte5gjazpqcgfwwpkakrz3wfy3jdogsu/56.png",
    "bafybeidfio3epkf6fpqyz2phkfvljakcezwilnfnkuuiywm5temfcaotiu/57.png",
    "bafybeifz6omzulksux26v6edmnbzlgibbypzubrkyx6ldlygocnniemchu/58.png",
    "bafybeigg5b7ekwbhscgpfcbkvlyvbfchwlgzfap7fijsq2ukpzz2em7sja/59.png",
    "bafybeia2bjfwpgonkj7vhhwg77uclpkw6yqollcvaxjxwwriqt76idow4a/60.png",
    "bafybeiag2qrodx2ccswb3i2s6y6bk7rtvh7tisrk4xijyl66sb6vuwelru/61.png",
    "bafybeibu3mvhofxxm5lsvzuhidepfcxlimdbzz3khisp3irqe66w53hnri/62.png",
    "bafybeidlrjyyrhyxibd72ckqptuejqx2kddbcqcpwydtz3vajun2yo4j3a/63.png",
    "bafybeibnfwgnv5yiapnx6fhorzhtsbrxyzoheexwmlmr2a2xkxy24keh3q/64.png",
    "bafybeiaywoattfnnyzoqdrovfvyulnj44ypkwqxsjz6knsrsr5omooklja/65.png",
    "bafybeifiyzfn5og6gr74v6oe4ytwoztszn6sjjzqprehjdew4xge35fyte/66.png",
    "bafybeigj57sqg6lwnt2hffigvvvwhpt6ir2hgujmgnqzm6l23rmsqdanei/67.png",
    "bafybeiel246xxkwgtz3li7iitx5ujjshjdip7su2zzongk63zgxzhzxuoe/68.png",
    "bafybeihj7grfgvonzjcvd2enc3kovwmwcwhhysddb2txb5x2updha4r7qm/69.png",
    "bafybeicob7xlej5qdwotmejiizt4dhuvoq3fcdso3fsfcfabokx7hjva2u/70.png",
    "bafybeigpzytgwmpdpig3s4l7fdg2w7627c4tz7gxqa742xo6uakmyze7qa/71.png",
    "bafybeihze2fkvmli5dm73ymiqztgdni27j3ztffmn2j4syr5wx4naejqiu/72.png",
    "bafybeia5falyzlwyt5zhhrkj5xkidjplz4yuaq5ppzs3mmml4tbgvgbcgq/73.png",
    "bafybeiexu6gltckfabwhvjmrrq6dokxnfdxydgzuzc4pwehp4asyji7dsi/74.png",
    "bafybeihiyvsc4isfvziwo5lg2bqnsoeyx545awvqvyk3afyireviercg2i/75.png",
    "bafybeiewjw2bmvclvewxpish4b3h3gokqbvp2rxkuklmroys73s2casno4/76.png",
    "bafybeifiyhndowzs5ohsbu6oo3jp2efdyg5r7koiyagbecnc3l3jxtgt4i/77.png",
    "bafybeibruwz6z4v2qodbuovpgctiu6qq4xpjgdyvrp5fqih3v33hba2tgi/78.png",
    "bafybeiatcunvjtmdhgiz5gaqnc63jvoe4ch5tf3gc2nc63jgdbjnsfnrce/79.png",
    "bafybeiekjthxvazasrv2i2fav55xnqcrww23k6z5xa7vbq6ygpj5d4y7nu/80.png",
    "bafybeia7x66ub5ninxssddqqhcjg7lhkpajucgjen62haljbtpo2jcl35y/81.png",
    "bafybeibgthwxybiyai3i3tismoujkogh4xtipobm6ez2j6kjpdgtbx5rie/82.png",
    "bafybeifg5blbog3h7knabnprws7lrt3e3owjc7zqhg5e442hdnmzhpmraq/83.png",
    "bafybeihssuwji6vdi6sxaqjifso4o7cdsyxaexfpsbxswqcljgi2k4fcna/84.png",
    "bafybeidwih3zspn6r6hnvrihwhggq7mifq6p5keitcmsuucwu2be3yiygu/85.png",
    "bafybeibwh7gmwgjwjw3siysytkhyiik3rx5zml5mtqzr4dah65mojlid2q/86.png",
    "bafybeiagfudwfwbc52kbxjvfngkdmy3dgj3dd3rptvtjxmw63tgnfrgtja/87.png",
    "bafybeifl2wrn3ewx4oh5iw3kh2uctbm2wdw4c75g2ekxxnvif3u3x22vru/88.png",
    "bafybeibmxm32pspx2bmpbvf32dh67qg5z4kmqqpuierdo5sbiwdfhz76uy/89.png",
    "bafybeihouhmonqdr4scfsgazyenulsl4krvif2l4v2xrhpwi454yh7zsfa/90.png",
    "bafybeia47xlh5g4s3b5wf2um5hixjrwvk2njnpzdmizr5ayxylvmrh256y/91.png",
    "bafybeifyltspgtm32zn6v5w3jasqkv5nkyugvk6s7btvjyehmllybers7m/92.png",
    "bafybeibch2274okimr24j27n7xpxl46iq63f5ros43rp4mzvihuz6hdtzi/93.png",
    "bafybeiefji3z6v3aqemjf4cyeqkb2r4cbr4hzqabkgwc5gbm2isv2kjqxq/94.png",
    "bafybeigzqm4h3mvmulviqo2sao33dncd4xmnrmemt7jk4luhsl34pmputu/95.png",
    "bafybeiaskeyvdkkp2hnpiaww3zhiewhxiq57zha6wshktyjdl6ivvijoia/96.png",
    "bafybeic2arp2fuuocdqdcx7tzjgl6m4jfozty7mjt4mvyffjqh2y3oz33y/97.png",
    "bafybeidej2nunivmxwsrpqyxmurnflproqobzv3pm7sx3uudpb64cawcxu/98.png",
    "bafybeidqpcfb6vg3xevz3n4jyfcl5s2nftftgdqhrnuclcwrsc6wgb2g6u/99.png"
  ];
    
  constructor() ERC721("Genesis Rocks: 10,000", "ROCKS10") {}

  function tokenURI(uint256 tokenId) public view virtual override returns (string memory) {
    require(tokenId > 99 && tokenId < 10000);
   
    string memory image = string(abi.encodePacked(_baseURI(), _hash(tokenId % 100)));

    return string(
      abi.encodePacked(
        'data:application/json;base64,',
        Base64.encode(
          bytes(
            abi.encodePacked(
              '{"name":"',
                string(abi.encodePacked("Rock #", tokenId.toString())),
              '", "description":"',
                string(abi.encodePacked("Rock #", tokenId.toString(), " from a contract deployed on the 25th of December, 2017")),
              '", "attributes": [{ "trait_type:": "Number", "value": ', tokenId.toString(), ' }], "image": "',
                image,
              '"}'
            )
          )
        )
      )
    );
  }
  
  function _baseURI() internal view virtual override returns (string memory) {
    return "ipfs://";
  }
  
  function _hash(uint256 id) internal view virtual returns (string memory) {
    return hashes[id];
  }
  
  function totalSupply() public view virtual returns (uint256) {
    return _totalSupply;
  }
    
  function wrap(uint256 id) public {
    // get warden address
    address warden = wardens[_msgSender()];
    require(warden != address(0), "Warden not registered");
    require(id > 99 && id < 10000);
    
    // claim rock
    RockWarden(warden).claim(id, rocks);
    
    // mint wrapped rock
    _mint(_msgSender(), id);
    
    // increment supply
    _totalSupply += 1;
  }
  
  function unwrap(uint256 id) public {
    require(_msgSender() == ownerOf(id));
    
    // burn wrapped rock
    _burn(id);
    
    // decrement supply
    _totalSupply -= 1;
    
    // send rock to user
    rocks.giftRock(id, _msgSender());
  }
  
  function rescue(uint256 id) public {
    // get warden address
    address warden = wardens[_msgSender()];
    require(warden != address(0), "Warden not registered");

    // withdraw rock
    RockWarden(warden).withdraw(id, rocks, _msgSender());
  }
  
  function createWarden() public {
    address warden = address(new RockWarden());
    require(warden != address(0), "Warden address incorrect");
    require(wardens[_msgSender()] == address(0), "Warden already created");
    wardens[_msgSender()] = warden;
  }
}