// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.6;

import "./openzeppelin/contracts/token/ERC721/ERC721.sol";
import "./verifier.sol";

interface ERC0001 /* is ERC721, ERC165 */ {

    /// @notice Mints token to a stealth address `stA` if proof is valid. stA is derived from
    ///  stealthAddressBytes which is the MIMC Sponge hash `h` (220 rounds) of the user address `eoa`,
    ///  the token id `tid` and a user-generated secret `s`, such that stA <== address() <== h(eoa,tid,s).
    /// @dev Requires a proof that verifies the following:
   ///        - prover can generate the StealthAddress (e.g. user signs msg => computePublicKey() => computeStealthAddress() ).
    ///       - prover can generate the merkle root from an empty leaf.
    ///       - prover can generate the merkle root after updating the empty leaf.
    /// @param currentRoot A known (historic) root.
    /// @param newRoot Updated root.
    /// @param stealthAddressBytes Hash of user address, tokenId and secret.
    /// @param tokenId The Id of the token.
    /// @param proof The zk-SNARK.
    function _mint(bytes32 currentRoot, bytes32 newRoot, bytes32 stealthAddressBytes, uint256 tokenId, bytes calldata proof) external;

    /// @notice Burns token with specified Id from stealth address `stA` if proof is valid.
    /// @dev Requires a proof that verifies the following:
    ///       - prover can generate the StealthAddress (e.g. user signs msg => computePublicKey() => computeStealthAddress() )
    ///       - prover can generate the merkle root from an non-empty leaf.
    ///       - prover can generate the merkle root after nullifieing the non-empty leaf.
    /// @param currentRoot A known (historic) root.
    /// @param newRoot Updated root.
    /// @param stealthAddressBytes Hash of user address, tokenId and secret.
    /// @param tokenId The Id of the token.
    /// @param proof The zk-SNARK.
    function _burn(bytes32 currentRoot, bytes32 newRoot, bytes32 stealthAddressBytes, uint256 tokenId, bytes calldata proof) external;

    /// @notice Transfers token with specified Id from current owner to the recipient's
    /// stealth address, if proof is valid.
    /// @dev Requires a proof that verifies the following:
    ///       - prover can generate the StealthAddress (e.g. user signs msg => computePublicKey() => computeStealthAddress() ).
    ///       - prover can generate the merkle root from an non-empty leaf.
    ///       - prover can generate the merkle root after updating the non-empty leaf.
    /// @param currentRoot A known (historic) root.
    /// @param newRoot Updated root.
    /// @param stealthAddressBytes Hash of user address, tokenId and secret.
    /// @param tokenId The Id of the token.
    /// @param proof The zk-SNARK.
    function _transfer(bytes32 currentRoot, bytes32 newRoot, bytes32 stealthAddressBytes, uint256 tokenId, bytes calldata proof) external;

    /// @notice Verifies zk-SNARKs
    /// @dev Forwards the different proofs to the right `Verifier` contracts.
    ///  Different Verifiers are required for each action, because of the merkle-tree logic involved.
    /// @param currentRoot A known (historic) root.
    /// @param newRoot Updated root.
    /// @param stealthAddressBytes Hash of user address, tokenId and secret.
    /// @param tokenId The Id of the token.
    /// @param proof The zk-SNARK.
    /// @return Validity of the provided proof.
    function _verifyProof(bytes32 currentRoot, bytes32 newRoot, bytes32 stealthAddressBytes, uint256 tokenId, bytes calldata proof) external returns (bool);
}


/**
 * @dev Extension of ERC721 to support owernship proofs using merkle proofs
 *
 * The merkle tree stores hashes of addresses and tokenIds in its leafs. It can be used to generate 
 * merkle proofs that prove owernship, off-chain. Using zk-SNARKs (e.g. PrivToAddress Circuits), users
 * can provide a merkle proof of ownership without unveiling their identity.
 */
abstract contract ERC721MerkleProvable is ERC165, ERC721 {
    // Verifier Contract Implementation
    Verifier private _verifier;  

    // Most recent merkle-root
    bytes32 public state_root;

    // Known merkle-roots (incl. historic roots)
    mapping (bytes32 => bool) public knownRoot;

	constructor(
        string memory name_, 
        string memory symbol_, 
        Verifier verifier_
    ) ERC721(name_, symbol_) {  
        _verifier = verifier_;
    }

    /**
    * @dev See {ERC721-_mint}. Mints token to a StealthAddress.
    *  Requires to provide a proof that a valid leaf was inserted into an empty slot
    *  in the merkle tree. The state_root is updated. 
    * @notice the roots, stealthAddressBytes and tokenId are 
    *  public parameter in the arithmetic circuit
    */
    function _mint( 
        bytes32 currentRoot,
        bytes32 newRoot,
        bytes32 stealthAddressBytes,
        uint256 tokenId,
        bytes calldata proof
    ) internal virtual {    
        require(knownRoot[currentRoot], "Root unknown");
        require(_verifyProof(currentRoot, newRoot, stealthAddressBytes, tokenId, proof), "Invalid proof");
        address stealthAddress = _getStealthAddress(stealthAddressBytes);
        super._mint(stealthAddress, tokenId);
        state_root = newRoot;
        knownRoot[state_root] = true;
    }

    /**
    * @dev See {ERC721-_burn}. Burns token with id tokenId.
    *  Requires to provide a proof that a valid leaf was zero`ed 
    *  in the merkle tree. The state_root is updated. 
    * @notice the roots, stealthAddressBytes and tokenId are 
    *  public parameter in the arithmetic circuit
    */
    function _burn(
        bytes32 currentRoot,
        bytes32 newRoot,
        bytes32 stealthAddressBytes,
        uint256 tokenId,
        bytes calldata proof
    ) internal virtual {    
        require(knownRoot[currentRoot], "Root unknown");
        require(_verifyProof(currentRoot, newRoot, stealthAddressBytes, tokenId, proof), "Invalid proof");
        super._burn(tokenId);
        state_root = newRoot;
        knownRoot[state_root] = true;
    }

    /**
    * @dev See {ERC721-_transfer}. Transfers token with tokenId.
    *  The caller must provide a valid proof of having computed the provided 
    *  stealthAddress and updated a non-empty leaf in the merkle tree
    *  Records the new state_root.
    * @notice the roots, stealthAddressBytes and tokenId are 
    *  public parameter in the arithmetic circuit
    */
    function _transfer(
        bytes32 currentRoot,
        bytes32 newRoot,
        bytes32 stealthAddressBytes,
        uint256 tokenId,
        bytes calldata proof
    ) internal virtual {
        require(knownRoot[currentRoot], "Root unknown");
        require(_verifyProof(currentRoot, newRoot, stealthAddressBytes, tokenId, proof), "Invalid proof");
        address stealthAddress = _getStealthAddress(stealthAddressBytes);
        super._transfer(ownerOf(tokenId), stealthAddress, tokenId);
        state_root = newRoot;
        knownRoot[state_root] = true;   
    }

    /**
    * @dev Verifies a proof. Note that the {Verifier} implementation must be able to parse the byte-data.
    */
    function _verifyProof(
        bytes32 currentRoot, 
        bytes32 newRoot, 
        bytes32 stealthAddressBytes, 
        uint256 tokenId,
        bytes calldata proof
    ) internal view returns (bool valid) {
        // require(knownRoot[currentRoot], "Root unknown");
        // Verifier implementation here, eg.:
        // Verifier.verifyProof(currentRoot, newRoot, stealthAddressBytes, tokenId, proof)
    }

    /**
    * @dev Generates Stealth Address from stealthAddressBytes.
    *  The stealthAddressBytes = MIMCSponge(220)(user_address, tokenid, user_secret).
    */
    function _getStealthAddress(bytes32 stealthAddressBytes) internal pure virtual returns (address) {
        return address(uint160(uint256(stealthAddressBytes)));
    }

    function supportsInterface(bytes4 interfaceId) public view virtual override(ERC165, ERC721) returns (bool) {
        return interfaceId == type(ERC0001).interfaceId ||
        super.supportsInterface(interfaceId);
    }
}