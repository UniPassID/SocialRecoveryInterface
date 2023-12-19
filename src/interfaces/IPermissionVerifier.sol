// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.13;

/**
 * @dev Interface for no-account type identity signature/proof verification
 */
interface IPermissionVerifier {
    /**
     * @dev Check if the signer key format is correct
     */
    function isValidSigners(bytes[] memory signers) external returns (bool);

    /**
     * @dev Validate signature
     */
    function isValidPermission(
        bytes32 hash,
        bytes memory signer,
        bytes memory signature
    ) external returns (bool);

    /**
     * @dev Validate signatures
     */
    function isValidPermissions(
        bytes32 hash,
        bytes[] memory signers,
        bytes[] memory signatures
    ) external returns (bool);

    /**
     * @dev Return supported signer key information, format, signature format, hash algorithm, etc.
     * MAY TODO:using ERC-3668: ccip-read
     */
    function getGuardianVerifierInfo() external view returns (bytes memory);
}
