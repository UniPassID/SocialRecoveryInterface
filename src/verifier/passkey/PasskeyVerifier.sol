// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "../../libraries/LibBase64.sol";
import "../../interfaces/IPermissionVerifier.sol";

import "./FCL_ecdsa.sol";

contract PasskeyVerifier is IPermissionVerifier {
    function isValidSigner(bytes memory signer) public pure returns (bool) {
        if (signer.length == 64) {
            return true;
        }

        return false;
    }

    /**
     * @dev Check if the signer key format is correct
     */
    function isValidSigners(
        bytes[] memory signers
    ) external pure returns (bool) {
        for (uint256 i = 0; i < signers.length; i++) {
            bool succ = isValidSigner(signers[i]);
            if (!succ) {
                return false;
            }
        }
        return true;
    }

    function isValidPermission(
        bytes32 hash,
        bytes calldata signer,
        bytes calldata signature
    ) public view returns (bool) {
        (
            uint256 r,
            uint256 s,
            bytes memory authenticatorData,
            string memory clientDataJSONPre,
            string memory clientDataJSONPost
        ) = abi.decode(signature, (uint256, uint256, bytes, string, string));

        (uint256 Qx, uint256 Qy) = abi.decode(signer, (uint256, uint256));

        string memory hashBase64 = LibBase64.urlEncode(bytes.concat(hash));
        string memory clientDataJSON = string.concat(
            clientDataJSONPre,
            hashBase64,
            clientDataJSONPost
        );
        bytes32 clientHash = sha256(bytes(clientDataJSON));
        bytes32 message = sha256(bytes.concat(authenticatorData, clientHash));

        require(
            FCL_ecdsa.ecdsa_verify(message, r, s, Qx, Qy),
            "PM07: Invalid signature"
        );
        return true;
    }

    /**
     * @dev Validate signatures
     */
    function isValidPermissions(
        bytes32 hash,
        bytes[] calldata signers,
        bytes[] calldata signatures
    ) public view returns (bool) {
        require(signers.length == signatures.length, "invalid args");

        for (uint256 i = 0; i < signers.length; i++) {
            bool succ = isValidPermission(hash, signers[i], signatures[i]);
            if (!succ) {
                return false;
            }
        }

        return true;
    }

    /**
     * @dev Return supported signer key information, format, signature format, hash algorithm, etc.
     * MAY TODO:using ERC-3668: ccip-read
     */
    function getGuardianVerifierInfo()
        external
        view
        returns (bytes memory metadata)
    {}
}
