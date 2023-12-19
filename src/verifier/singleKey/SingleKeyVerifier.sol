// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.13;

import "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";

import "../../interfaces/IPermissionVerifier.sol";

contract SingleKeyVerifier is IPermissionVerifier {
    function bytesToAddress(
        bytes memory bys
    ) private pure returns (address addr) {
        assembly {
            addr := mload(add(bys, 20))
        }
    }

    function isValidSigner(bytes memory signer) public pure returns (bool) {
        if (signer.length == 20) {
            return true;
        }
        return false;
    }

    /**
     * @dev Check if the signer key format is correct
     */
    function isValidSigners(bytes[] memory signers) public pure returns (bool) {
        for (uint256 i = 0; i < signers.length; i++) {
            bool succ = isValidSigner(signers[i]);
            if (!succ) {
                return false;
            }
        }

        return true;
    }

    /**
     * @dev Validate signature
     */
    function isValidPermission(
        bytes32 hash,
        bytes memory signer,
        bytes memory signature
    ) public view returns (bool) {
        address signerAddr = bytesToAddress(signer);
        return
            SignatureChecker.isValidSignatureNow(signerAddr, hash, signature);
    }

    /**
     * @dev Validate signatures
     */
    function isValidPermissions(
        bytes32 hash,
        bytes[] memory signers,
        bytes[] memory signatures
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
        pure
        returns (bytes memory metadata)
    {}
}
