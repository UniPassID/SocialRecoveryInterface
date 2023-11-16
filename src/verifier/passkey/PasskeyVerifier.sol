// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "../../libraries/LibBase64.sol";
import "../../libraries/LibBytes.sol";
import "../../interfaces/IPermissionVerifier.sol";

import "./FCL_ecdsa.sol";

// import "./Secp256r1.sol";

contract PasskeyVerifier is IPermissionVerifier {
    using LibBytes for bytes;

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

    function getMessage(
        bytes32 hash,
        bytes calldata signature
    ) internal pure returns (bytes32) {
        uint32 len;
        uint256 index;
        bytes calldata authenticatorData;
        bytes calldata clientDataJSONPre;
        bytes calldata clientDataJSONPost;
        (len, index) = signature.cReadUint32(64);
        authenticatorData = signature[index:index + len];
        index += len;
        (len, index) = signature.cReadUint32(index);
        clientDataJSONPre = signature[index:index + len];
        index += len;
        (len, index) = signature.cReadUint32(index);
        clientDataJSONPost = signature[index:index + len];
        index += len;

        string memory hashBase64 = LibBase64.urlEncode(abi.encodePacked(hash));
        bytes memory clientDataJSON = abi.encodePacked(
            clientDataJSONPre,
            hashBase64,
            clientDataJSONPost
        );

        bytes32 clientHash = sha256(bytes(clientDataJSON));
        return sha256(abi.encodePacked(authenticatorData, clientHash));
    }

    function isValidPermission(
        bytes32 hash,
        bytes calldata signer,
        bytes calldata signature
    ) public view returns (bool) {
        bytes32 r;
        bytes32 s;
        bytes32 message = getMessage(hash, signature);
        r = signature.mcReadBytes32(0);
        s = signature.mcReadBytes32(32);
        {
            bytes32 Qx;
            bytes32 Qy;
            Qx = signer.mcReadBytes32(0);
            Qy = signer.mcReadBytes32(32);
            require(
                FCL_ecdsa.ecdsa_verify(
                    message,
                    uint256(r),
                    uint256(s),
                    uint256(Qx),
                    uint256(Qy)
                ),
                // Secp256r1.Verify(
                //     uint256(Qx),
                //     uint256(Qy),
                //     uint256(r),
                //     uint256(s),
                //     uint256(message)
                // ),
                "P256: Invalid signature"
            );
        }
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
