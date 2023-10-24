// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.12;

import "@openzeppelin/contracts/access/Ownable.sol";

contract OpenIDKeyManager is Ownable {
    event UpdateOpenIDPublicKey(bytes32 _key, bytes _publicKey);
    event DeleteOpenIdPublicKey(bytes32 _key);

    /**
    /**
     * openIDPublicKey: kecaak256(issuser + key id) => public key
     */
    mapping(bytes32 => bytes) openIDPublicKey;

    function getOpenIDPublicKey(
        bytes32 _key
    ) public view returns (bytes memory publicKey) {
        publicKey = openIDPublicKey[_key];
    }

    function updateOpenIDPublicKey(
        bytes32 _key,
        bytes calldata _publicKey
    ) external onlyOwner {
        openIDPublicKey[_key] = _publicKey;
        emit UpdateOpenIDPublicKey(_key, _publicKey);
    }

    function batchUpdateOpenIDPublicKey(
        bytes32[] calldata _keys,
        bytes[] calldata _publicKeys
    ) external onlyOwner {
        uint256 length = _keys.length;
        require(
            length == _publicKeys.length,
            "batchUpdateOpenIDPublicKey: INVALID_LENGTH"
        );

        for (uint256 i; i < length; i++) {
            bytes32 key = _keys[i];
            bytes calldata publicKey = _publicKeys[i];
            openIDPublicKey[key] = publicKey;
            emit UpdateOpenIDPublicKey(key, publicKey);
        }
    }

    function deleteOpenIDPublicKey(bytes32 _key) external onlyOwner {
        delete openIDPublicKey[_key];
        emit DeleteOpenIdPublicKey(_key);
    }
}
