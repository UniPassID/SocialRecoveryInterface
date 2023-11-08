// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.12;

import "@openzeppelin/contracts/access/Ownable.sol";

abstract contract DkimKeys is Ownable {
    event UpdateDKIMKey(bytes emailServer, bytes key);
    event DeleteDKIMKey(bytes emailServer, bytes oldKey);

    mapping(bytes => bytes) private dkimKeys;

    function getDKIMKey(
        bytes memory _emailServer
    ) public view returns (bytes memory) {
        return dkimKeys[_emailServer];
    }

    function updateDKIMKey(
        bytes calldata _emailServer,
        bytes calldata key
    ) external onlyOwner {
        dkimKeys[_emailServer] = key;
        emit UpdateDKIMKey(_emailServer, key);
    }

    function batchUpdateDKIMKeys(
        bytes[] calldata _emailServers,
        bytes[] calldata _keys
    ) external onlyOwner {
        uint256 length = _emailServers.length;
        require(length == _keys.length, "batchUpdateDKIMKeys: INVALID_LENGTH");
        for (uint256 i; i < length; i++) {
            bytes calldata emailServer = _emailServers[i];
            bytes calldata key = _keys[i];
            dkimKeys[emailServer] = key;
            emit UpdateDKIMKey(emailServer, key);
        }
    }

    function deleteDKIMKey(bytes calldata _emailServer) external onlyOwner {
        delete dkimKeys[_emailServer];
        emit DeleteDKIMKey(_emailServer, dkimKeys[_emailServer]);
    }
}
