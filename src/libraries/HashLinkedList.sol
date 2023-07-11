// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.17;

library HashLinkedList {
    bytes32 internal constant SENTINEL_HASH = bytes32(uint256(1));

    function add(
        mapping(bytes32 => bytes32) storage self,
        bytes32 hash
    ) internal {
        if (self[hash] != bytes32(0)) {
            revert("HASH_ALREADY_EXISTS");
        }
        bytes32 _prev = self[SENTINEL_HASH];
        if (_prev == bytes32(0)) {
            self[SENTINEL_HASH] = hash;
            self[hash] = SENTINEL_HASH;
        } else {
            self[SENTINEL_HASH] = hash;
            self[hash] = _prev;
        }
    }

    function replace(
        mapping(bytes32 => bytes32) storage self,
        bytes32 oldAddr,
        bytes32 newAddr
    ) internal {
        if (!isExist(self, oldAddr)) {
            revert("HASH_NOT_EXIST");
        }
        if (isExist(self, newAddr)) {
            revert("HASH_ALREADY_EXISTS");
        }

        bytes32 cursor = SENTINEL_HASH;
        while (true) {
            bytes32 _hash = self[cursor];
            if (_hash == oldAddr) {
                bytes32 next = self[_hash];
                self[newAddr] = next;
                self[cursor] = newAddr;
                self[_hash] = bytes32(0);
                return;
            }
            cursor = _hash;
        }
    }

    function remove(
        mapping(bytes32 => bytes32) storage self,
        bytes32 hash
    ) internal {
        if (!tryRemove(self, hash)) {
            revert("HASH_NOT_EXIST");
        }
    }

    function tryRemove(
        mapping(bytes32 => bytes32) storage self,
        bytes32 hash
    ) internal returns (bool) {
        if (isExist(self, hash)) {
            bytes32 cursor = SENTINEL_HASH;
            while (true) {
                bytes32 _hash = self[cursor];
                if (_hash == hash) {
                    bytes32 next = self[_hash];
                    self[cursor] = next;
                    self[_hash] = bytes32(0);
                    return true;
                }
                cursor = _hash;
            }
        }
        return false;
    }

    function clear(mapping(bytes32 => bytes32) storage self) internal {
        for (
            bytes32 hash = self[SENTINEL_HASH];
            uint256(hash) > uint256(SENTINEL_HASH);
            hash = self[hash]
        ) {
            self[hash] = bytes32(0);
        }
        self[SENTINEL_HASH] = bytes32(0);
    }

    function isExist(
        mapping(bytes32 => bytes32) storage self,
        bytes32 hash
    ) internal view returns (bool) {
        return self[hash] != bytes32(0);
    }

    function size(
        mapping(bytes32 => bytes32) storage self
    ) internal view returns (uint256) {
        uint256 result = 0;
        bytes32 hash = self[SENTINEL_HASH];
        while (uint256(hash) > uint256(SENTINEL_HASH)) {
            hash = self[hash];
            unchecked {
                result++;
            }
        }
        return result;
    }

    function isEmpty(
        mapping(bytes32 => bytes32) storage self
    ) internal view returns (bool) {
        return self[SENTINEL_HASH] == bytes32(0);
    }

    /**
     * @dev This function is just an example, please copy this code directly when you need it, you should not call this function
     */
    function list(
        mapping(bytes32 => bytes32) storage self,
        bytes32 from,
        uint256 limit
    ) internal view returns (bytes32[] memory) {
        bytes32[] memory result = new bytes32[](limit);
        uint256 i = 0;
        bytes32 hash = self[from];
        while (uint256(hash) > uint256(SENTINEL_HASH) && i < limit) {
            result[i] = hash;
            hash = self[hash];
            unchecked {
                i++;
            }
        }

        return result;
    }
}
