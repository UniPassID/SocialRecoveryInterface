// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.12;

import "@openzeppelin/contracts/access/Ownable.sol";

contract AudManager is Ownable {
    event AddOpenIDAudience(bytes32 _key);
    event DeleteOpenIDAudience(bytes32 _key);

    /**
     * openIDAudience: keccak256(issuser + audience) => is valid
     */
    mapping(bytes32 => bool) openIDAudience;

    function isAudienceValid(bytes32 _key) public view returns (bool isValid) {
        isValid = openIDAudience[_key];
    }

    function addOpenIDAudience(bytes32 _key) external onlyOwner {
        openIDAudience[_key] = true;
        emit AddOpenIDAudience(_key);
    }

    function deleteOpenIDAudience(bytes32 _key) external onlyOwner {
        delete openIDAudience[_key];
        emit DeleteOpenIDAudience(_key);
    }
}
