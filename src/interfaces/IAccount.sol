// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

interface IAccount {
    function isAuthorizedModule(address module) external returns (bool);

    function resetOwner(bytes memory newOwner) external;
}
