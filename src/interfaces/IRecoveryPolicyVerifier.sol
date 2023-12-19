// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.13;

import "../TypesAndDecoders.sol";

/**
 * @dev Interface for recovery policy verification
 */
interface IRecoveryPolicyVerifier {
    /**
     * @dev Verify recovery policy and return verification success and lock period
     * Verification includes checking if guardians exist in the Guardians List
     */
    function verifyRecoveryPolicy(
        Permission[] memory permissions,
        uint64[] memory properties
    ) external view returns (bool succ, uint64 weight);

    /**
     * @dev Returns supported policy settings and accompanying property definitions for Guardian.
     */
     
    function getPolicyVerifierInfo() external view returns (bytes memory);
}
