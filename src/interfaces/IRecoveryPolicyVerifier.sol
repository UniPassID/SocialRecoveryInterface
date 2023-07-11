// SPDX-License-Identifier: UNLICENSED
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
        Identity[] memory guardians,
        RecoveryConfigArg memory configArg
    ) external view returns (bool succ, uint48 lockPeriod);

    /**
     * @dev Returns supported policy settings and accompanying property definitions for Guardian.
     */
    function getPolicyVerifierInfo() external view returns (bytes memory);
}
