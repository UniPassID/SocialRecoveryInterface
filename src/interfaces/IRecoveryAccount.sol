// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "../TypesAndDecoders.sol";

interface IRecoveryAccount {
    /**
     * @dev Events for updating guardians, starting for recovery, executing recovery, and canceling recovery
     */
    event GuardiansUpdated(RecoveryPolicyArg[] recoveryPolicies);
    event RecoveryStarted(bytes newOwners, uint256 nonce, uint48 expireTime);
    event RecoveryExecuted(bytes newOwners, uint256 nonce);
    event RecoveryCanceled(uint256 nonce);

    /**
     * @dev Return the domain separator name and version for signatures
     * Also return the domainSeparator for EIP-712 signature
     */

    /// @notice             Domain separator name for signatures
    function DOMAIN_SEPARATOR_NAME() external view returns (string memory);

    /// @notice             Domain separator version for signatures
    function DOMAIN_SEPARATOR_VERSION() external view returns (string memory);

    /// @notice             returns the domainSeparator for EIP-712 signature
    /// @return             the bytes32 domainSeparator for EIP-712 signature
    function domainSeparatorV4() external view returns (bytes32);

    /**
     * @dev Update /replace guardians and recovery policies
     * Multiple recovery policies can be set using an array of RecoveryPolicyConfig
     */
    function updateGuardians(
        RecoveryPolicyArg[] memory policyArgs
    ) external;

    // Generate EIP-712 message hash,
    // Iterate over signatures for verification,
    // Verify recovery policy,
    // Store temporary state or recover immediately based on the result returned by verifyRecoveryPolicy.
    function startRecovery(
        address policyVerifier,
        bytes memory newOwner,
        Permissions[] memory permissions
    ) external;

    /**
     * @dev Execute recovery
     * temporary state -> ownerKey rotation
     */
    function executeRecovery(address policyVerifier) external;

    function cancelRecovery(address policyVerifier) external;

    function cancelRecoveryByGuardians(
        address policyVerifier,
        Permissions[] memory permissions
    ) external;

    /**
     * @dev Get wallet recovery info, recovery policy config, check if an identity is a guardian, get the nonce of social recovery, and get the recovery status of the wallet
     */
    function isGuardian(
        Identity memory guardian
    )
        external
        view
        returns (bool);

    function getRecoveryPolicies()
        external
        view
        returns (RecoveryPolicyArg[] memory recoveryPolicyArgs);

    function getRecoveryConfigs(
        address policyVerifier
    ) external view returns (RecoveryConfigArg memory configArg);

    function getRecoveryNonce() external view returns (uint256 nonce);

    function getRecoveryStatus(
        address policyVerifier
    ) external view returns (bool isRecovering, uint48 expiryTime);
}
