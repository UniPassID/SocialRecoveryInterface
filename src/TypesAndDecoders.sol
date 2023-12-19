// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.13;

/**
 * @dev Structure representing an identity with its signature/proof verification logic.
 * Represents an EOA/CA account when signer is empty,use `verifier`as the actual signer for signature verification.
 * OtherWise execute IGuardianPermissionVerifier(verifier).isValidPermission(signer,hash,signature).
 */
struct Identity {
    address guardianVerifier;
    bytes signer;
}

/**
 * @dev Structure representing a guardian with a property
 * The property of Guardian are defined by the associated RecoveryPolicyVerifier contract.
 */
struct GuardianInfo {
    Identity guardian;
    uint64 property; //eg.,Weight,Percentage,Role with weight,etc.
}

/**
 * @dev Structure representing a threshold configuration
 */
struct ThresholdConfig {
    uint64 threshold; // Threshold value
    uint48 lockPeriod; // Lock period for the threshold
}

/**
 * @dev Structure representing a recovery configuration
 * A RecoveryConfig can have multiple threshold configurations for different threshold values and their lock periods
 */
struct RecoveryConfigArg {
    address policyVerifier;
    GuardianInfo[] guardianInfos;
    ThresholdConfig[] thresholdConfigs;
}

enum UpdateType {
    Replace,
    Append
}

struct PendingConfig {
    UpdateType updateType;
    uint256 pendingUntil;
    bytes32 configsHash;
}

/**
 * @dev Structure representing a recovery configuration
 * A RecoveryConfig can have multiple threshold configurations for different threshold values and their lock periods
 */
struct RecoveryConfig {
    bool enabled;
    address policyVerifier;
    mapping(bytes32 => bytes32) identityHashs;
    mapping(bytes32 => GuardianInfo) guardianInfos;
    ThresholdConfig[] thresholdConfigs;
}

struct Permission {
    Identity guardian;
    bytes signature;
}
