// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

/**
 * @dev Structure representing an identity with its signature/proof verification logic.
 * Represents an EOA/CA account when signer is empty,use `guardianVerifier`as the actual signer for signature verification.
 * OtherWise execute IGuardianPermissionVerifier(guardianVerifier).isValidPermissions(signer,hash,signature).
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
    uint32 property; //eg.,Weight,Percentage,Role with weight,etc.
}

/**
 * @dev Structure representing a threshold configuration
 */
struct ThresholdConfig {
    uint32 threshold; // Threshold value
    uint48 lockPeriod; // Lock period for the threshold
}

/**
 * @dev Structure representing a recovery configuration
 * A RecoveryConfig can have multiple threshold configurations for different threshold values and their lock periods
 */
struct RecoveryConfigArg {
    GuardianInfo[] guardianInfos;
    ThresholdConfig[] thresholdConfigs;
}

/**
 * @dev Structure representing a recovery policy with its verification logic (policy verifier contract address)
 */
struct RecoveryPolicyArg {
    address policyVerifier;
    RecoveryConfigArg config;
}

/**
 * @dev Structure representing a recovery configuration
 * A RecoveryConfig can have multiple threshold configurations for different threshold values and their lock periods
 */
struct RecoveryConfig {
    mapping(bytes32 => bytes32) identityHashs;
    mapping(bytes32 => GuardianInfo) guardianInfos;
    ThresholdConfig[] thresholdConfigs;
}

struct RecoveryPolicy {
    bool enabled;
    address policyVerifier;
    RecoveryConfig config;
}

struct Permissions {
    Identity[] guardians;
    bytes[] signatures;
}
