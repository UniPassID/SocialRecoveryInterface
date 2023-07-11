// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "./TypesAndDecoders.sol";
import "./interfaces/IPermissionVerifier.sol";
import "./interfaces/IRecoveryAccount.sol";
import "./interfaces/IRecoveryPolicyVerifier.sol";
import "./libraries/HashLinkedList.sol";
import "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";

interface IUniPassWallet {
    function isAuthorizedModule(address module) external returns (bool);
}

contract RecoveryModule {
    using HashLinkedList for mapping(bytes32 => bytes32);

    struct RecoveryEntry {
        address[] newOwners;
        uint256 executeAfter;
        uint256 nonce;
    }

    /**
     * @dev Events for updating guardians, starting for recovery, executing recovery, and canceling recovery
     */
    event GuardiansUpdated(
        address account,
        RecoveryPolicyArg[] recoveryPolicies
    );
    event RecoveryStarted(
        address account,
        bytes newOwners,
        uint256 nonce,
        uint48 expireTime
    );
    event RecoveryExecuted(address account, bytes newOwners, uint256 nonce);
    event RecoveryCanceled(address account, uint256 nonce);

    /**
     * @dev Return the domain separator name and version for signatures
     * Also return the domainSeparator for EIP-712 signature
     */

    string public constant NAME = "Recovery Module";
    string public constant VERSION = "0.0.1";

    // keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 private constant _DOMAIN_SEPARATOR_TYPEHASH =
        0x8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f;

    mapping(address => uint256) walletRecoveryNonce;
    mapping(address => RecoveryPolicy[]) internal walletPolicies;

    mapping(address => mapping(bytes32 => uint256)) approvedRecords;
    mapping(address => RecoveryEntry) recoveryEntries;

    modifier authorized(address _wallet) {
        require(
            IUniPassWallet(_wallet).isAuthorizedModule(address(this)),
            "unauthorized"
        );
        _;
    }

    modifier InRecovering(address account) {
        require(
            recoveryEntries[account].executeAfter > 0,
            "no ongoing recovery"
        );
        _;
    }

    modifier NotInRecovering(address account) {
        require(recoveryEntries[account].executeAfter == 0, "ongoing recovery");
        _;
    }

    function getChainID() internal view returns (uint256) {
        uint256 id;
        assembly {
            id := chainid()
        }
        return id;
    }

    /// @notice             returns the domainSeparator for EIP-712 signature
    /// @return             the bytes32 domainSeparator for EIP-712 signature
    function domainSeparator() public view returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    _DOMAIN_SEPARATOR_TYPEHASH,
                    keccak256(abi.encodePacked(NAME)),
                    keccak256(abi.encodePacked(VERSION)),
                    getChainID(),
                    this
                )
            );
    }

    function updateGuardians(RecoveryPolicyArg[] memory policyArgs) public {
        address account = msg.sender;
        delete walletPolicies[account];
        for (uint i = 0; i > policyArgs.length; i++) {
            _addPolicy(account, policyArgs[i]);
        }
    }

    function addPolicy(
        RecoveryPolicyArg memory policyArg
    ) external authorized(msg.sender) NotInRecovering(msg.sender) {
        address account = msg.sender;
        _addPolicy(account, policyArg);
    }

    function _addPolicy(
        address account,
        RecoveryPolicyArg memory policyArg
    ) internal {
        RecoveryPolicy storage policy = walletPolicies[account].push();
        policy.policyVerifier = policyArg.policyVerifier;

        for (uint i = 0; i < policyArg.config.thresholdConfigs.length; i++) {
            policy.config.thresholdConfigs.push(
                policyArg.config.thresholdConfigs[i]
            );
        }
        for (uint i = 0; i < policyArg.config.guardianInfos.length; i++) {
            bytes32 identityHash = keccak256(
                abi.encode(policyArg.config.guardianInfos[i])
            );
            policy.enabled = true;
            policy.config.identityHashs.add(identityHash);
            policy.config.guardianInfos[identityHash] = policyArg
                .config
                .guardianInfos[i];
        }
    }

    // Generate EIP-712 message hash,
    // Iterate over signatures for verification,
    // Verify recovery policy,
    // Store temporary state or recover immediately based on the result returned by verifyRecoveryPolicy.
    function startRecovery(
        address account,
        uint256 index,
        bytes memory newOwner,
        Permissions memory permissions
    ) external {
        RecoveryPolicy storage policy = walletPolicies[account][index];
        require(policy.enabled, "unenabled policy");
        bool _defaultPolicyVerifier = policy.policyVerifier == address(0);

        for (uint256 i = 0; i < permissions.length - 1; i++) {
            if (permissions.guardians[i].signer.length == 0) {
                require(
                    SignatureChecker.isValidSignatureNow(
                        permissions.guardians[i].guardianVerifier,
                        bytes32(uint256(0)),
                        permissions.signatures[i]
                    ),
                    "invalid signature"
                );
            } else {
                require(
                    IPermissionVerifier(
                        permissions.guardians[i].guardianVerifier
                    ).isValidPermission(
                            bytes32(uint256(0)),
                            permissions.guardians[i].signer,
                            permissions.signatures[i]
                        ),
                    "invalid signature"
                );
            }

            if (_defaultPolicyVerifier) {
                for (uint256 j = i + 1; j < permissions.guardians.length; j++) {
                    if (permissions.guardian[i] == permissions.guardian[j]) {
                        return true;
                    }
                }
            } else {
                IRecoveryPolicyVerifier(policy.policyVerifier).verifyRecoveryPolicy(permissions.guardians, configArg);
            }
        }
    }

    /**
     * @dev Execute recovery
     * temporary state -> ownerKey rotation
     */
    function executeRecovery(
        address account,
        address policyVerifier
    ) external {}

    function cancelRecovery(
        address account,
        address policyVerifier
    ) external InRecovering(account) {}

    function cancelRecoveryByGuardians(
        address account,
        address policyVerifier,
        Permission[] memory permissions
    ) external InRecovering(account) {}

    /**
     * @dev Get wallet recovery info, recovery policy config, check if an identity is a guardian, get the nonce of social recovery, and get the recovery status of the wallet
     */
    function isGuardian(
        address account,
        Identity memory guardian
    )
        public
        view
        returns (bool, RecoveryPolicyArg[] memory recoveryPolicyConfigs)
    {
        recoveryPolicyConfigs = new RecoveryPolicyArg[](1);
        return (false, recoveryPolicyConfigs);
    }

    function getRecoveryPolicies(
        address account
    ) public view returns (RecoveryPolicyArg[] memory recoveryPolicyConfigs) {
        recoveryPolicyConfigs = new RecoveryPolicyArg[](1);
        return recoveryPolicyConfigs;
    }

    function getRecoveryConfigs(
        address account,
        address policyVerifier
    ) public view returns (RecoveryConfigArg memory config) {}

    function getRecoveryNonce(
        address account
    ) public view returns (uint256 nonce) {
        return 0;
    }

    function getRecoveryStatus(
        address account,
        address policyVerifier
    ) public view returns (bool isRecovering, uint48 expiryTime) {
        return (false, 0);
    }
}
