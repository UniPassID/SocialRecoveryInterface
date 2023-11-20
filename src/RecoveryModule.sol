// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "./TypesAndDecoders.sol";
import "./interfaces/IPermissionVerifier.sol";
import "./interfaces/ISafe.sol";
import "./interfaces/IRecoveryPolicyVerifier.sol";
import "./libraries/HashLinkedList.sol";
import "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";

contract RecoveryModule {
    using HashLinkedList for mapping(bytes32 => bytes32);

    struct RecoveryEntry {
        bytes data;
        uint256 executeAfter;
        uint256 nonce;
    }

    /**
     * @dev Events for updating guardians, starting for recovery, executing recovery, and canceling recovery
     */
    event GuardiansUpdated(address account);

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

    bytes32 internal constant _START_RECOVERY_TYPEHASH =
        keccak256(
            "startRecovery(address account,bytes newOwner,uint256 nonce)"
        );

    bytes32 internal constant _CANCEL_RECOVERY_TYPEHASH =
        keccak256("cancelRecovery(address account,uint256 nonce)");

    mapping(address => uint256) public walletRecoveryNonce;
    mapping(address => RecoveryConfig[]) internal walletConfigs;

    mapping(address => mapping(bytes32 => uint256)) approvedRecords;
    mapping(address => RecoveryEntry) recoveryEntries;
    mapping(address => PendingConfig) pendingConfigs;

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

    function replaceConfigs(
        bytes32 configsHash
    ) external NotInRecovering(msg.sender) {
        pendingConfigs[msg.sender] = PendingConfig({
            updateType: UpdateType.Replace,
            pendingUntil: block.timestamp + 2 days,
            configsHash: configsHash
        });
    }

    function addConfigs(
        bytes32 configsHash
    ) external NotInRecovering(msg.sender) {
        pendingConfigs[msg.sender] = PendingConfig({
            updateType: UpdateType.Append,
            pendingUntil: block.timestamp + 2 days,
            configsHash: configsHash
        });
    }

    function executeConfigsUpdate(
        address account,
        RecoveryConfigArg[] memory configArgs
    ) external NotInRecovering(account) {
        PendingConfig memory pending = pendingConfigs[account];
        require(block.timestamp > pending.pendingUntil, "Invalid time");
        require(
            keccak256(abi.encode(configArgs)) == pending.configsHash,
            "hash unmatched"
        );

        if (pending.updateType == UpdateType.Replace) {
            delete walletConfigs[account];
        }
        for (uint i = 0; i < configArgs.length; i++) {
            _addConfig(account, configArgs[i]);
        }
    }

    function _addConfig(
        address account,
        RecoveryConfigArg memory configArg
    ) internal {
        RecoveryConfig storage config = walletConfigs[account].push();
        config.policyVerifier = configArg.policyVerifier;

        for (uint i = 0; i < configArg.thresholdConfigs.length; i++) {
            config.thresholdConfigs.push(configArg.thresholdConfigs[i]);
        }
        for (uint i = 0; i < configArg.guardianInfos.length; i++) {
            bytes32 identityHash = keccak256(
                abi.encode(configArg.guardianInfos[i].guardian)
            );
            config.enabled = true;
            config.identityHashs.add(identityHash);
            config.guardianInfos[identityHash] = configArg.guardianInfos[i];
        }
    }

    function verifyPermissions(
        address account,
        uint256 configIndex,
        bytes32 digest,
        Permission[] memory permissions
    ) public returns (uint48) {
        RecoveryConfig storage config = walletConfigs[account][configIndex];
        require(config.enabled, "unenabled policy");

        bytes32[] memory identityHashs = new bytes32[](permissions.length);
        for (uint256 i = 0; i < permissions.length; i++) {
            if (permissions[i].guardian.signer.length == 0) {
                require(
                    SignatureChecker.isValidSignatureNow(
                        permissions[i].guardian.guardianVerifier,
                        digest,
                        permissions[i].signature
                    ),
                    "invalid signature"
                );
            } else {
                require(
                    IPermissionVerifier(
                        permissions[i].guardian.guardianVerifier
                    ).isValidPermission(
                            digest,
                            permissions[i].guardian.signer,
                            permissions[i].signature
                        ),
                    "invalid signature"
                );
            }

            identityHashs[i] = keccak256(abi.encode(permissions[i].guardian));
        }

        uint256 cumulatedWeight = 0;
        if (config.policyVerifier == address(0)) {
            for (uint256 i = 0; i < identityHashs.length; i++) {
                cumulatedWeight += config
                    .guardianInfos[identityHashs[i]]
                    .property;
                for (uint256 j = i + 1; j < identityHashs.length; j++) {
                    if (identityHashs[i] == identityHashs[j]) {
                        revert("duplicated guradian");
                    }
                }
            }
        } else {
            uint64[] memory properties = new uint64[](identityHashs.length);
            for (uint256 i = 0; i < identityHashs.length - 1; i++) {
                properties[i] += config
                    .guardianInfos[identityHashs[i]]
                    .property;
                for (uint256 j = i + 1; j < identityHashs.length; j++) {
                    if (identityHashs[i] == identityHashs[j]) {
                        revert("duplicated guradian");
                    }
                }
            }
            (bool succ, uint256 weight) = IRecoveryPolicyVerifier(
                config.policyVerifier
            ).verifyRecoveryPolicy(permissions, properties);
            require(succ, "failed permissions");
            cumulatedWeight += weight;
        }

        uint48 lockPeriod = type(uint48).max;
        for (uint i = 0; i < config.thresholdConfigs.length; i++) {
            if (cumulatedWeight >= config.thresholdConfigs[i].threshold) {
                lockPeriod = config.thresholdConfigs[i].lockPeriod;
                break;
            }
        }

        require(lockPeriod < type(uint48).max, "threshold unmatched");
        return lockPeriod;
    }

    // Generate EIP-712 message hash,
    // Iterate over signatures for verification,
    // Verify recovery policy,
    // Store temporary state or recover immediately based on the result.
    function startRecovery(
        address account,
        uint256 configIndex,
        bytes memory data,
        Permission[] memory permissions
    ) external NotInRecovering(account) {
        walletRecoveryNonce[account]++;
        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                domainSeparator(),
                keccak256(
                    abi.encode(
                        _START_RECOVERY_TYPEHASH,
                        account,
                        data,
                        walletRecoveryNonce[account]
                    )
                )
            )
        );

        uint48 lockPeriod = verifyPermissions(
            account,
            configIndex,
            digest,
            permissions
        );
        if (lockPeriod == 0) {
            ISafe(account).execTransactionFromModule(account, 0, data, 0);
            emit RecoveryExecuted(account, data, walletRecoveryNonce[account]);
        } else {
            RecoveryEntry memory entry;
            entry.data = data;
            entry.nonce = walletRecoveryNonce[account];
            entry.executeAfter = uint48(block.timestamp) + lockPeriod;

            recoveryEntries[account] = entry;
        }
    }

    /**
     * @dev Execute recovery
     * temporary state -> ownerKey rotation
     */
    function executeRecovery(address account) external InRecovering(account) {
        require(
            recoveryEntries[account].executeAfter < block.timestamp,
            "locking"
        );
        ISafe(account).execTransactionFromModule(
            account,
            0,
            recoveryEntries[account].data,
            0
        );
        emit RecoveryExecuted(
            account,
            recoveryEntries[account].data,
            recoveryEntries[account].nonce
        );
        delete recoveryEntries[account];
    }

    function cancelRecovery(address account) external InRecovering(account) {
        emit RecoveryCanceled(account, recoveryEntries[account].nonce);
        delete recoveryEntries[account];
    }

    function cancelRecoveryByGuardians(
        address account,
        uint256 configIndex,
        Permission[] memory permissions
    ) external InRecovering(account) {
        walletRecoveryNonce[account]++;
        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                domainSeparator(),
                keccak256(
                    abi.encode(
                        _CANCEL_RECOVERY_TYPEHASH,
                        account,
                        walletRecoveryNonce[account]
                    )
                )
            )
        );

        verifyPermissions(account, configIndex, digest, permissions);

        emit RecoveryCanceled(account, recoveryEntries[account].nonce);
        delete recoveryEntries[account];
    }

    /**
     * @dev Get wallet recovery info, recovery config, check if an identity is a guardian, get the nonce of social recovery, and get the recovery status of the wallet
     */
    function isGuardian(
        address account,
        Identity memory guardian
    ) public view returns (bool) {
        RecoveryConfig[] storage configs = walletConfigs[account];
        bytes32 guardianHash = keccak256(abi.encode(guardian));
        for (uint256 i = 0; i < configs.length; i++) {
            bool exist = configs[i].identityHashs.isExist(guardianHash);
            if (exist) {
                return true;
            }
        }

        return false;
    }

    function getRecoveryConfigs(
        address account
    ) public view returns (RecoveryConfigArg[] memory configArgs) {
        RecoveryConfig[] storage configs = walletConfigs[account];
        configArgs = new RecoveryConfigArg[](configs.length);
        for (uint256 i = 0; i < configs.length; i++) {
            RecoveryConfigArg memory configArg;
            bytes32[] memory identityHashs = configs[i].identityHashs.list(
                HashLinkedList.SENTINEL_HASH,
                configs[i].identityHashs.size()
            );

            for (uint256 j = 0; j < identityHashs.length; j++) {
                configArg.guardianInfos = new GuardianInfo[](
                    identityHashs.length
                );
                configArg.guardianInfos[j] = configs[i].guardianInfos[
                    identityHashs[j]
                ];
            }
            configArg.policyVerifier = configs[i].policyVerifier;
            configArg.thresholdConfigs = configs[i].thresholdConfigs;
            configArgs[i] = configArg;
        }
    }

    function getRecoveryNonce(
        address account
    ) public view returns (uint256 nonce) {
        return walletRecoveryNonce[account];
    }

    function getRecoveryStatus(
        address account
    ) public view returns (bool isRecovering, uint48 expiryTime) {
        RecoveryEntry memory status = recoveryEntries[account];
        isRecovering = status.executeAfter > 0 ? true : false;
        expiryTime = uint48(status.executeAfter);
    }
}
