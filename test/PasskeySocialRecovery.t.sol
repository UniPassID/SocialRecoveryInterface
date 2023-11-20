// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "forge-std/console2.sol";
import "../src/RecoveryModule.sol";
import "../src/test/SimpleAccount.sol";
import "../src/TypesAndDecoders.sol";
import "../src/interfaces/IPermissionVerifier.sol";
import "../src/verifier/passkey/PasskeyVerifier.sol";

import "@safe-global/safe-contracts/contracts/Safe.sol";

contract PasskeySocialRecoveryTest is Test {
    // keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 private constant _DOMAIN_SEPARATOR_TYPEHASH =
        0x8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f;

    bytes32 internal constant _START_RECOVERY_TYPEHASH =
        keccak256(
            "startRecovery(address account,bytes newOwner,uint256 nonce)"
        );

    bytes32 internal constant _CANCEL_RECOVERY_TYPEHASH =
        keccak256("cancelRecovery(address account,uint256 nonce)");

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
                    keccak256(abi.encodePacked("Recovery Module")),
                    keccak256(abi.encodePacked("0.0.1")),
                    getChainID(),
                    address(_recoveryModule)
                )
            );
    }

    RecoveryModule _recoveryModule;
    SimpleAccount _account;
    PasskeyVerifier _verifier;

    uint256 _owner;
    address _ownerAddr;

    uint256 _newOwner;
    address _newOwnerAddr;

    RecoveryConfigArg configArg;
    uint256 _guardianCount;
    uint256 _threshold;
    uint256 _lockPeriod;

    function setUp() public {
        _guardianCount = 3;
        _threshold = 2;
        _lockPeriod = 1024;
        _recoveryModule = new RecoveryModule();
        _verifier = new PasskeyVerifier();

        _owner = 0x100;
        _ownerAddr = vm.addr(_owner);

        vm.startPrank(_ownerAddr);
        _account = new SimpleAccount();
        vm.stopPrank();

        vm.startPrank(address(_account));
        _account.enableModule(address(_recoveryModule));

        ThresholdConfig memory thresholdConfig0;
        thresholdConfig0.threshold = uint64(_guardianCount);
        thresholdConfig0.lockPeriod = 0;
        configArg.thresholdConfigs.push(thresholdConfig0);

        ThresholdConfig memory thresholdConfig1;
        thresholdConfig0.threshold = uint64(_threshold);
        thresholdConfig0.lockPeriod = uint48(_lockPeriod);
        configArg.thresholdConfigs.push(thresholdConfig1);

        {
            GuardianInfo memory guardian;
            Identity memory id;
            id.guardianVerifier = address(_verifier);
            id.signer = abi.encodePacked(
                uint256(
                    0x17da6df3f5c2caee96b41e7bfd2aac174a3a1aae72d782cfe865df8c906a6b9f
                ),
                uint256(
                    0x141ef6bdfd992485fefbf717b02c1056adfbaf0899bdc7de983792be1a3a2307
                )
            );
            guardian.guardian = id;
            guardian.property = 1;
            configArg.guardianInfos.push(guardian);
        }
        {
            GuardianInfo memory guardian;
            Identity memory id;
            id.guardianVerifier = address(_verifier);
            id.signer = abi.encodePacked(
                uint256(
                    0x682bac82404a56771b9e98bd2d7c8588b79c0e9e6561cf4183e00e46d3f33f34
                ),
                uint256(
                    0x4af574a0e75912bf71f89362fd2859f77ce51cb202eae146c36469f271f446ae
                )
            );
            guardian.guardian = id;
            guardian.property = 1;
            configArg.guardianInfos.push(guardian);
        }
        {
            GuardianInfo memory guardian;
            Identity memory id;
            id.guardianVerifier = address(_verifier);
            id.signer = abi.encodePacked(
                uint256(
                    0x01ecee6992c9027b52883a91d2122fc95450e1611c55a71aee7f7abb1afccb89
                ),
                uint256(
                    0xa44f219c8b933e0beece8cbb068f5c6a003326df81c0ecbb7f736a3a1add030c
                )
            );
            guardian.guardian = id;
            guardian.property = 1;
            configArg.guardianInfos.push(guardian);
        }

        RecoveryConfigArg[] memory configArgs = new RecoveryConfigArg[](1);
        configArgs[0] = configArg;
        bytes32 configsHash = keccak256(abi.encode(configArgs));
        _recoveryModule.addConfigs(configsHash);

        vm.warp(block.timestamp + 3 days);
        _recoveryModule.executeConfigsUpdate(address(_account), configArgs);
        vm.stopPrank();

        console2.log("domainSeparator: ");
        console2.logBytes32(domainSeparator());
    }

    function testPasskeyInstantRecovery() public {
        _newOwner = 0x101;
        _newOwnerAddr = vm.addr(_newOwner);
        bytes memory data = abi.encodeCall(
            OwnerManager.swapOwner,
            (address(0x1), _ownerAddr, _newOwnerAddr)
        );

        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                domainSeparator(),
                keccak256(
                    abi.encode(
                        _START_RECOVERY_TYPEHASH,
                        address(_account),
                        data,
                        _recoveryModule.walletRecoveryNonce(address(_account)) +
                            1
                    )
                )
            )
        );

        console2.log("digest: ");
        console2.logBytes32(digest);

        Permission[] memory permissions = new Permission[](_guardianCount);
        {
            Identity memory id;
            id.guardianVerifier = address(_verifier);
            id.signer = configArg.guardianInfos[0].guardian.signer;
            permissions[0].guardian = id;
            permissions[0]
                .signature = hex"e48098479197df113edf144d365cf254d7c4b0ed78b4561cbd0e3fad8e6808a5422bcab90f93a5460a92ced0ed69730bef27b240e5174dbace5eb8f63cb2fbec0000002582edcf1a363de8c1491dea3ed6e5f62b3decae93f836ba27c839bac52ab641f41d00000000000000247b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a2200000025222c226f726967696e223a2268747470733a2f2f6675747572652e746573742e636f6d227d";
        }
        {
            Identity memory id;
            id.guardianVerifier = address(_verifier);
            id.signer = configArg.guardianInfos[1].guardian.signer;
            permissions[1].guardian = id;
            permissions[1]
                .signature = hex"6e7de4bdf2c8be420a03767bcc44bbcb5d9163c60a3ba1b9df7431b6e51740449c70b612d70bbc5dc5b204fde89bd487379e6abf87941b0dd679be7fb5e8a80a0000002582edcf1a363de8c1491dea3ed6e5f62b3decae93f836ba27c839bac52ab641f41d00000000000000247b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a2200000025222c226f726967696e223a2268747470733a2f2f6675747572652e746573742e636f6d227d";
        }
        {
            Identity memory id;
            id.guardianVerifier = address(_verifier);
            id.signer = configArg.guardianInfos[2].guardian.signer;
            permissions[2].guardian = id;
            permissions[2]
                .signature = hex"dc43c65b016264e08c3c3c5cfa6afb5f10a812a9e7ed04747e252db676f92eea51a0ce047c48da4d318ba079bb089f5fe8da63a2cfe4468181653a042058ec640000002582edcf1a363de8c1491dea3ed6e5f62b3decae93f836ba27c839bac52ab641f41d00000000000000247b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a2200000025222c226f726967696e223a2268747470733a2f2f6675747572652e746573742e636f6d227d";
        }

        _recoveryModule.startRecovery(address(_account), 0, data, permissions);
    }
}
