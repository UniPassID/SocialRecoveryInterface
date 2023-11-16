// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "forge-std/console2.sol";
import "../src/RecoveryModule.sol";
import "../src/test/SimpleAccount.sol";
import "../src/TypesAndDecoders.sol";
import "../src/interfaces/IPermissionVerifier.sol";
import "../src/verifier/passkey/PasskeyVerifier.sol";

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
    uint256 _admin;
    address _adminAddr;

    RecoveryConfigArg configArg;
    uint256 _guardianCount;
    uint256 _threshold;
    uint256 _lockPeriod;

    function setUp() public {
        _guardianCount = 3;
        _threshold = 2;
        _lockPeriod = 1024;
        _recoveryModule = new RecoveryModule();

        _admin = 0x99;
        _adminAddr = vm.addr(_admin);
        vm.startPrank(_adminAddr);
        _verifier = new PasskeyVerifier();
        vm.stopPrank();

        _owner = 0x100;
        _ownerAddr = vm.addr(_owner);

        vm.startPrank(_ownerAddr);
        _account = new SimpleAccount();
        _account.authorizeModule(address(_recoveryModule));
        vm.stopPrank();

        vm.startPrank(address(_account));

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
                    25439812940730053386580936542891364417474020294652604502369156242031282984427
                ),
                uint256(
                    92459717555669712015170072192226755241821920400613365299576471803361698190492
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
                    0x03c145628175069d7702d27871c96ce8b1130f05a7e1c9de5679f498a36548a7
                ),
                uint256(
                    0x70827bc7393555c30e2dbffd8fb8679ff7e2fde05866661b69a6c789f26ade85
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
                    0xd7c9c9a325909eeb869a2791fac44e26bd269ece82490934c845a5c97dd08527
                ),
                uint256(
                    0xe4a15ba25107f05c8c22ac1d7b560f59cc7ae657d88f41b9c3ae89f4b6c5cf43
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
        _owner = 0x101;
        _ownerAddr = vm.addr(_owner);

        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                domainSeparator(),
                keccak256(
                    abi.encode(
                        _START_RECOVERY_TYPEHASH,
                        address(_account),
                        abi.encodePacked(_ownerAddr),
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
                .signature = hex"b95b9740ccb3694f551ce4f6fd0f5aa94385d0a9ef6858a0d008de9b160bd94890d9fb8a429de8eb7c9f16ccd488c6d7b60c32126d3d181552cb21c1a351e87f00000025a379a6f6eeafb9a55e378c118034e2751e682fab9f2d30ab13d2125586ce19470500000000000000247b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a2200000021222c226f726967696e223a2268747470733a2f2f6578616d706c652e636f6d227d";
        }
        {
            Identity memory id;
            id.guardianVerifier = address(_verifier);
            id.signer = configArg.guardianInfos[1].guardian.signer;
            permissions[1].guardian = id;
            permissions[1]
                .signature = hex"9312ecb5cb31606fa2b35a4bcacd24a9330d26441a9cc36a1e45e337d785ba68fbf947d8a568f4d39ca6b559d0da48e53c4eae0b10a1346c5c4910d1888b0cb20000002582edcf1a363de8c1491dea3ed6e5f62b3decae93f836ba27c839bac52ab641f41d00000000000000247b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a2200000025222c226f726967696e223a2268747470733a2f2f6675747572652e746573742e636f6d227d";
        }
        {
            Identity memory id;
            id.guardianVerifier = address(_verifier);
            id.signer = configArg.guardianInfos[2].guardian.signer;
            permissions[2].guardian = id;
            permissions[2]
                .signature = hex"13f2dc83d280dcfc0c05bcc20896e80749b843d8edf1f35f989f6ffcd1a336c2bacb789be9c2cb9a8e0e4bce90d7b05d46b250cf10f62b380978ccd854fbd6cc0000002582edcf1a363de8c1491dea3ed6e5f62b3decae93f836ba27c839bac52ab641f41d00000000000000247b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a2200000025222c226f726967696e223a2268747470733a2f2f6675747572652e746573742e636f6d227d";
        }

        vm.warp(1699582162);
        _recoveryModule.startRecovery(
            address(_account),
            0,
            abi.encodePacked(_ownerAddr),
            permissions
        );
    }
}
