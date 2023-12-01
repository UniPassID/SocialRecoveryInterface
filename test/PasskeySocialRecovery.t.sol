// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "forge-std/console2.sol";
import "../src/RecoveryModule.sol";
import "../src/test/TestAccount.sol";
import "../src/TypesAndDecoders.sol";
import "../src/interfaces/IPermissionVerifier.sol";
import "../src/verifier/passkey/PasskeyVerifier.sol";

import "@safe-global/safe-contracts/contracts/Safe.sol";
import "@safe-global/safe-contracts/contracts/proxies/SafeProxyFactory.sol";

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
    SafeProxyFactory _factory;
    TestAccount _accountImpl;
    ISafe _account;
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
        _factory = new SafeProxyFactory();
        _accountImpl = new TestAccount();
        _verifier = new PasskeyVerifier();

        _owner = 0x100;
        _ownerAddr = vm.addr(_owner);

        address[] memory owners = new address[](1);
        owners[0] = _ownerAddr;

        bytes memory initializer = abi.encodeCall(
            Safe.setup,
            (
                owners,
                1,
                address(0),
                hex"",
                address(0),
                address(0),
                0,
                payable(address(0))
            )
        );

        _account = ISafe(
            address(
                _factory.createProxyWithNonce(
                    address(_accountImpl),
                    initializer,
                    0
                )
            )
        );

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
                    0xe15686f67d66539c05f8421a546072575a5a640c3080d7a4afd611676b25400e
                ),
                uint256(
                    0x79596a6fef33c07461a944fa8a199665b52810557aaa1a99be4e85b9c8c95562
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
                    0xf2b0a2eb4a88cf7743460dda473a5a3e08c5c6db63f3ebd82c1c4a6bd6761f91
                ),
                uint256(
                    0xa490c09076f43dc7fc91cab46568ef9f660ec9f684fb64343bb36a91e82c4693
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
                    0x34160c417cef5ef9a1c3b7950fe1bb78ca4ffbb727cd4726df4a732557fee5e9
                ),
                uint256(
                    0x62c94c2d5357bfb3ebff9db5541d17a0e94d757d6581455fd73e8c624dc74f77
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
                .signature = hex"32098de0f6585491bce967d578db5fc17ec7f11e0f0a298c0c299778fce4325047d57dfe4ca9f3d4e3f7802635af17efaf781d7df09b3c06ca884655f1349c4900000025d636379c6ca019fe4b03b02a66222c9ce4526a3a3a22ed464ee63b50dda27ef61d00000000000000247b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a2200000026222c226f726967696e223a2268747470733a2f2f706173736b65792e746573742e636f6d227d";
        }
        {
            Identity memory id;
            id.guardianVerifier = address(_verifier);
            id.signer = configArg.guardianInfos[1].guardian.signer;
            permissions[1].guardian = id;
            permissions[1]
                .signature = hex"8bc63a15d927fafd15920576c2430e7fea3611cae0182d5d0b24e00d7abb713957fb4f839b9e827365f4265890580501294b62d4bcbca30e9e87b11fdbc04a9900000025d636379c6ca019fe4b03b02a66222c9ce4526a3a3a22ed464ee63b50dda27ef61d00000000000000247b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a2200000026222c226f726967696e223a2268747470733a2f2f706173736b65792e746573742e636f6d227d";
        }
        {
            Identity memory id;
            id.guardianVerifier = address(_verifier);
            id.signer = configArg.guardianInfos[2].guardian.signer;
            permissions[2].guardian = id;
            permissions[2]
                .signature = hex"1aac4cdc48dd1473d4ce11ee5af58ae380aefc1f580d1a1883bfa36841195de695accaa2cc3d3dde8e80a0d50ceeda8c829f877159dada8011c22c9414903eb700000025d636379c6ca019fe4b03b02a66222c9ce4526a3a3a22ed464ee63b50dda27ef61d00000000000000247b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a2200000026222c226f726967696e223a2268747470733a2f2f706173736b65792e746573742e636f6d227d";
        }

        _recoveryModule.startRecovery(address(_account), 0, data, permissions);
    }

    function testPasskeyTimelockRecovery() public {}
}
