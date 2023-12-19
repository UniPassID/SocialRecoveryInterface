// SPDX-License-Identifier: LGPL-3.0-only
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
                    0xea67eef7967ed7f362fae4ee98336aee097a999bdf7cc580db1f945b9439f17a
                ),
                uint256(
                    0x16b339cc67ac3f78aabd85db0d29b47355588921b167434e2ce5784112818a97
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
                    0x9727212cfb34abd3e60d59074ab49f8455fd001ec67f3e3b0e8af6f5fa17b0bf
                ),
                uint256(
                    0x14567f015a8a88b1fd50b7272791d6190187cc4da46d9a0f7d49a22af25a4097
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
                    0x2b524330d507d6d91d1151def4181a86edb078c300b862fb1d3ef51a24cd2d25
                ),
                uint256(
                    0x7028f9c0043341edfe6ba9980edbf3e050b5e44af1268145eac181b9293f5343
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
                .signature = hex"1cf8f08f5f84e301bf3717a13f0251bb88c383350ec9ce71b297c8a0029f93f9b4d12863fd96ae06999da0fa6354fbecc77442f484541d555023da6a0c29ba7700000025d636379c6ca019fe4b03b02a66222c9ce4526a3a3a22ed464ee63b50dda27ef61d00000000000000247b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a2200000026222c226f726967696e223a2268747470733a2f2f706173736b65792e746573742e636f6d227d";
        }
        {
            Identity memory id;
            id.guardianVerifier = address(_verifier);
            id.signer = configArg.guardianInfos[1].guardian.signer;
            permissions[1].guardian = id;
            permissions[1]
                .signature = hex"e69f65c505be51990831bcf652106ef8743862d65a2225ee3737b847a140a0ef10d556b1e5649ad21afdde109f7abc542951409c907e6ba2415aedab64ca492600000025d636379c6ca019fe4b03b02a66222c9ce4526a3a3a22ed464ee63b50dda27ef61d00000000000000247b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a2200000026222c226f726967696e223a2268747470733a2f2f706173736b65792e746573742e636f6d227d";
        }
        {
            Identity memory id;
            id.guardianVerifier = address(_verifier);
            id.signer = configArg.guardianInfos[2].guardian.signer;
            permissions[2].guardian = id;
            permissions[2]
                .signature = hex"26988b571271cd4286676cce1d286b498f05a2a81dc38e67a624bff60164ce6fff7b6d43700901b18131ce155d480e8157da02169d03b0ed7fc7655677a8e42c00000025d636379c6ca019fe4b03b02a66222c9ce4526a3a3a22ed464ee63b50dda27ef61d00000000000000247b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a2200000026222c226f726967696e223a2268747470733a2f2f706173736b65792e746573742e636f6d227d";
        }

        _recoveryModule.startRecovery(address(_account), 0, data, permissions);
    }

    function testPasskeyTimelockRecovery() public {}
}
