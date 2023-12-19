// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "forge-std/console2.sol";
import "../src/RecoveryModule.sol";
import "../src/test/TestAccount.sol";
import "../src/TypesAndDecoders.sol";
import "../src/interfaces/IPermissionVerifier.sol";
import "../src/verifier/openid/OpenIDVerifier.sol";

import "@safe-global/safe-contracts/contracts/Safe.sol";
import "@safe-global/safe-contracts/contracts/proxies/SafeProxyFactory.sol";

contract OpenIDSocialRecoveryTest is Test {
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
    OpenIDVerifier _verifier;

    uint256 _owner;
    address _ownerAddr;

    uint256 _newOwner;
    address _newOwnerAddr;

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
        _factory = new SafeProxyFactory();
        _accountImpl = new TestAccount();

        _admin = 0x99;
        _adminAddr = vm.addr(_admin);
        vm.startPrank(_adminAddr);
        _verifier = new OpenIDVerifier();
        _verifier.addOpenIDAudience(
            keccak256(abi.encodePacked("test_issuer", "test_aud"))
        );
        _verifier.updateOpenIDPublicKey(
            keccak256(abi.encodePacked("test_issuer", "test_kid")),
            hex"d1b83f8a96f95e42651b74bd506dc6f6e91f1da5efcc4751c9d5c4973ba3654f1ebfc5b4d3e1a75d05f90050a0c8c69f95fe9cf95d33005c2ce50141e8af13406d668f0f587e982e723c48f63a15435c70913856345d34bd05ff9d4854cb106d51d5294372550e742ef89372e77c94b5bf46d9216ddfd13646a3ba0d06d33f8b81e10c7b8864d314028a7ba74227dc5dd9c1828ce06bedaa0d58c5200c7c13c4581c8578a4504dfc6763039af65ff231651a03fe069a3e4f15800bc52f87a075007efd63b9d761fc9b1029ea6f04b2c3fc240cd69519c0e74df6166345bc30e9c5a23b1f929d7d065f91ce12d3c0377212d78a309add8c70a3b56b922814dd83"
        );
        vm.stopPrank();

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
        thresholdConfig1.threshold = uint64(_threshold);
        thresholdConfig1.lockPeriod = uint48(_lockPeriod);
        configArg.thresholdConfigs.push(thresholdConfig1);

        {
            GuardianInfo memory guardian;
            Identity memory id;
            id.guardianVerifier = address(_verifier);
            id.signer = abi.encodePacked(
                keccak256(
                    abi.encodePacked(
                        keccak256("test_issuer"),
                        keccak256("test_user1")
                    )
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
                keccak256(
                    abi.encodePacked(
                        keccak256("test_issuer"),
                        keccak256("test_user2")
                    )
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
                keccak256(
                    abi.encodePacked(
                        keccak256("test_issuer"),
                        keccak256("test_user3")
                    )
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

    function testOpenIDInstantRecovery() public {
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
            id.guardianVerifier = configArg
                .guardianInfos[0]
                .guardian
                .guardianVerifier;
            id.signer = configArg.guardianInfos[0].guardian.signer;
            permissions[0].guardian = id;
            permissions[0]
                .signature = hex"0000003b00000046000000160000001e0000004f00000059000000620000006a0000007500000007000000180000002c7b22616c67223a225253323536222c226b6964223a22746573745f6b6964222c22747970223a224a5754227d000000b97b22696174223a313730323938323137382c22657870223a313730333036383537382c226e6266223a313730323938323137382c22697373223a22746573745f697373756572222c22737562223a22746573745f7573657231222c22617564223a22746573745f617564222c226e6f6e6365223a22307830313166616439346233336564666630303866393636633933633662616235336132343436383238623566303932343637303332336164306666303563336331227d0000010041a4b10600ca7472fb9691b140c4f45d9bb9be5ff2786664648a792ae6ef82f1d2eefc66aae89f5a3af46e8bc7cb8ee340c33f78239e50ce56e55346dc14f3137e54daf7a3b0122ca433bebbfe1e40903e7b0636826cc4eeccba38fc48d75386864503a0f0f5a854fd10632997bb93bfc81b420c60bb781d94eca5cdc4985b8e15533e7cc0dfdfec352623142cb317bc91d9f938ecea9dabb3f8a37f69836eaf33b8c3d800bbdce80f7a29a02dbf3c87bc09d34fb4c0fd07eb46830391a7b3c594290e3562510db1a7f51f8530f2a5073223c36b191b26cb3ba08d30970637fb382728762598c036b3d9a89695689c9f8c5b0fd56bc2857f31f752983fd47791";
        }
        {
            Identity memory id;
            id.guardianVerifier = configArg
                .guardianInfos[1]
                .guardian
                .guardianVerifier;
            id.signer = configArg.guardianInfos[1].guardian.signer;
            permissions[1].guardian = id;
            permissions[1]
                .signature = hex"0000003b00000046000000160000001e0000004f00000059000000620000006a0000007500000007000000180000002c7b22616c67223a225253323536222c226b6964223a22746573745f6b6964222c22747970223a224a5754227d000000b97b22696174223a313730323938323138312c22657870223a313730333036383538312c226e6266223a313730323938323138312c22697373223a22746573745f697373756572222c22737562223a22746573745f7573657232222c22617564223a22746573745f617564222c226e6f6e6365223a22307830313166616439346233336564666630303866393636633933633662616235336132343436383238623566303932343637303332336164306666303563336331227d000001001449f4c36979a3d4bda9b440370561fa97aa569c328b8e229088ee250510a13ed7720bb40ae82ef90235d160da4663b85b1c02c19108f1c440f14bc6ec005a0f680ff715f2954eb15d18c11940080c755d060b5dc0a3608b1cddcd10b1a30bc5c1a2128d7a1109b99c9cd6995e24493e04f7852a5e9e2e24f79f1b3246133b7aee69c9d933fbe72e0f04ebfcf185ea7b0055477aa168c6f220e530ad23355b7b247bf8a2d1d21c1fb6875af8859cfbb8fdceea5c22116dbeb750b0e48cde9ee88fdfec73a2e0e69b4b7651b5b30dd9f3cd54f4f286efda322c31e1d4cecc74b7aa2edf9ce24df87b4b5cb871217ca6356d358634a92db4a320f912452a3ca26a";
        }
        {
            Identity memory id;
            id.guardianVerifier = configArg
                .guardianInfos[2]
                .guardian
                .guardianVerifier;
            id.signer = configArg.guardianInfos[2].guardian.signer;
            permissions[2].guardian = id;
            permissions[2]
                .signature = hex"0000003b00000046000000160000001e0000004f00000059000000620000006a0000007500000007000000180000002c7b22616c67223a225253323536222c226b6964223a22746573745f6b6964222c22747970223a224a5754227d000000b97b22696174223a313730323938323138332c22657870223a313730333036383538332c226e6266223a313730323938323138332c22697373223a22746573745f697373756572222c22737562223a22746573745f7573657233222c22617564223a22746573745f617564222c226e6f6e6365223a22307830313166616439346233336564666630303866393636633933633662616235336132343436383238623566303932343637303332336164306666303563336331227d000001002cbf36e014c8fe215e2bc3fca77c3a485d4cacea956370763ad9e9c2600cfe90df45f162479a4792c521154f46080eb5388c956a862fe81569298caac0b9673d4e6818f62e78da9a304e2f6aeae4219061f99f7c74877c41287c44afab5a723a854da5c02ca58bc8e4af99a2f1b666960ff62f34593e44abd728da2aa82db519a355b1a9d6868fb2670d1ef68c6d28bf97e2444b65cf0f4228f138c6d132be22fc786f51a6f877dccde3e54ec70cda5e1f3e30b82d750b716f86f4aa6cb884ca4fe5b43e0d27ab9ba39228898760a4409e5a5befe53bd716fcffe18b1d3520bfabf967f16b5189f337f4c3833f00aa5281b8ce5892d130f362335669f5a1e51c";
        }

        vm.warp(1702983183);
        _recoveryModule.startRecovery(address(_account), 0, data, permissions);
    }
}
