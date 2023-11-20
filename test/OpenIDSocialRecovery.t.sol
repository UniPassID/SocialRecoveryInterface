// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "forge-std/console2.sol";
import "../src/RecoveryModule.sol";
import "../src/test/SimpleAccount.sol";
import "../src/TypesAndDecoders.sol";
import "../src/interfaces/IPermissionVerifier.sol";
import "../src/verifier/openid/OpenIDVerifier.sol";

import "@safe-global/safe-contracts/contracts/Safe.sol";

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
    SimpleAccount _account;
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
                .signature = hex"0000003b00000046000000160000001e0000004f00000059000000620000006a0000007500000007000000180000002c7b22616c67223a225253323536222c226b6964223a22746573745f6b6964222c22747970223a224a5754227d000000b97b22696174223a313730303439343236302c22657870223a313730303538303636302c226e6266223a313730303439343236302c22697373223a22746573745f697373756572222c22737562223a22746573745f7573657231222c22617564223a22746573745f617564222c226e6f6e6365223a22307838666133373231663461373661346439386165383766343661353636326262393237313436316665313766393739316464313164393966663065343963323636227d000001005241f6050b084b3908ae72d2c7f2709cbc1faf9bca2a8179a4749c513d9532071959b1ede5aa3f1178f3c83897aa636edb6b0342e5156f6eaf3533e3986372100fba1c6a2125cf5f239e8835531a8caafc60d1e07ad23475a92644a9c890d237569328a6746832a81cadc102dce32703cd762ac0ac16aaa19ae69b7452edb63033141b235bc93496687cf0fc040d8908c9dedbda6cd8a25e62bdfb5f02f392c93ebfb6376e8185d46698d7326d2c6d04d1b80132437cf87805c74288553ba4dd3b7a1fdad58ac0c5d1e177d25cacf4b016c631427cd040e96b5f7dce861b7799c071bc4afa36c1ce1fad067b90ca89565b408626e4a31a7c1a5705043f647778";
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
                .signature = hex"0000003b00000046000000160000001e0000004f00000059000000620000006a0000007500000007000000180000002c7b22616c67223a225253323536222c226b6964223a22746573745f6b6964222c22747970223a224a5754227d000000b97b22696174223a313730303439343232342c22657870223a313730303538303632342c226e6266223a313730303439343232342c22697373223a22746573745f697373756572222c22737562223a22746573745f7573657232222c22617564223a22746573745f617564222c226e6f6e6365223a22307838666133373231663461373661346439386165383766343661353636326262393237313436316665313766393739316464313164393966663065343963323636227d00000100b86007187560a398b28dcfecf6ab772da523625875c28e97556d331d50be8ed23feb697a9fbf7a204db47f0f0b7a92cde7706c2d2f8a8d728997023dfdd3b36e808051716358d18d94de4ae70680f69ea8c35d76d00687f6e380cebe96c3dbd12b1a3a15a9f1358763c709bfc7defdce4470fd792f488d6b33aec8dd0d53c60901c79d289f28b1b0e8d7235005080356d42c63b88f670160f3f3184d07ad4a3053b1c5bc838f09cbcac612491ee1e05c99e895f7c21f89990d5b97df4bbd98c9dca7f2331eabce7f066f8ecc97ad5a1cbd4061b5083f2cfdf1167efd2c2641cb05ead7fc9fc75485634a26ca51cc9cab2dd754fbe1d3ae724b7ad77a834e70ba";
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
                .signature = hex"0000003b00000046000000160000001e0000004f00000059000000620000006a0000007500000007000000180000002c7b22616c67223a225253323536222c226b6964223a22746573745f6b6964222c22747970223a224a5754227d000000b97b22696174223a313730303439343233372c22657870223a313730303538303633372c226e6266223a313730303439343233372c22697373223a22746573745f697373756572222c22737562223a22746573745f7573657233222c22617564223a22746573745f617564222c226e6f6e6365223a22307838666133373231663461373661346439386165383766343661353636326262393237313436316665313766393739316464313164393966663065343963323636227d000001000c04288e9de29c49ef5ad07c4dbd9c27d2d16d69345ff380c649dae056cc66b00f584d553759afc1f4988a2075073f0c4b4450ac875883e5c604e2d750b5efd23800f55e15f2dad219b5ee5ec3278b72c561a45c7f087b63c6d04804c7d11fd035ad0b05322a53f96d2b347876c30b80a89adabd4874e8e6b4ca178baddc2ca12563b6bfbbd537178e96ae884056db37d4bc9b813a001740bfb2ddecf6d19c0c8f817630dbe3752db5fe2784180bf644fbbfec7eeaf2d258ffc49294b03bb6b09c7c97a9e8118078af5c68f4a81236585ed7cde8aa6f068b43d9db91bcbd981a20b5cbbd91b69a44f85ae4bb3be51c6c2fb4f69a1d0b63e4b15c3832d555dd54";
        }

        vm.warp(1700495260);
        _recoveryModule.startRecovery(address(_account), 0, data, permissions);
    }
}
