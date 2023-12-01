// SPDX-License-Identifier: UNLICENSED
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
                .signature = hex"0000003b00000046000000160000001e0000004f00000059000000620000006a0000007500000007000000180000002c7b22616c67223a225253323536222c226b6964223a22746573745f6b6964222c22747970223a224a5754227d000000b97b22696174223a313730313333353333332c22657870223a313730313432313733332c226e6266223a313730313333353333332c22697373223a22746573745f697373756572222c22737562223a22746573745f7573657231222c22617564223a22746573745f617564222c226e6f6e6365223a22307832343930666432343839656438646138646531653538633536613265306662343030666237363530313362623030306131303435366634353266663131333834227d00000100aa37ac3818210fc00ee48c31842ea8fea212768acb817833f480e9224f3fa958cee6e12cd5c8a1a8ba7dcc98c76f53c750a7f3b9144f6fcd1e8dc8ddffa011ca756c434a0534165276a099b51e99f8f6921c06f07e086bb846e87e9bff21fc09933d466fc3fb6916620e058d5ed5c963ecf5ccaf52169e7704bace8289148557314b5ed2932b0c6ffc59c8a7ea2baf8b8f7cb906d8bc5cfcd0836332e3107bfb5e79b18166466494e77e34dde0b26b92935686067121fe0cd29f39705b7654c7b6e6839a3a9a56dd73440e3c9a86d99c5481f5606851948b1e25daba7062888778b94a762d644be393906ade52d9391ba1918e1c527953b8ce032c3067ea526a";
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
                .signature = hex"0000003b00000046000000160000001e0000004f00000059000000620000006a0000007500000007000000180000002c7b22616c67223a225253323536222c226b6964223a22746573745f6b6964222c22747970223a224a5754227d000000b97b22696174223a313730313333353334382c22657870223a313730313432313734382c226e6266223a313730313333353334382c22697373223a22746573745f697373756572222c22737562223a22746573745f7573657232222c22617564223a22746573745f617564222c226e6f6e6365223a22307832343930666432343839656438646138646531653538633536613265306662343030666237363530313362623030306131303435366634353266663131333834227d00000100a3993eef4562cc1541dad9b292e392af41ae50babb3158c8be3b6ec1c0ff63c48dfd542bd23ed65f261e9de5bec530c67c1bf2e64c0de164e315a33e346f78c22911be41cee4995f28a2b867dd1504ddc37ac0fd39dbad72fd55b2679634ddc17f952091d617151ee86226dbad15dd23911825d393f29fb3b36448054b58d62f3654bd5d036587e195ebbc6db5c0c5b49f4515d9bbf55ce007fa1ca8ccc1c5097ad1e55bf45c6163ff809016a752bbd14b7fabd8541651611a7de0712f13a2593079d79546e170370a40981301ae9c90d5a812a6750aead8a9d53ab5f6c9198428edc0301420bf23a8d2d0bfcdbd576da66ca487bd338c2f3727e4f38631a954";
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
                .signature = hex"0000003b00000046000000160000001e0000004f00000059000000620000006a0000007500000007000000180000002c7b22616c67223a225253323536222c226b6964223a22746573745f6b6964222c22747970223a224a5754227d000000b97b22696174223a313730313333353336322c22657870223a313730313432313736322c226e6266223a313730313333353336322c22697373223a22746573745f697373756572222c22737562223a22746573745f7573657233222c22617564223a22746573745f617564222c226e6f6e6365223a22307832343930666432343839656438646138646531653538633536613265306662343030666237363530313362623030306131303435366634353266663131333834227d000001009b9fbd52e979b9867065e6709474c190cb95a2d0df3cd8be09fa53eec307c40588222a23d955cf54246c614f0ae99da905e01fc98697e9fc8fde97d7c6b5950140c8d235ed97f620d4b7aeebdf7eb9da914cbe4951c0aaacb1502c415abdd2a340164cc341a4d766c7e31937c20a673eced53d2a357dd7bff1b736c2beb0032690fbbebc80319b86b5d310d7869eed31958b1eaf9c62f98f16c7ba66bc67f613e121067774403337ee581d5633b429c74b5ac8f6d55ab57cf950507cf6fad32c785b4df1e0305d7c43d40498ccbcf77841e5d521cb327a7f29e527691a980917905cc1a9a7d145e898b394c8271a9dc9ff4c67ebe0c731ad086985865ab9f1e0";
        }

        vm.warp(1701355362);
        _recoveryModule.startRecovery(address(_account), 0, data, permissions);
    }

    function testOpenIDTimelockRecovery() public {}
}
