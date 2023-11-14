// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "forge-std/console2.sol";
import "../src/RecoveryModule.sol";
import "../src/test/SimpleAccount.sol";
import "../src/TypesAndDecoders.sol";
import "../src/interfaces/IPermissionVerifier.sol";
import "../src/verifier/openid/OpenIDVerifier.sol";

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
        _account.authorizeModule(address(_recoveryModule));
        vm.stopPrank();

        vm.startPrank(address(_account));

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

        _recoveryModule.addConfig(configArg);
        vm.stopPrank();

        console2.log("domainSeparator: ");
        console2.logBytes32(domainSeparator());
    }

    function testOpenIDInstantRecovery() public {
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
            id.guardianVerifier = configArg
                .guardianInfos[0]
                .guardian
                .guardianVerifier;
            id.signer = configArg.guardianInfos[0].guardian.signer;
            permissions[0].guardian = id;
            permissions[0]
                .signature = hex"0000003b00000046000000160000001e0000004f00000059000000620000006a0000007500000007000000180000002c7b22616c67223a225253323536222c226b6964223a22746573745f6b6964222c22747970223a224a5754227d000000b97b22696174223a313639393538323135392c22657870223a313639393636383535392c226e6266223a313639393538323135392c22697373223a22746573745f697373756572222c22737562223a22746573745f7573657231222c22617564223a22746573745f617564222c226e6f6e6365223a22307835343038646330666161616134643633323530616663353130633832303831306261323963336335323965623031373533613033663034353964666462666430227d000001007821b7239a6d9dd00ba66ff49762c62ed0942df0f101fad873c855e75394c4e7eae8abc1867d58002e9c198f7553d4fd4f31284b404f9646f35c0a0fe55707a257f5577f7f811ab8032e3d86f4584cef754b612dc2be2a9a3140e0c6d7d8a969da4b3b2096a1264b250ac65cf509b426729acf8fde4a984ce6bb49db8d28b63a604d6cfbfbb68d2956d1836dceed63e85dfed6c715df625f9718755fb745f05d8b16ce5b1e8505a2110fc12d5e346a296a86110308eca6a95e96397d18626fec0fcdb38d136a4bf4f0a33b33347ff921433418437ef1ee68165fb3698d4536675363159624eb031b6b43b28c7c8f6d62bb11b6a41075d52ca90cacb8c79da27d";
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
                .signature = hex"0000003b00000046000000160000001e0000004f00000059000000620000006a0000007500000007000000180000002c7b22616c67223a225253323536222c226b6964223a22746573745f6b6964222c22747970223a224a5754227d000000b97b22696174223a313639393538323136312c22657870223a313639393636383536312c226e6266223a313639393538323136312c22697373223a22746573745f697373756572222c22737562223a22746573745f7573657232222c22617564223a22746573745f617564222c226e6f6e6365223a22307835343038646330666161616134643633323530616663353130633832303831306261323963336335323965623031373533613033663034353964666462666430227d000001007825d5ea3de02f940ada2d45022017ac8e0cbd8b9e778f814d7f891cbf23c6ac88998493244edbcaeb12451e12bb4e0cec7d32179970340269e3898c61c9ab1bd3e2b9afd1c0a0c4cb57005251e9b383f9120c634ce810e82d39f507219f54064a0c5915f8559c50690ada34bebda11dca9ac2c221212776720d89b37eb93b57d218e3b7d0d08fce15901dbcc6e52d73b5e5cd2d00d521975fb7d1d83ea13f6ea7cda2523224093701e4ab1d6a7c5f9c4e186d5939478ea01d94910ca3362f5de6a485c469b080e2dc767a5e0749e3682a6642f0505c0493abd8c8ab34d3a0393052b9a440a50485d9ae65215af2802222e1100db0508aca5925027d77abc724";
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
                .signature = hex"0000003b00000046000000160000001e0000004f00000059000000620000006a0000007500000007000000180000002c7b22616c67223a225253323536222c226b6964223a22746573745f6b6964222c22747970223a224a5754227d000000b97b22696174223a313639393538323136332c22657870223a313639393636383536332c226e6266223a313639393538323136332c22697373223a22746573745f697373756572222c22737562223a22746573745f7573657233222c22617564223a22746573745f617564222c226e6f6e6365223a22307835343038646330666161616134643633323530616663353130633832303831306261323963336335323965623031373533613033663034353964666462666430227d00000100afacfc9b81690c493c09e38ce23f61710021fc2ddb74fee02bf88bd8aa0b8082178e989aaac80473d60d0048bd527f69619f54ef9a33626024de9dfc6d1595695eb07c9d209e7bf40f832fad09d2c043686eeec550691f9b36d255317944753e88b53703b3ba807520b13adee80df559f943660081932d69164576f66c0aa834b8a91403cb4c9fa2618b52994cde33f7f4306175b0f9e2af6e480934f245df03fdf8fede569b3ce463fe4245d2147d52edae015d90ed39549e8d1a55caf3d4a3871eca5539992652c4a098f706154cdd3169c34bbec292d6d7b22a81c03d31be043bbf88c486ecc47d1b24e3aa752da3190fced722a0134f2ad97b524f457cd9";
        }

        vm.warp(1699582180);
        _recoveryModule.startRecovery(
            address(_account),
            0,
            abi.encodePacked(_ownerAddr),
            permissions
        );
    }
}
