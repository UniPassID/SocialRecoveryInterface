// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "forge-std/console2.sol";
import "../src/RecoveryModule.sol";
import "../src/test/SimpleAccount.sol";
import "../src/TypesAndDecoders.sol";
import "../src/interfaces/IPermissionVerifier.sol";
import "../src/verifier/email/EmailVerifier.sol";

import "@safe-global/safe-contracts/contracts/Safe.sol";

contract EmailSocialRecoveryTest is Test {
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
    EmailVerifier _verifier;

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
        _verifier = new EmailVerifier();
        _verifier.updateDKIMKey(
            keccak256(abi.encodePacked("s2023", "test.com")),
            hex"a69e506330f22d05d609f3bd17803fb397585634c89ac8bbaa018ceecd1d8a51c75eb6d57889a1916a062aa4884b5c54b163d43cb46d84085987da27bc1537725ba18faf85cfff910ff0d4d96c1cd2fcaec0620820cc36b7a88940758552edd93f71979c7e103362675af392b2a24853f7f9a1008a3ed519fea9d591e5bbab948369e6acbe9a13ba0bfe28eff156a06b4b3d7a1fd6f7d386c10d303688240f626c8a9dbf2e77a19cb3d8e672282e2ac10b81eec6757683b2f3a8b48638bc6c2ad72b55131b2edaa861660a33bd9c827217d825124923f9bc7fbd8bee1ff45bcdb1c4a7060c2d91f054aa4945d9832e9eb0f5caf75a57b6db5631b9b1e6645d95"
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
        thresholdConfig0.threshold = uint64(_threshold);
        thresholdConfig0.lockPeriod = uint48(_lockPeriod);
        configArg.thresholdConfigs.push(thresholdConfig1);

        {
            GuardianInfo memory guardian;
            Identity memory id;
            id.guardianVerifier = address(_verifier);
            id.signer = abi.encodePacked(sha256("alice@test.com"));
            guardian.guardian = id;
            guardian.property = 1;
            configArg.guardianInfos.push(guardian);
        }
        {
            GuardianInfo memory guardian;
            Identity memory id;
            id.guardianVerifier = address(_verifier);
            id.signer = abi.encodePacked(sha256("bob@test.com"));
            guardian.guardian = id;
            guardian.property = 1;
            configArg.guardianInfos.push(guardian);
        }
        {
            GuardianInfo memory guardian;
            Identity memory id;
            id.guardianVerifier = address(_verifier);
            id.signer = abi.encodePacked(sha256("charlie@test.com"));
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

    function testEmailInstantRecovery() public {
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
                .signature = hex"00000000150000005f0000000000000005000000120000009e000000ce000000d3000000c2000000ca0000014c66726f6d3a616c69636540746573742e636f6d0d0a7375626a6563743a3078386661333732316634613736613464393861653837663436613536363262623932373134363166653137663937393164643131643939666630653439633236360d0a746f3a426f62203c626f6240746573742e636f6d3e0d0a646174653a4d6f6e2c203230204e6f7620323032332031353a32363a3030202b303030300d0a646b696d2d7369676e61747572653a763d313b20613d7273612d7368613235363b20643d746573742e636f6d3b20733d73323032333b20633d72656c617865642f72656c617865643b20713d646e732f7478743b20743d313730303439333936303b20683d66726f6d3a7375626a6563743a746f3a646174653b2062683d4f4e4c366e6d63494c4d524b7074326d7235326371714b54627059482b557031387564316b5a396f5969453d3b20623d000001000fb622df92ebaa3f8e5cb6c03a405736442e2ef4a7adfc98b93ff20fb55c7c8e2e93926c7da9577afac508cb15d5d30ebac04cf77ef3dc3cf99900fbb73f20b54a4ffabb3ae03d5251fb6843d896ef890fcd92e2ce20232546cff6a0d77484f4eb9303ca5316fd9f3c0388fa2ff08ce5577a4adfc4911acb9d333e33f613df8952ee8baa9b23dadbdafe6cbc6a70c9b740c355adc0982116ab0fc0b406508a77f4f2dd27efa9f1b2626e7e7ce092780e4f5fc713cf8229fae08690a124dab65c748e730e8af9267f223c07b18cba85383b12760b2cd6a0d429311a72ec378fdd2f3981d5d725f7288da30965036886efcb5790808e452f4db0ccaae9e913d060";
        }
        {
            Identity memory id;
            id.guardianVerifier = address(_verifier);
            id.signer = configArg.guardianInfos[1].guardian.signer;
            permissions[1].guardian = id;
            permissions[1]
                .signature = hex"00000000130000005d0000000000000005000000100000009c000000cc000000d1000000c0000000c80000014a66726f6d3a626f6240746573742e636f6d0d0a7375626a6563743a3078386661333732316634613736613464393861653837663436613536363262623932373134363166653137663937393164643131643939666630653439633236360d0a746f3a426f62203c626f6240746573742e636f6d3e0d0a646174653a4d6f6e2c203230204e6f7620323032332031353a32363a3235202b303030300d0a646b696d2d7369676e61747572653a763d313b20613d7273612d7368613235363b20643d746573742e636f6d3b20733d73323032333b20633d72656c617865642f72656c617865643b20713d646e732f7478743b20743d313730303439333938353b20683d66726f6d3a7375626a6563743a746f3a646174653b2062683d4f4e4c366e6d63494c4d524b7074326d7235326371714b54627059482b557031387564316b5a396f5969453d3b20623d000001009d6f23669a08f16198723aeff416fc4ef55e911d0160296090c7b45d5d9cb786135ab794c8811c4626ba90a83cae1eed8579987c79386973d96f6bc8e31db0a31f2d24ec92020b33a38621ae1563736db1aff68ddc4336edc8aa6c0a36659fb925339167084f103050bebdd684cbada60f499a9d4987f7f6cca7fa1b48183fe609a4e8ffb19b7306d6e15b01bb6799816f98cbe4625339e4484d083ee72d120d5ba8de9cc345870f3498a8496bf725f3f02747c8a71b785ce594b423abdb8ad79aa8e5e0a43d263301316406e2be95e94ea80f5fb75d2fe9a490598e3fca9dada42753274653d00ad362be13f3a4b71c8c051bfecc2359770e5c9c72f1d2178f";
        }
        {
            Identity memory id;
            id.guardianVerifier = address(_verifier);
            id.signer = configArg.guardianInfos[2].guardian.signer;
            permissions[2].guardian = id;
            permissions[2]
                .signature = hex"000000001700000061000000000000000500000014000000a0000000d0000000d5000000c4000000cc0000014e66726f6d3a636861726c696540746573742e636f6d0d0a7375626a6563743a3078386661333732316634613736613464393861653837663436613536363262623932373134363166653137663937393164643131643939666630653439633236360d0a746f3a426f62203c626f6240746573742e636f6d3e0d0a646174653a4d6f6e2c203230204e6f7620323032332031353a32363a3436202b303030300d0a646b696d2d7369676e61747572653a763d313b20613d7273612d7368613235363b20643d746573742e636f6d3b20733d73323032333b20633d72656c617865642f72656c617865643b20713d646e732f7478743b20743d313730303439343030363b20683d66726f6d3a7375626a6563743a746f3a646174653b2062683d4f4e4c366e6d63494c4d524b7074326d7235326371714b54627059482b557031387564316b5a396f5969453d3b20623d0000010059fa991f2a16ad943fac557ffcf1d512a3198bfa597eea50311796c71338486263114a04a04dda35b76a81679c75c1a17e71652ade2ab663840791a0f5758f4f03c4cfe021702010667b331f32580b49b347fe71752e3b75ed07dae533d658fecc083f8fb20a316ec3becc7075f6530931f055f408b3ed0f3beddc06a6bb3d677394c7445f9cb59aa5c83fd9d91402049986805f7fd9cc64f70a5a190755130bfad8ff24ed3dbdb8ea163b86129c322880719409be01a526ac3a458f90dfcafef861962ddbca623608829caf5d4dec0997a8deb355748ea5927df5884999bb790159affe917d93c3f1c5032c3f7579f0dcc004516a60b45918dacf03153d2438";
        }

        vm.warp(1699582162);
        _recoveryModule.startRecovery(address(_account), 0, data, permissions);
    }
}
