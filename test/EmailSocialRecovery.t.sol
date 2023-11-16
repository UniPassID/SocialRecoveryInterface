// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "forge-std/console2.sol";
import "../src/RecoveryModule.sol";
import "../src/test/SimpleAccount.sol";
import "../src/TypesAndDecoders.sol";
import "../src/interfaces/IPermissionVerifier.sol";
import "../src/verifier/email/EmailVerifier.sol";

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
                .signature = hex"00000000150000005f0000000000000005000000120000009e000000ce000000d3000000c2000000ca0000014c66726f6d3a616c69636540746573742e636f6d0d0a7375626a6563743a3078353430386463306661616161346436333235306166633531306338323038313062613239633363353239656230313735336130336630343539646664626664300d0a746f3a426f62203c626f6240746573742e636f6d3e0d0a646174653a4d6f6e2c203133204e6f7620323032332030333a35353a3430202b303030300d0a646b696d2d7369676e61747572653a763d313b20613d7273612d7368613235363b20643d746573742e636f6d3b20733d73323032333b20633d72656c617865642f72656c617865643b20713d646e732f7478743b20743d313639393834373734303b20683d66726f6d3a7375626a6563743a746f3a646174653b2062683d4f4e4c366e6d63494c4d524b7074326d7235326371714b54627059482b557031387564316b5a396f5969453d3b20623d000001006652049332418221c669824b22caea03af5945ec290dadba75029fcafcc7af8577f74db738078e8652dc230f0f3cb699d57b75bf43f2c3201f9fa55b4fe43cb51b7c9831deb5b4c0f3e148139fd2897fcd298965813cab400d0b9d95081bb33becc4d046bca35115986aa03d6c667fd9d4644b936527a929ba8c9de729a4f79d76d73de798225b8c0f4c504eb88a3f30726726b09bc566db7da17d7f98b524b46b26065953a1ebe93c54e344bb97a884f3c430d51a034447a29fd9a095b8e3acb46bd8f21cb028cedb07051e5c14f49e788a30514f0e9fc30f0ce87cec43af404334a27430bb3614e1c2a8a05e23f5282fc397f81be696b458698923e3546812";
        }
        {
            Identity memory id;
            id.guardianVerifier = address(_verifier);
            id.signer = configArg.guardianInfos[1].guardian.signer;
            permissions[1].guardian = id;
            permissions[1]
                .signature = hex"00000000130000005d0000000000000005000000100000009c000000cc000000d1000000c0000000c80000014a66726f6d3a626f6240746573742e636f6d0d0a7375626a6563743a3078353430386463306661616161346436333235306166633531306338323038313062613239633363353239656230313735336130336630343539646664626664300d0a746f3a426f62203c626f6240746573742e636f6d3e0d0a646174653a4d6f6e2c203133204e6f7620323032332030353a33353a3538202b303030300d0a646b696d2d7369676e61747572653a763d313b20613d7273612d7368613235363b20643d746573742e636f6d3b20733d73323032333b20633d72656c617865642f72656c617865643b20713d646e732f7478743b20743d313639393835333735383b20683d66726f6d3a7375626a6563743a746f3a646174653b2062683d4f4e4c366e6d63494c4d524b7074326d7235326371714b54627059482b557031387564316b5a396f5969453d3b20623d000001001673d9f66b4299e065a49772be9ccf0b23933a505d2a92c793ce19b4d3ec39592d1f7e47e1a228d3e4273f407e3adfee0cd0d439d2812897f125ff8fd0b0c49a429202ea0b6178f2bc07323d6bcc4197c7a24bf32ef59e247bac13155df38fbef7a04216b11a2f46044324485fbe0b714c3d7702a56ac3c927a68ce834b7e1eb0d4b47a056c75d1e64e434fd545ebb5f53bc10c3f28506d7ea37d0057d78c66a9aee97a4a0fe3720da2ab30805cf3298de5db5f90a77dc07d7040b2b5eb1d21fbd6aeae7e7600a532e7b8441276cb0b80b3cc071bf112b4b0f46e350a5e8ace6ccc57be9fb864d00bf33e7f4885f2fe2155810004f9aaaa7587a039d6b695769";
        }
        {
            Identity memory id;
            id.guardianVerifier = address(_verifier);
            id.signer = configArg.guardianInfos[2].guardian.signer;
            permissions[2].guardian = id;
            permissions[2]
                .signature = hex"000000001700000061000000000000000500000014000000a0000000d0000000d5000000c4000000cc0000014e66726f6d3a636861726c696540746573742e636f6d0d0a7375626a6563743a3078353430386463306661616161346436333235306166633531306338323038313062613239633363353239656230313735336130336630343539646664626664300d0a746f3a426f62203c626f6240746573742e636f6d3e0d0a646174653a4d6f6e2c203133204e6f7620323032332030353a33363a3132202b303030300d0a646b696d2d7369676e61747572653a763d313b20613d7273612d7368613235363b20643d746573742e636f6d3b20733d73323032333b20633d72656c617865642f72656c617865643b20713d646e732f7478743b20743d313639393835333737323b20683d66726f6d3a7375626a6563743a746f3a646174653b2062683d4f4e4c366e6d63494c4d524b7074326d7235326371714b54627059482b557031387564316b5a396f5969453d3b20623d000001001e426e52ed7ba560727d1c6b4c87c76daade9251ef648df6027c1087912484fc90bdf8450a7980ba9dbe6cfcc026952ca67b8877893af746d466e234c9d9b3655af8ccae765b0e385a7a65ad1e0f7a01359838079f12c4ed26aaef2ead97950248df1e0bd0204bb48e3f82d5aa47cdd5752a1f515a09a1d2d8a8ee971b78ed663dc421b9789c329f41ab4240c35dad7453b30136ce9a4343d535070cbdb6b2348e18d65c4d0e61349c89ff5071191c0a37600622f435d917e0b779d81697ecea913196c2dffa8daad2a9592f36f30f898737129b2a8f8919f204b27b9e50480ec35c5c53e83ca73b461b3a6ca0348549e65823139ddc47ffd3313c270d829352";
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
