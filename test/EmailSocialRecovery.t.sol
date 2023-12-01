// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "forge-std/console2.sol";
import "../src/RecoveryModule.sol";
import "../src/test/TestAccount.sol";
import "../src/TypesAndDecoders.sol";
import "../src/interfaces/IPermissionVerifier.sol";
import "../src/verifier/email/EmailVerifier.sol";

import "@safe-global/safe-contracts/contracts/Safe.sol";
import "@safe-global/safe-contracts/contracts/proxies/SafeProxyFactory.sol";

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
    SafeProxyFactory _factory;
    TestAccount _accountImpl;
    ISafe _account;
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
        _factory = new SafeProxyFactory();
        _accountImpl = new TestAccount();

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
                .signature = hex"00000000150000005f0000000000000005000000120000009e000000ce000000d3000000c2000000ca0000014c66726f6d3a616c69636540746573742e636f6d0d0a7375626a6563743a3078323439306664323438396564386461386465316535386335366132653066623430306662373635303133626230303061313034353666343532666631313338340d0a746f3a426f62203c626f6240746573742e636f6d3e0d0a646174653a5468752c203330204e6f7620323032332030383a35313a3237202b303030300d0a646b696d2d7369676e61747572653a763d313b20613d7273612d7368613235363b20643d746573742e636f6d3b20733d73323032333b20633d72656c617865642f72656c617865643b20713d646e732f7478743b20743d313730313333343238373b20683d66726f6d3a7375626a6563743a746f3a646174653b2062683d4f4e4c366e6d63494c4d524b7074326d7235326371714b54627059482b557031387564316b5a396f5969453d3b20623d0000010097c40c282f285ef4f68406118cac079fb207a2a4774c7b30a3e18624c105db57513730565c36f05309e800e5b9ed03b0f1dd310998a6e9f7d928af121fcf8aa38b3d45a23e621f6893691a81bfbe8c58efbf519351d802324b4012bbf637cbf380d4bf5c2728a6c8ca1c64c55d10322a92b84a9fee988a56fcddf83397c9e769b3d724d948457a20c5b3dff7224750cabab23100067443f358d8340ee7732d220619ac56424b92977d37bc93407714489a319507abedd318b11f2d446e4c1aa350855cf347e2466fac9429b366ed588d7419e30d361b192d3b5861dc95d72b022ea0cf82d0d7fd7efd87060f7b2cac085a112c3e84b07137dc1d9bf11231e5b0";
        }
        {
            Identity memory id;
            id.guardianVerifier = address(_verifier);
            id.signer = configArg.guardianInfos[1].guardian.signer;
            permissions[1].guardian = id;
            permissions[1]
                .signature = hex"00000000130000005d0000000000000005000000100000009c000000cc000000d1000000c0000000c80000014a66726f6d3a626f6240746573742e636f6d0d0a7375626a6563743a3078323439306664323438396564386461386465316535386335366132653066623430306662373635303133626230303061313034353666343532666631313338340d0a746f3a426f62203c626f6240746573742e636f6d3e0d0a646174653a5468752c203330204e6f7620323032332030383a35313a3434202b303030300d0a646b696d2d7369676e61747572653a763d313b20613d7273612d7368613235363b20643d746573742e636f6d3b20733d73323032333b20633d72656c617865642f72656c617865643b20713d646e732f7478743b20743d313730313333343330343b20683d66726f6d3a7375626a6563743a746f3a646174653b2062683d4f4e4c366e6d63494c4d524b7074326d7235326371714b54627059482b557031387564316b5a396f5969453d3b20623d000001001d293a5e1d577d0c60707f2c027c3a58f40049381a8b469110fa1329affead730cdd624ffbfbe0c8e9a574f371f591a6372f76ab6b5ebe6f58b8b00bcbacde59103882a5535b724d6882980c6cc99ba17efc2d18aa5652309369007fa0ab14025858fa6d1673163c2e0a52976434d6e09f2c9893f3c8237d42ed5150fa69ebe1cdf6c082835d39541750148282ccaaea288020adb2fbace68018dd0e20da23b7de887ebc6cfe03e63de4b09a9917799f9d2e6eedc6174ccf1705b2c2dbba67b8bfb44c0c33c1f2dd6bed9fbee3a7d0855b1a7a01db4f221e21997449a6dcda991a873c221c8ec78d9012b460061234207e410e93e535b8467996137ccc66d276";
        }
        {
            Identity memory id;
            id.guardianVerifier = address(_verifier);
            id.signer = configArg.guardianInfos[2].guardian.signer;
            permissions[2].guardian = id;
            permissions[2]
                .signature = hex"000000001700000061000000000000000500000014000000a0000000d0000000d5000000c4000000cc0000014e66726f6d3a636861726c696540746573742e636f6d0d0a7375626a6563743a3078323439306664323438396564386461386465316535386335366132653066623430306662373635303133626230303061313034353666343532666631313338340d0a746f3a426f62203c626f6240746573742e636f6d3e0d0a646174653a5468752c203330204e6f7620323032332030383a35323a3133202b303030300d0a646b696d2d7369676e61747572653a763d313b20613d7273612d7368613235363b20643d746573742e636f6d3b20733d73323032333b20633d72656c617865642f72656c617865643b20713d646e732f7478743b20743d313730313333343333333b20683d66726f6d3a7375626a6563743a746f3a646174653b2062683d4f4e4c366e6d63494c4d524b7074326d7235326371714b54627059482b557031387564316b5a396f5969453d3b20623d00000100a3d778efff6ac0d4c0eae0b8193759e88d0541c7eebd51f9111d866ccedf052ff4c845bd65439410604192881be737e1a5ce443fab44a8f9c31708bd75fbf512472b6810978f79d1e42c000669e1db964082bda13cf89a7f25584213a41773d5eee1ba3ebf18f4ceb4836626dbdaae84a88f2522047d803ceaad12039eb9a75e6f8ec9ee009a62fe3ff4af326496b8b4333b63b432cebcfa537658fa677abdf6a799693e7dca95cf0ea733b8a30a7d535fb6ed772f2480933ac4b7412fbfbdf893324a994f6012fefa5c4fd01de2bd8028c7c6edbcbbc4e1a8c2d53b802a6f5e4b0ea66ab82612c08641973bf97843b66f6226b6df300a30fb7fa42e846ddb2e";
        }

        vm.warp(1699582162);
        _recoveryModule.startRecovery(address(_account), 0, data, permissions);
    }

    function testEmailTimelockRecovery() public {}
}
