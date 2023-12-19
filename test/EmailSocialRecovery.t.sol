// SPDX-License-Identifier: LGPL-3.0-only
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
                .signature = hex"00000000150000005f0000000000000005000000120000009e000000ce000000d3000000c2000000ca0000014c66726f6d3a616c69636540746573742e636f6d0d0a7375626a6563743a3078303131666164393462333365646666303038663936366339336336626162353361323434363832386235663039323436373033323361643066663035633363310d0a746f3a426f62203c626f6240746573742e636f6d3e0d0a646174653a5475652c2031392044656320323032332030393a33323a3230202b303030300d0a646b696d2d7369676e61747572653a763d313b20613d7273612d7368613235363b20643d746573742e636f6d3b20733d73323032333b20633d72656c617865642f72656c617865643b20713d646e732f7478743b20743d313730323937383334303b20683d66726f6d3a7375626a6563743a746f3a646174653b2062683d4f4e4c366e6d63494c4d524b7074326d7235326371714b54627059482b557031387564316b5a396f5969453d3b20623d0000010050a43f09753b4a1a10fb4caa94ef2bec64ed74c8bedc4cec88a0a8ed18679fb335824c50656c9be8314210846398e0ee3a49e960b60f6cbf11be3e6201f2a2f52485b7b848b50ed7f80b468b5b05695b511ac71ce751ec6c6c33f346009eef9c5e8dc9f7790e5e1dae90bd9c0533d1ec1c3dcaed24d2c451b08136005eee75d9664fd72fb523a1dc5a9c1cc10236dded2fcd8aef11a6f38f6b00d31a8c7abb736e3d247b02fd19195e70ca37a1d0e61f09a203289382001a118b982b74936fdf82eda821b15353a6dce25cd7b9d17a7f29a9c44ec69d3e90eda5048e2c92681552af02e604b86fe130af531d7a96c1c967df563877cd75ca297cb323496bde1c";
        }
        {
            Identity memory id;
            id.guardianVerifier = address(_verifier);
            id.signer = configArg.guardianInfos[1].guardian.signer;
            permissions[1].guardian = id;
            permissions[1]
                .signature = hex"00000000130000005d0000000000000005000000100000009c000000cc000000d1000000c0000000c80000014a66726f6d3a626f6240746573742e636f6d0d0a7375626a6563743a3078303131666164393462333365646666303038663936366339336336626162353361323434363832386235663039323436373033323361643066663035633363310d0a746f3a426f62203c626f6240746573742e636f6d3e0d0a646174653a5475652c2031392044656320323032332030393a33323a3438202b303030300d0a646b696d2d7369676e61747572653a763d313b20613d7273612d7368613235363b20643d746573742e636f6d3b20733d73323032333b20633d72656c617865642f72656c617865643b20713d646e732f7478743b20743d313730323937383336383b20683d66726f6d3a7375626a6563743a746f3a646174653b2062683d4f4e4c366e6d63494c4d524b7074326d7235326371714b54627059482b557031387564316b5a396f5969453d3b20623d000001006621b5c93b5391b00b3844e7ec74cc7891abcddf465b2261e084d772246a0012f7c25b55fae806ec7e843dd395033ceea244aa6a56dc9c38c2fcc26c282b78f4c0e856176bd8c88ed60e9568fc63e04ffa62ca79f284dcda6c2b4a48b91242c378db765584298fff018a867b507113998a3bb178766c0b95566484c5fb67abbb396a8e3c74f6d037ee861576e9b28b3426d2302b09e8883fda379b840246d41114d2b42a249a5bcfd086173014116984eca716df45c4ac4d37bc0b58e552a2972c369856ae3c1953c6c7198b711cbf12c4916488fdc3c1a5c593cb7ac3be6f13e0f57e8d921fa993e41845c6ec88583d15bae038352c59464ee9bf884fd24a0b";
        }
        {
            Identity memory id;
            id.guardianVerifier = address(_verifier);
            id.signer = configArg.guardianInfos[2].guardian.signer;
            permissions[2].guardian = id;
            permissions[2]
                .signature = hex"000000001700000061000000000000000500000014000000a0000000d0000000d5000000c4000000cc0000014e66726f6d3a636861726c696540746573742e636f6d0d0a7375626a6563743a3078303131666164393462333365646666303038663936366339336336626162353361323434363832386235663039323436373033323361643066663035633363310d0a746f3a426f62203c626f6240746573742e636f6d3e0d0a646174653a5475652c2031392044656320323032332030393a33333a3233202b303030300d0a646b696d2d7369676e61747572653a763d313b20613d7273612d7368613235363b20643d746573742e636f6d3b20733d73323032333b20633d72656c617865642f72656c617865643b20713d646e732f7478743b20743d313730323937383430333b20683d66726f6d3a7375626a6563743a746f3a646174653b2062683d4f4e4c366e6d63494c4d524b7074326d7235326371714b54627059482b557031387564316b5a396f5969453d3b20623d000001008a7fc1cb337867899ca90058a91aa6d323e0ec9d53d3d1f90a2b3b1809bbac730cb5f08d5a8afc3375c2a5a84ed59221456e00be954d7904b92fe25f76ef281c88cf1bbed36cedb8c10cfd0246295f1ec77ff86cdbfbf384999e17b2a3f0264ab6fe77cfb940a9cf34eec4496dcfb8eea07182742c1893a832b0fddd07d04ba0b20420553b31f0392ba0c2ce1a9b147b1d57b590e75439edd6b55dd325559cd44a79e27027f30520394f896318250013f4b8c8415fa447ff7fb2410064dd8770232837294305cbe62ce9696276441416aa8b396816087d38190a2f3c763d850a9b0024f2756f7d08fa628a8a6386588de6130a4962f58efd8c93b3eaf4490e08";
        }

        vm.warp(1699582162);
        _recoveryModule.startRecovery(address(_account), 0, data, permissions);
    }
}
