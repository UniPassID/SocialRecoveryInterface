// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

contract SimpleAccount {
    address public _owner;

    mapping(address => bool) public _authorizedModule;

    constructor() {
        _owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == _owner, "not owner");
        _;
    }

    modifier onlyAuthorizedModule() {
        require(_authorizedModule[msg.sender], "unauthorized");
        _;
    }

    function authorizeModule(address module) public onlyOwner {
        _authorizedModule[module] = true;
    }

    function bytesToAddress(
        bytes memory bys
    ) private pure returns (address addr) {
        assembly {
            addr := mload(add(bys, 20))
        }
    }

    function isAuthorizedModule(address module) external view returns (bool) {
        return _authorizedModule[module];
    }

    function resetOwner(bytes memory newOwner) external onlyAuthorizedModule {
        _owner = bytesToAddress(newOwner);
    }

    /**
     * @param target call target
     * @param value carried value
     * @param data calldata
     */
    function execute(
        address target,
        uint256 value,
        uint256 gasLimit,
        bytes calldata data
    ) external payable onlyOwner returns (bool) {
        return call(target, value, gasLimit, data);
    }

    function call(
        address _to,
        uint256 _val,
        uint256 _gas,
        bytes calldata _data
    ) internal returns (bool r) {
        assembly {
            let tmp := mload(0x40)
            calldatacopy(tmp, _data.offset, _data.length)

            r := call(_gas, _to, _val, tmp, _data.length, 0, 0)
        }
    }
}
