// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

abstract contract BaseV2Contract {
    uint256 public newVariable;
    bool public newFunctionCalled;

    function setNewVariable(uint256 _value) external {
        newVariable = _value;
    }

    function version() external pure virtual returns (string memory) {
        return "V2";
    }

    function newFunction() external {
        newFunctionCalled = true;
    }
}
