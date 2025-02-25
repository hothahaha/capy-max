// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {MultiSig} from "../../src/access/MultiSig.sol";
import {BaseContractUpgradeTest} from "../upgrades/BaseContractUpgradeTest.sol";
import {DeployScript} from "../../script/Deploy.s.sol";

contract MultiSigV2 is MultiSig {
    uint256 public newVariable;

    function setNewVariable(uint256 _value) external {
        newVariable = _value;
    }

    function version() external pure returns (string memory) {
        return "V2";
    }
}

contract MultiSigUpgradesTest is BaseContractUpgradeTest {
    MultiSigV2 public multiSigV2;

    function setUp() public {
        DeployScript deploy = new DeployScript();
        (, , , signerManager, multiSig, helperConfig) = deploy.run();
        (, , , , , deployerKey, , ) = helperConfig.activeNetworkConfig();
        multiSigV2 = new MultiSigV2();
    }

    function getUpgradeableContract() public view override returns (address) {
        return address(multiSig);
    }

    function getNewImplementation() public view override returns (address) {
        return address(multiSigV2);
    }

    function validateUpgrade() public view override {
        assertEq(MultiSigV2(address(multiSig)).version(), "V2");
    }
}
