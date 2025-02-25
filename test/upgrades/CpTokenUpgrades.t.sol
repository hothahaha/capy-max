// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {CpToken} from "../../src/tokens/CpToken.sol";
import {BaseContractUpgradeTest} from "../upgrades/BaseContractUpgradeTest.sol";
import {DeployScript} from "../../script/Deploy.s.sol";

contract CpTokenV2 is CpToken {
    uint256 public newVariable;

    function setNewVariable(uint256 _value) external {
        newVariable = _value;
    }

    function version() external pure returns (string memory) {
        return "V2";
    }
}

contract CpTokenUpgradesTest is BaseContractUpgradeTest {
    CpToken public cpToken;
    CpTokenV2 public cpTokenV2;

    function setUp() public {
        DeployScript deploy = new DeployScript();
        (, cpToken, , signerManager, multiSig, helperConfig) = deploy.run();
        (, , , , , deployerKey, , ) = helperConfig.activeNetworkConfig();
        cpTokenV2 = new CpTokenV2();
    }

    function getUpgradeableContract() public view override returns (address) {
        return address(cpToken);
    }

    function getNewImplementation() public view override returns (address) {
        return address(cpTokenV2);
    }

    function validateUpgrade() public view override {
        assertEq(CpTokenV2(address(cpToken)).version(), "V2");
    }
}
