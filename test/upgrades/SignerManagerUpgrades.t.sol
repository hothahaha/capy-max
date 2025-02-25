// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {SignerManager} from "../../src/access/SignerManager.sol";
import {BaseContractUpgradeTest} from "../upgrades/BaseContractUpgradeTest.sol";
import {DeployScript} from "../../script/Deploy.s.sol";

contract SignerManagerV2 is SignerManager {
    uint256 public newVariable;

    function setNewVariable(uint256 _value) external {
        newVariable = _value;
    }

    function version() external pure returns (string memory) {
        return "V2";
    }
}

contract SignerManagerUpgradesTest is BaseContractUpgradeTest {
    SignerManagerV2 public signerManagerV2;

    function setUp() public {
        DeployScript deploy = new DeployScript();
        (, , , signerManager, multiSig, helperConfig) = deploy.run();
        (, , , , , deployerKey, , ) = helperConfig.activeNetworkConfig();
        signerManagerV2 = new SignerManagerV2();
    }

    function getUpgradeableContract() public view override returns (address) {
        return address(signerManager);
    }

    function getNewImplementation() public view override returns (address) {
        return address(signerManagerV2);
    }

    function validateUpgrade() public view override {
        assertEq(SignerManagerV2(address(signerManager)).version(), "V2");
    }
}
