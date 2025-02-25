// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {BaseContractUpgradeTest} from "./BaseContractUpgradeTest.sol";
import {MultiSig} from "../../src/access/MultiSig.sol";
import {DeployScript} from "../../script/Deploy.s.sol";
import {BaseV2Contract} from "./BaseV2Contract.sol";

contract MultiSigV2 is MultiSig, BaseV2Contract {
    function getDefaultThreshold() external pure returns (uint256) {
        return 2;
    }
}

contract MultiSigUpgradesTest is BaseContractUpgradeTest {
    MultiSigV2 internal multiSigV2;

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

    function validateUpgrade() public override {
        assertEq(MultiSigV2(address(multiSig)).version(), "V2");
        assertEq(MultiSigV2(address(multiSig)).getDefaultThreshold(), 2);

        // Test new functionality
        MultiSigV2(address(multiSig)).newFunction();
        assertTrue(MultiSigV2(address(multiSig)).newFunctionCalled());
    }
}
