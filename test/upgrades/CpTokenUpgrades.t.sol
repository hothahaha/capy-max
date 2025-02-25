// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {BaseContractUpgradeTest} from "./BaseContractUpgradeTest.sol";
import {StrategyEngine} from "../../src/StrategyEngine.sol";
import {CpToken} from "../../src/tokens/CpToken.sol";
import {DeployScript} from "../../script/Deploy.s.sol";
import {BaseV2Contract} from "./BaseV2Contract.sol";

contract CpTokenV2 is CpToken, BaseV2Contract {
    function getDefaultDecimals() external pure returns (uint256) {
        return 18;
    }
}

contract CpTokenUpgradesTest is BaseContractUpgradeTest {
    StrategyEngine internal engine;
    CpToken internal cpToken;
    CpTokenV2 internal cpTokenV2;

    function setUp() public {
        DeployScript deploy = new DeployScript();
        (engine, cpToken, , signerManager, multiSig, helperConfig) = deploy.run();
        (, , , , , deployerKey, , ) = helperConfig.activeNetworkConfig();
        cpTokenV2 = new CpTokenV2();
    }

    function getUpgradeableContract() public view override returns (address) {
        return address(cpToken);
    }

    function getNewImplementation() public view override returns (address) {
        return address(cpTokenV2);
    }

    function validateUpgrade() public override {
        assertEq(CpTokenV2(address(cpToken)).version(), "V2");
        assertEq(CpTokenV2(address(cpToken)).getDefaultDecimals(), 18);

        // Test new functionality
        CpTokenV2(address(cpToken)).newFunction();
        assertTrue(CpTokenV2(address(cpToken)).newFunctionCalled());
    }

    function test_StorageSlotConsistency() public {
        // Set initial state
        vm.startPrank(address(engine));
        cpToken.mint(address(this), 1000e18);
        vm.stopPrank();

        // Perform upgrade
        address implementation = getNewImplementation();
        UpgradeTestParams memory params = _prepareUpgradeTest(
            getUpgradeableContract(),
            implementation
        );
        _executeUpgradeTest(params);

        // Verify data preservation
        assertEq(cpToken.balanceOf(address(this)), 1000e18, "Balance not preserved");
    }

    function test_UpgradeToAndCall() public {
        // Set initial state
        vm.startPrank(address(engine));
        cpToken.mint(address(this), 500e18);
        vm.stopPrank();

        // Prepare initialization data

        // Perform upgrade with initialization
        UpgradeTestParams memory params = _prepareUpgradeTest(
            getUpgradeableContract(),
            address(cpTokenV2)
        );
        _executeUpgradeTest(params);

        cpTokenV2.setNewVariable(777);

        // Verify initialization and state preservation
        assertEq(cpTokenV2.newVariable(), 777);
        assertEq(cpToken.balanceOf(address(this)), 500e18, "Balance not preserved");
    }
}
