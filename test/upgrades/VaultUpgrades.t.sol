// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {BaseContractUpgradeTest} from "./BaseContractUpgradeTest.sol";
import {Vault} from "../../src/vault/Vault.sol";
import {DeployScript} from "../../script/Deploy.s.sol";
import {BaseV2Contract} from "./BaseV2Contract.sol";

contract VaultV2 is Vault, BaseV2Contract {
    function getDefaultFee() external pure returns (uint256) {
        return 50; // 0.5%
    }
}

contract VaultUpgradesTest is BaseContractUpgradeTest {
    Vault internal vault;
    VaultV2 internal vaultV2;

    function setUp() public {
        DeployScript deploy = new DeployScript();
        (, , vault, signerManager, multiSig, helperConfig) = deploy.run();
        (, , , , , deployerKey, , ) = helperConfig.activeNetworkConfig();
        vaultV2 = new VaultV2();
    }

    function getUpgradeableContract() public view override returns (address) {
        return address(vault);
    }

    function getNewImplementation() public view override returns (address) {
        return address(vaultV2);
    }

    function validateUpgrade() public override {
        assertEq(VaultV2(address(vault)).version(), "V2");
        assertEq(VaultV2(address(vault)).getDefaultFee(), 50);

        // Test new functionality
        VaultV2(address(vault)).newFunction();
        assertTrue(VaultV2(address(vault)).newFunctionCalled());
    }
}
