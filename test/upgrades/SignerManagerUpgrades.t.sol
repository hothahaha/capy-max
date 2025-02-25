// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {BaseContractUpgradeTest} from "./BaseContractUpgradeTest.sol";
import {SignerManager} from "../../src/access/SignerManager.sol";
import {DeployScript} from "../../script/Deploy.s.sol";
import {BaseV2Contract} from "./BaseV2Contract.sol";

contract SignerManagerV2 is SignerManager, BaseV2Contract {
    function getMaxSigners() external pure returns (uint256) {
        return 10;
    }
}

contract SignerManagerUpgradesTest is BaseContractUpgradeTest {
    SignerManagerV2 internal signerManagerV2;

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

    function validateUpgrade() public override {
        assertEq(SignerManagerV2(address(signerManager)).version(), "V2");
        assertEq(SignerManagerV2(address(signerManager)).getMaxSigners(), 10);

        // Test new functionality
        SignerManagerV2(address(signerManager)).newFunction();
        assertTrue(SignerManagerV2(address(signerManager)).newFunctionCalled());
    }

    function test_StorageSlotConsistency() public {
        address newSigner = makeAddr("newSigner");

        // Set initial state
        vm.startPrank(address(multiSig));
        signerManager.addSigner(newSigner);
        vm.stopPrank();

        // Perform upgrade
        address implementation = getNewImplementation();
        UpgradeTestParams memory params = _prepareUpgradeTest(
            getUpgradeableContract(),
            implementation
        );
        _executeUpgradeTest(params);

        // Verify data preservation
        assertTrue(signerManager.isSigner(newSigner), "Signer not preserved");
    }
}
