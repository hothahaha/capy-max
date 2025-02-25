// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {BaseContractUpgradeTest} from "./upgrades/BaseContractUpgradeTest.sol";
import {UserPosition} from "../src/UserPosition.sol";
import {MultiSig} from "../src/access/MultiSig.sol";
import {SignerManager} from "../src/access/SignerManager.sol";
import {StrategyEngine} from "../src/StrategyEngine.sol";
import {DeployScript} from "../script/Deploy.s.sol";
import {HelperConfig} from "../script/HelperConfig.s.sol";
import {UUPSUpgradeableBase} from "../src/upgradeable/UUPSUpgradeableBase.sol";

import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

contract UserPositionV2 is UserPosition {
    uint256 public newVariable;
    bool public newFunctionCalled;

    function setNewVariable(uint256 _value) external {
        newVariable = _value;
    }

    function version() external pure returns (string memory) {
        return "V2";
    }

    function newFunction() external {
        newFunctionCalled = true;
    }
}

contract UserPositionUpgradesTest is BaseContractUpgradeTest {
    StrategyEngine internal engine;
    UserPosition internal userPosition;
    UserPositionV2 internal userPositionV2;

    function setUp() public {
        DeployScript deployer = new DeployScript();
        (engine, , , signerManager, multiSig, helperConfig) = deployer.run();
        (, , , , , deployerKey, , ) = helperConfig.activeNetworkConfig();
        address user = vm.addr(deployerKey);
        userPosition = deployUserPosition(user, address(engine), user, address(multiSig));
        userPositionV2 = new UserPositionV2();
    }

    function getUpgradeableContract() public view override returns (address) {
        return address(userPosition);
    }

    function getNewImplementation() public view override returns (address) {
        return address(userPositionV2);
    }

    function validateUpgrade() public override {
        assertEq(UserPositionV2(payable(address(userPosition))).version(), "V2");

        // Test new functionality
        UserPositionV2(payable(address(userPosition))).newFunction();
        assertTrue(UserPositionV2(payable(address(userPosition))).newFunctionCalled());
    }

    function test_StorageSlotConsistency() public {
        // Set initial state
        vm.prank(address(engine));
        userPosition.transferOwnership(address(0x123));

        // Perform upgrade
        address implementation = getNewImplementation();
        UpgradeTestParams memory params = _prepareUpgradeTest(
            getUpgradeableContract(),
            implementation
        );
        _executeUpgradeTest(params);

        // Verify data preservation
        assertEq(userPosition.owner(), address(0x123), "Owner not preserved after upgrade");
    }

    // Helper functions
    function deployUserPosition(
        address initialOwner,
        address engine_,
        address user_,
        address multiSig_
    ) internal returns (UserPosition) {
        UserPosition impl = new UserPosition();
        ERC1967Proxy proxy = new ERC1967Proxy(address(impl), "");
        UserPosition up = UserPosition(payable(address(proxy)));

        // Initialize
        UserPosition(payable(address(proxy))).initialize(initialOwner, engine_, user_, multiSig_);

        // Ensure we are the contract owner
        assertEq(up.owner(), initialOwner);

        vm.startPrank(initialOwner);

        // Finally transfer ownership
        up.transferOwnership(address(engine));
        vm.stopPrank();
        return up;
    }
}
