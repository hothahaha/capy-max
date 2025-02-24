// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
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

    function setNewVariable(uint256 _value) external {
        newVariable = _value;
    }

    function version() external pure returns (string memory) {
        return "V2";
    }
}

contract UserPositionUpgradesTest is Test {
    UserPosition public userPosition;
    MultiSig public multiSig;
    SignerManager public signerManager;
    HelperConfig public helperConfig;
    StrategyEngine public engine;
    uint256 public deployerKey;

    bytes32 public constant IMPLEMENTATION_SLOT =
        0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    event Upgraded(address indexed implementation);

    function setUp() public {
        DeployScript deployer = new DeployScript();
        (engine, , , signerManager, multiSig, helperConfig) = deployer.run();
        (, , , , , deployerKey, , ) = helperConfig.activeNetworkConfig();

        address user = makeAddr("user");

        // Deploy UserPosition
        userPosition = deployUserPosition(
            address(engine),
            address(engine),
            user,
            address(multiSig)
        );
    }

    function test_UpgradeToV2() public {
        UserPositionV2 userPositionV2 = new UserPositionV2();

        uint256 deadline = block.timestamp + 1 days;

        // Construct upgrade data
        bytes memory upgradeData = abi.encodeWithSelector(
            userPosition.upgradeToAndCall.selector,
            address(userPositionV2),
            ""
        );

        // Generate signatures
        bytes[] memory signatures = new bytes[](2);
        (address signer2, uint256 signer2Key) = makeAddrAndKey("signer2");

        _addSigner(signer2);
        _updateThreshold(2);

        // Ensure correct signature order
        address deployer = vm.addr(deployerKey);
        require(signerManager.isSigner(deployer), "Deployer not a signer");
        require(signerManager.isSigner(signer2), "Signer2 not a signer");

        // Get transaction hash
        bytes32 txHash = multiSig.hashTransaction(
            address(userPosition),
            upgradeData,
            multiSig.nonce(),
            deadline
        );

        signatures[0] = _signTransaction(deployerKey, txHash);
        signatures[1] = _signTransaction(signer2Key, txHash);

        vm.expectEmit(true, true, true, true);
        emit Upgraded(address(userPositionV2));

        multiSig.executeTransaction(address(userPosition), upgradeData, deadline, signatures);

        UserPositionV2 upgradedUserPosition = UserPositionV2(payable(address(userPosition)));
        assertEq(upgradedUserPosition.version(), "V2");
    }

    function test_RevertWhen_UpgradeUnauthorized() public {
        UserPositionV2 userPositionV2 = new UserPositionV2();

        uint256 deadline = block.timestamp + 1 days;

        // Construct upgrade data
        bytes memory upgradeData = abi.encodeWithSelector(
            userPosition.upgradeToAndCall.selector,
            address(userPositionV2),
            ""
        );

        // Generate signatures
        bytes[] memory signatures = new bytes[](2);
        (address signer2, uint256 signer2Key) = makeAddrAndKey("signer2");

        _addSigner(signer2);
        _updateThreshold(2);

        // Generate signatures with unauthorized signer
        (, uint256 unauthorizedKey) = makeAddrAndKey("unauthorized");

        // Get transaction hash
        bytes32 txHash = multiSig.hashTransaction(
            address(userPosition),
            upgradeData,
            multiSig.nonce(),
            deadline
        );

        signatures[0] = _signTransaction(unauthorizedKey, txHash);
        signatures[1] = _signTransaction(signer2Key, txHash);

        vm.expectRevert(MultiSig.MultiSig__InvalidSignature.selector);
        multiSig.executeTransaction(address(userPosition), upgradeData, deadline, signatures);
    }

    function test_RevertWhen_UpgradeDirectly() public {
        UserPositionV2 userPositionV2 = new UserPositionV2();

        // Try to call upgrade function directly
        vm.prank(vm.addr(deployerKey));
        vm.expectRevert(UUPSUpgradeableBase.UUPSUpgradeableBase__Unauthorized.selector);
        userPosition.upgradeToAndCall(address(userPositionV2), "");

        // Try to call upgrade function using contract owner
        address owner = userPosition.owner();
        vm.prank(owner);
        vm.expectRevert(UUPSUpgradeableBase.UUPSUpgradeableBase__Unauthorized.selector);
        userPosition.upgradeToAndCall(address(userPositionV2), "");
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

    function _signTransaction(
        uint256 privateKey,
        bytes32 digest
    ) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        return abi.encodePacked(r, s, v);
    }

    function _addSigner(address signer) internal {
        bytes memory data = abi.encodeWithSelector(SignerManager.addSigner.selector, signer);
        uint256 deadline = block.timestamp + 1 days;

        bytes32 txHash = multiSig.hashTransaction(
            address(signerManager),
            data,
            multiSig.nonce(),
            deadline
        );

        bytes[] memory signatures = new bytes[](1);
        signatures[0] = _signTransaction(deployerKey, txHash);

        vm.prank(vm.addr(deployerKey));
        multiSig.executeTransaction(address(signerManager), data, deadline, signatures);
    }

    function _updateThreshold(uint256 newThreshold) internal {
        bytes memory data = abi.encodeWithSelector(
            SignerManager.updateThreshold.selector,
            newThreshold
        );
        uint256 deadline = block.timestamp + 1 days;

        bytes32 txHash = multiSig.hashTransaction(
            address(signerManager),
            data,
            multiSig.nonce(),
            deadline
        );

        bytes[] memory signatures = new bytes[](1);
        signatures[0] = _signTransaction(deployerKey, txHash);

        vm.prank(vm.addr(deployerKey));
        multiSig.executeTransaction(address(signerManager), data, deadline, signatures);
    }
}
