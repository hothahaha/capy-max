// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {CpToken} from "../../src/tokens/CpToken.sol";
import {MultiSig} from "../../src/access/MultiSig.sol";
import {SignerManager} from "../../src/access/SignerManager.sol";
import {DeployScript} from "../../script/Deploy.s.sol";
import {HelperConfig} from "../../script/HelperConfig.s.sol";
import {UUPSUpgradeableBase} from "../../src/upgradeable/UUPSUpgradeableBase.sol";

contract CpTokenV2 is CpToken {
    uint256 public newVariable;

    function setNewVariable(uint256 _value) external {
        newVariable = _value;
    }

    function version() external pure returns (string memory) {
        return "V2";
    }
}

contract CpTokenUpgradesTest is Test {
    CpToken public cpToken;
    MultiSig public multiSig;
    SignerManager public signerManager;
    HelperConfig public helperConfig;
    uint256 public deployerKey;

    bytes32 public constant IMPLEMENTATION_SLOT =
        0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    event Upgraded(address indexed implementation);

    function setUp() public {
        DeployScript deployer = new DeployScript();
        (, cpToken, , signerManager, multiSig, helperConfig) = deployer.run();
        (, , , , , deployerKey, , ) = helperConfig.activeNetworkConfig();
    }

    function test_UpgradeToV2() public {
        CpTokenV2 cpTokenV2 = new CpTokenV2();

        uint256 deadline = block.timestamp + 1 days;

        // Construct upgrade data
        bytes memory upgradeData = abi.encodeWithSelector(
            cpToken.upgradeToAndCall.selector,
            address(cpTokenV2),
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
            address(cpToken),
            upgradeData,
            multiSig.nonce(),
            deadline
        );

        signatures[0] = _signTransaction(deployerKey, txHash);
        signatures[1] = _signTransaction(signer2Key, txHash);

        vm.expectEmit(true, true, true, true);
        emit Upgraded(address(cpTokenV2));

        multiSig.executeTransaction(address(cpToken), upgradeData, deadline, signatures);

        CpTokenV2 upgradedCpToken = CpTokenV2(address(cpToken));
        assertEq(upgradedCpToken.version(), "V2");
    }

    function test_RevertWhen_UpgradeUnauthorized() public {
        CpTokenV2 cpTokenV2 = new CpTokenV2();

        uint256 deadline = block.timestamp + 1 days;

        // Construct upgrade data
        bytes memory upgradeData = abi.encodeWithSelector(
            cpToken.upgradeToAndCall.selector,
            address(cpTokenV2),
            ""
        );

        // Generate signatures
        bytes[] memory signatures = new bytes[](2);
        (address signer2, uint256 signer2Key) = makeAddrAndKey("signer2");

        _addSigner(signer2);
        _updateThreshold(2);

        // Generate signatures using unauthorized signer
        (, uint256 unauthorizedKey) = makeAddrAndKey("unauthorized");

        // Get transaction hash
        bytes32 txHash = multiSig.hashTransaction(
            address(cpToken),
            upgradeData,
            multiSig.nonce(),
            deadline
        );

        signatures[0] = _signTransaction(unauthorizedKey, txHash);
        signatures[1] = _signTransaction(signer2Key, txHash);

        vm.expectRevert(MultiSig.MultiSig__InvalidSignature.selector);
        multiSig.executeTransaction(address(cpToken), upgradeData, deadline, signatures);
    }

    function test_RevertWhen_UpgradeDirectly() public {
        CpTokenV2 cpTokenV2 = new CpTokenV2();

        // Try to call upgrade function directly
        vm.prank(vm.addr(deployerKey));
        vm.expectRevert(UUPSUpgradeableBase.UUPSUpgradeableBase__Unauthorized.selector);
        cpToken.upgradeToAndCall(address(cpTokenV2), "");

        // Try to call upgrade function using contract owner
        address owner = cpToken.owner();
        vm.prank(owner);
        vm.expectRevert(UUPSUpgradeableBase.UUPSUpgradeableBase__Unauthorized.selector);
        cpToken.upgradeToAndCall(address(cpTokenV2), "");
    }

    // Helper functions
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
