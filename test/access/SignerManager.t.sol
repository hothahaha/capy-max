// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {SignerManager} from "../../src/access/SignerManager.sol";
import {MultiSig} from "../../src/access/MultiSig.sol";
import {DeployScript} from "../../script/Deploy.s.sol";
import {HelperConfig} from "../../script/HelperConfig.s.sol";

contract SignerManagerTest is Test {
    HelperConfig public helperConfig;
    SignerManager public signerManager;
    MultiSig public multiSig;
    address public owner;
    address public signer1;
    address public signer2;
    uint256 public signer1Key;
    uint256 public signer2Key;
    uint256 public deployerKey;

    event SignerAdded(address indexed signer);
    event SignerRemoved(address indexed signer);
    event ThresholdUpdated(uint256 oldThreshold, uint256 newThreshold);

    function setUp() public {
        owner = makeAddr("owner");
        (signer1, signer1Key) = makeAddrAndKey("signer1");
        (signer2, signer2Key) = makeAddrAndKey("signer2");

        DeployScript deployer = new DeployScript();
        (, , , signerManager, multiSig, helperConfig) = deployer.run();
        (, , , , , deployerKey, , ) = helperConfig.activeNetworkConfig();
    }

    function test_Initialize() public view {
        // Verify if DEPLOYER is a signer
        assertTrue(signerManager.isSigner(vm.addr(deployerKey)));
        assertEq(signerManager.getThreshold(), 1);
        assertEq(address(signerManager.multiSig()), address(multiSig));
    }

    function test_AddSigner() public {
        address newSigner = makeAddr("newSigner");
        bytes memory data = abi.encodeWithSelector(SignerManager.addSigner.selector, newSigner);
        uint256 deadline = block.timestamp + 1 days;

        bytes32 txHash = _hashTransaction(
            address(multiSig),
            address(signerManager),
            data,
            0,
            deadline
        );

        bytes[] memory signatures = new bytes[](1);
        signatures[0] = _signTransaction(deployerKey, txHash);

        vm.expectEmit(true, true, true, true);
        emit SignerAdded(newSigner);

        vm.prank(vm.addr(deployerKey));
        multiSig.executeTransaction(address(signerManager), data, deadline, signatures);

        assertTrue(signerManager.isSigner(newSigner));
    }

    function test_RevertWhen_AddExistingSigner() public {
        // Record current nonce
        uint256 nonce = multiSig.nonce();

        // Use DEPLOYER as initial signer to add signer1
        bytes memory addSigner1Data = abi.encodeWithSelector(
            SignerManager.addSigner.selector,
            signer1
        );
        uint256 addDeadline = block.timestamp + 1 days;

        bytes32 addTxHash = _hashTransaction(
            address(multiSig),
            address(signerManager),
            addSigner1Data,
            nonce,
            addDeadline
        );

        bytes[] memory addSignatures = new bytes[](1);
        addSignatures[0] = _signTransaction(deployerKey, addTxHash);

        vm.prank(vm.addr(deployerKey));
        multiSig.executeTransaction(
            address(signerManager),
            addSigner1Data,
            addDeadline,
            addSignatures
        );

        // Use updated nonce
        nonce = multiSig.nonce();

        // Try to add the same signer again
        bytes memory data = abi.encodeWithSelector(SignerManager.addSigner.selector, signer1);
        uint256 deadline = block.timestamp + 1 days;

        bytes32 txHash = _hashTransaction(
            address(multiSig),
            address(signerManager),
            data,
            nonce,
            deadline
        );

        bytes[] memory signatures = new bytes[](1);
        signatures[0] = _signTransaction(deployerKey, txHash);

        vm.expectRevert(MultiSig.MultiSig__ExecutionFailed.selector);

        vm.prank(vm.addr(deployerKey));
        multiSig.executeTransaction(address(signerManager), data, deadline, signatures);
    }

    function test_RemoveSigner() public {
        // Record current nonce
        uint256 nonce = multiSig.nonce();

        // First add a signer
        bytes memory addData = abi.encodeWithSelector(SignerManager.addSigner.selector, signer1);
        uint256 addDeadline = block.timestamp + 1 days;

        bytes32 addTxHash = _hashTransaction(
            address(multiSig),
            address(signerManager),
            addData,
            nonce,
            addDeadline
        );

        bytes[] memory addSignatures = new bytes[](1);
        addSignatures[0] = _signTransaction(deployerKey, addTxHash);

        vm.prank(vm.addr(deployerKey));
        multiSig.executeTransaction(address(signerManager), addData, addDeadline, addSignatures);

        // Use updated nonce
        nonce = multiSig.nonce();

        // Then try to remove that signer
        bytes memory data = abi.encodeWithSelector(SignerManager.removeSigner.selector, signer1);
        uint256 deadline = block.timestamp + 1 days;

        bytes32 txHash = _hashTransaction(
            address(multiSig),
            address(signerManager),
            data,
            nonce,
            deadline
        );

        bytes[] memory signatures = new bytes[](1);
        signatures[0] = _signTransaction(deployerKey, txHash);

        vm.expectEmit(true, true, true, true);
        emit SignerRemoved(signer1);

        vm.prank(vm.addr(deployerKey));
        multiSig.executeTransaction(address(signerManager), data, deadline, signatures);

        assertFalse(signerManager.isSigner(signer1));
    }

    function test_RevertWhen_RemoveNonExistentSigner() public {
        address nonSigner = makeAddr("nonSigner");
        bytes memory data = abi.encodeWithSelector(SignerManager.removeSigner.selector, nonSigner);
        uint256 deadline = block.timestamp + 1 days;

        bytes32 txHash = _hashTransaction(
            address(multiSig),
            address(signerManager),
            data,
            0,
            deadline
        );

        bytes[] memory signatures = new bytes[](1);
        signatures[0] = _signTransaction(deployerKey, txHash);

        vm.expectRevert(MultiSig.MultiSig__ExecutionFailed.selector);
        vm.prank(vm.addr(deployerKey));
        multiSig.executeTransaction(address(signerManager), data, deadline, signatures);
    }

    function test_UpdateThreshold() public {
        // Record current nonce
        uint256 nonce = multiSig.nonce();

        // First add a signer
        bytes memory addData = abi.encodeWithSelector(SignerManager.addSigner.selector, signer1);
        uint256 addDeadline = block.timestamp + 1 days;

        bytes32 addTxHash = _hashTransaction(
            address(multiSig),
            address(signerManager),
            addData,
            nonce,
            addDeadline
        );

        bytes[] memory addSignatures = new bytes[](1);
        addSignatures[0] = _signTransaction(deployerKey, addTxHash);

        vm.prank(vm.addr(deployerKey));
        multiSig.executeTransaction(address(signerManager), addData, addDeadline, addSignatures);

        // Use updated nonce
        nonce = multiSig.nonce();

        uint256 newThreshold = 2;
        bytes memory data = abi.encodeWithSelector(
            SignerManager.updateThreshold.selector,
            newThreshold
        );
        uint256 deadline = block.timestamp + 1 days;

        bytes32 txHash = _hashTransaction(
            address(multiSig),
            address(signerManager),
            data,
            nonce,
            deadline
        );

        bytes[] memory signatures = new bytes[](1);
        signatures[0] = _signTransaction(deployerKey, txHash);

        vm.expectEmit(true, true, true, true);
        emit ThresholdUpdated(1, newThreshold);

        vm.prank(vm.addr(deployerKey));
        multiSig.executeTransaction(address(signerManager), data, deadline, signatures);

        assertEq(signerManager.getThreshold(), newThreshold);
    }

    function test_RevertWhen_UpdateThresholdTooHigh() public {
        uint256 newThreshold = 3;

        bytes memory data = abi.encodeWithSelector(
            SignerManager.updateThreshold.selector,
            newThreshold
        );
        uint256 deadline = block.timestamp + 1 days;

        bytes32 txHash = _hashTransaction(
            address(multiSig),
            address(signerManager),
            data,
            0,
            deadline
        );

        bytes[] memory signatures = new bytes[](1);
        signatures[0] = _signTransaction(deployerKey, txHash);

        vm.expectRevert(MultiSig.MultiSig__ExecutionFailed.selector);
        vm.prank(vm.addr(deployerKey));
        multiSig.executeTransaction(address(signerManager), data, deadline, signatures);
    }

    function test_GetSigners() public {
        // Add two new signers
        address newSigner1 = makeAddr("newSigner1");
        address newSigner2 = makeAddr("newSigner2");

        // Add first signer
        bytes memory data1 = abi.encodeWithSelector(SignerManager.addSigner.selector, newSigner1);
        uint256 deadline = block.timestamp + 1 days;
        bytes32 txHash1 = _hashTransaction(
            address(multiSig),
            address(signerManager),
            data1,
            multiSig.nonce(),
            deadline
        );

        bytes[] memory signatures = new bytes[](1);
        signatures[0] = _signTransaction(deployerKey, txHash1);

        vm.prank(vm.addr(deployerKey));
        multiSig.executeTransaction(address(signerManager), data1, deadline, signatures);

        // Add second signer
        bytes memory data2 = abi.encodeWithSelector(SignerManager.addSigner.selector, newSigner2);
        bytes32 txHash2 = _hashTransaction(
            address(multiSig),
            address(signerManager),
            data2,
            multiSig.nonce(),
            deadline
        );

        signatures[0] = _signTransaction(deployerKey, txHash2);

        vm.prank(vm.addr(deployerKey));
        multiSig.executeTransaction(address(signerManager), data2, deadline, signatures);

        // Get all signers
        address[] memory allSigners = signerManager.getSigners();

        // Verify signer count
        assertEq(allSigners.length, 3); // deployer + 2 new signers

        // Verify signer list contains all added signers
        bool hasDeployer = false;
        bool hasSigner1 = false;
        bool hasSigner2 = false;

        for (uint256 i = 0; i < allSigners.length; i++) {
            if (allSigners[i] == vm.addr(deployerKey)) hasDeployer = true;
            if (allSigners[i] == newSigner1) hasSigner1 = true;
            if (allSigners[i] == newSigner2) hasSigner2 = true;
        }

        assertTrue(hasDeployer, "Deployer should be in signers list");
        assertTrue(hasSigner1, "Signer1 should be in signers list");
        assertTrue(hasSigner2, "Signer2 should be in signers list");
    }

    // Helper functions
    function _hashTransaction(
        address verifyingContract,
        address to,
        bytes memory data,
        uint256 nonce,
        uint256 deadline
    ) internal view returns (bytes32) {
        bytes32 txHash = MultiSig(verifyingContract).hashTransaction(to, data, nonce, deadline);
        return txHash;
    }

    function _signTransaction(
        uint256 privateKey,
        bytes32 digest
    ) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        return abi.encodePacked(r, s, v);
    }
}
