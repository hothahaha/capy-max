// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {MultiSig} from "../../src/access/MultiSig.sol";
import {SignerManager} from "../../src/access/SignerManager.sol";
import {DeployScript} from "../../script/Deploy.s.sol";
import {HelperConfig} from "../../script/HelperConfig.s.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

contract MockTarget {
    uint256 public value;
    bool public called;

    function setValue(uint256 _value) external {
        value = _value;
        called = true;
    }
}

contract MultiSigTest is Test {
    using MessageHashUtils for bytes32;
    MultiSig public multiSig;
    SignerManager public signerManager;
    HelperConfig public helperConfig;
    MockTarget public target;
    address public owner;
    address public signer1;
    address public signer2;
    uint256 public signer1Key;
    uint256 public signer2Key;

    event TransactionExecuted(
        address indexed to,
        bytes data,
        uint256 nonce,
        uint256 deadline
    );

    function setUp() public {
        owner = makeAddr("owner");
        (signer2, signer2Key) = makeAddrAndKey("signer2");

        DeployScript deployer = new DeployScript();
        (, , , signerManager, multiSig, helperConfig) = deployer.run();
        (, , signer1Key) = helperConfig.activeNetworkConfig();
        signer1 = vm.addr(signer1Key);

        target = new MockTarget();
    }

    function test_Initialize() public view {
        assertEq(address(multiSig.signerManager()), address(signerManager));
    }

    function test_ExecuteTransaction() public {
        uint256 newValue = 42;
        bytes memory data = abi.encodeWithSelector(
            MockTarget.setValue.selector,
            newValue
        );
        uint256 deadline = block.timestamp + 1 days;

        bytes32 txHash = _hashTransaction(
            address(multiSig),
            address(target),
            data,
            0,
            deadline
        );

        bytes[] memory signatures = new bytes[](1);
        signatures[0] = _signTransaction(signer1Key, txHash);

        vm.expectEmit(true, true, true, true);
        emit TransactionExecuted(address(target), data, 0, deadline);

        vm.prank(signer1);
        multiSig.executeTransaction(
            address(target),
            data,
            deadline,
            signatures
        );

        assertTrue(target.called());
        assertEq(target.value(), newValue);
        assertEq(multiSig.nonce(), 1);
    }

    function test_RevertWhen_ExecuteExpiredTransaction() public {
        bytes memory data = abi.encodeWithSelector(
            MockTarget.setValue.selector,
            1
        );
        uint256 deadline = block.timestamp - 1;

        bytes32 txHash = _hashTransaction(
            address(multiSig),
            address(target),
            data,
            0,
            deadline
        );

        bytes[] memory signatures = new bytes[](1);
        signatures[0] = _signTransaction(signer1Key, txHash);

        vm.prank(signer1);
        vm.expectRevert(MultiSig.MultiSig__InvalidDeadline.selector);
        multiSig.executeTransaction(
            address(target),
            data,
            deadline,
            signatures
        );
    }

    function test_RevertWhen_ExecuteWithInvalidSignature() public {
        bytes memory data = abi.encodeWithSelector(
            MockTarget.setValue.selector,
            1
        );
        uint256 deadline = block.timestamp + 1 days;

        bytes32 txHash = _hashTransaction(
            address(multiSig),
            address(target),
            data,
            0,
            deadline
        );

        bytes[] memory signatures = new bytes[](1);
        signatures[0] = _signTransaction(signer2Key, txHash); // Using non-signer key

        vm.prank(signer1);
        vm.expectRevert(MultiSig.MultiSig__InvalidSignature.selector);
        multiSig.executeTransaction(
            address(target),
            data,
            deadline,
            signatures
        );
    }

    function test_RevertWhen_ExecuteWithDuplicateSignatures() public {
        // Add second signer and update threshold
        bytes memory addSignerData = abi.encodeWithSelector(
            SignerManager.addSigner.selector,
            signer2
        );
        uint256 deadline = block.timestamp + 1 days;

        // Add signer2
        bytes32 addSignerTxHash = _hashTransaction(
            address(multiSig),
            address(signerManager),
            addSignerData,
            0,
            deadline
        );

        bytes[] memory signatures = new bytes[](1);
        signatures[0] = _signTransaction(signer1Key, addSignerTxHash);

        vm.prank(signer1);
        multiSig.executeTransaction(
            address(signerManager),
            addSignerData,
            deadline,
            signatures
        );

        // Update threshold to 2
        bytes memory updateThresholdData = abi.encodeWithSelector(
            SignerManager.updateThreshold.selector,
            2
        );

        bytes32 updateThresholdTxHash = _hashTransaction(
            address(multiSig),
            address(signerManager),
            updateThresholdData,
            1,
            deadline
        );

        signatures = new bytes[](2);
        signatures[0] = _signTransaction(signer1Key, updateThresholdTxHash);
        signatures[1] = _signTransaction(signer2Key, updateThresholdTxHash);

        vm.prank(signer1);
        multiSig.executeTransaction(
            address(signerManager),
            updateThresholdData,
            deadline,
            signatures
        );

        // Try to execute with duplicate signatures
        bytes memory targetData = abi.encodeWithSelector(
            MockTarget.setValue.selector,
            42
        );

        bytes32 targetTxHash = _hashTransaction(
            address(multiSig),
            address(target),
            targetData,
            2,
            deadline
        );

        signatures = new bytes[](2);
        signatures[0] = _signTransaction(signer1Key, targetTxHash);
        signatures[1] = _signTransaction(signer1Key, targetTxHash); // Duplicate signature

        vm.prank(signer1);
        vm.expectRevert(MultiSig.MultiSig__DuplicateSignature.selector);
        multiSig.executeTransaction(
            address(target),
            targetData,
            deadline,
            signatures
        );
    }

    function test_RevertWhen_ExecuteWithInvalidSignatureLength() public {
        bytes memory data = abi.encodeWithSelector(
            MockTarget.setValue.selector,
            42
        );
        uint256 deadline = block.timestamp + 1 days;

        bytes[] memory signatures = new bytes[](1);
        signatures[0] = hex"1234"; // Invalid signature length

        vm.prank(signer1);
        vm.expectRevert(MultiSig.MultiSig__InvalidSignatureLength.selector);
        multiSig.executeTransaction(
            address(target),
            data,
            deadline,
            signatures
        );
    }

    function test_RevertWhen_ExecuteWithInsufficientSignatures() public {
        // Add second signer and update threshold
        bytes memory addSignerData = abi.encodeWithSelector(
            SignerManager.addSigner.selector,
            signer2
        );
        uint256 deadline = block.timestamp + 1 days;

        // Add signer2
        bytes32 addSignerTxHash = _hashTransaction(
            address(multiSig),
            address(signerManager),
            addSignerData,
            0,
            deadline
        );

        bytes[] memory signatures = new bytes[](1);
        signatures[0] = _signTransaction(signer1Key, addSignerTxHash);

        vm.prank(signer1);
        multiSig.executeTransaction(
            address(signerManager),
            addSignerData,
            deadline,
            signatures
        );

        // Update threshold to 2
        bytes memory updateThresholdData = abi.encodeWithSelector(
            SignerManager.updateThreshold.selector,
            2
        );

        bytes32 updateThresholdTxHash = _hashTransaction(
            address(multiSig),
            address(signerManager),
            updateThresholdData,
            1,
            deadline
        );

        signatures = new bytes[](2);
        signatures[0] = _signTransaction(signer1Key, updateThresholdTxHash);
        signatures[1] = _signTransaction(signer2Key, updateThresholdTxHash);

        vm.prank(signer1);
        multiSig.executeTransaction(
            address(signerManager),
            updateThresholdData,
            deadline,
            signatures
        );

        // Try to execute with insufficient signatures
        bytes memory targetData = abi.encodeWithSelector(
            MockTarget.setValue.selector,
            42
        );

        bytes32 targetTxHash = _hashTransaction(
            address(multiSig),
            address(target),
            targetData,
            2,
            deadline
        );

        signatures = new bytes[](1); // Only one signature when two are required
        signatures[0] = _signTransaction(signer1Key, targetTxHash);

        vm.prank(signer1);
        vm.expectRevert(MultiSig.MultiSig__InsufficientSignatures.selector);
        multiSig.executeTransaction(
            address(target),
            targetData,
            deadline,
            signatures
        );
    }

    function test_RevertWhen_ExecuteWithZeroSignatures() public {
        bytes memory data = abi.encodeWithSelector(
            MockTarget.setValue.selector,
            42
        );
        uint256 deadline = block.timestamp + 1 days;

        bytes[] memory signatures = new bytes[](0);

        vm.prank(signer1);
        vm.expectRevert(MultiSig.MultiSig__InsufficientSignatures.selector);
        multiSig.executeTransaction(
            address(target),
            data,
            deadline,
            signatures
        );
    }

    function test_RevertWhen_ExecuteWithZeroAddress() public {
        bytes memory data = abi.encodeWithSelector(
            MockTarget.setValue.selector,
            42
        );
        uint256 deadline = block.timestamp + 1 days;

        bytes32 txHash = _hashTransaction(
            address(multiSig),
            address(0),
            data,
            0,
            deadline
        );

        bytes[] memory signatures = new bytes[](1);
        signatures[0] = _signTransaction(signer1Key, txHash);

        vm.prank(signer1);
        vm.expectRevert(MultiSig.MultiSig__InvalidTarget.selector);
        multiSig.executeTransaction(address(0), data, deadline, signatures);
    }

    function test_ExecuteWithMultipleSigners() public {
        // Add second signer and update threshold
        bytes memory addSignerData = abi.encodeWithSelector(
            SignerManager.addSigner.selector,
            signer2
        );
        uint256 deadline = block.timestamp + 1 days;
        uint256 currentNonce = multiSig.nonce();

        bytes32 addSignerTxHash = _hashTransaction(
            address(multiSig),
            address(signerManager),
            addSignerData,
            currentNonce,
            deadline
        );

        bytes[] memory signatures = new bytes[](1);
        signatures[0] = _signTransaction(signer1Key, addSignerTxHash);

        vm.prank(signer1);
        multiSig.executeTransaction(
            address(signerManager),
            addSignerData,
            deadline,
            signatures
        );

        bytes memory updateThresholdData = abi.encodeWithSelector(
            SignerManager.updateThreshold.selector,
            2
        );

        currentNonce = multiSig.nonce();
        bytes32 updateThresholdTxHash = _hashTransaction(
            address(multiSig),
            address(signerManager),
            updateThresholdData,
            currentNonce,
            deadline
        );

        signatures = new bytes[](2);
        signatures[0] = _signTransaction(signer1Key, updateThresholdTxHash);
        signatures[1] = _signTransaction(signer2Key, updateThresholdTxHash);

        vm.prank(signer1);
        multiSig.executeTransaction(
            address(signerManager),
            updateThresholdData,
            deadline,
            signatures
        );

        // Test transaction with multiple signatures
        bytes memory targetData = abi.encodeWithSelector(
            MockTarget.setValue.selector,
            42
        );

        currentNonce = multiSig.nonce();
        bytes32 targetTxHash = _hashTransaction(
            address(multiSig),
            address(target),
            targetData,
            currentNonce,
            deadline
        );

        signatures = new bytes[](2);
        signatures[0] = _signTransaction(signer1Key, targetTxHash);
        signatures[1] = _signTransaction(signer2Key, targetTxHash);

        vm.prank(signer1);
        multiSig.executeTransaction(
            address(target),
            targetData,
            deadline,
            signatures
        );

        assertTrue(target.called());
        assertEq(target.value(), 42);
    }

    // Helper functions
    function _hashTransaction(
        address verifyingContract,
        address to,
        bytes memory data,
        uint256 nonce,
        uint256 deadline
    ) internal view returns (bytes32) {
        bytes32 txHash = MultiSig(verifyingContract).hashTransaction(
            to,
            data,
            nonce,
            deadline
        );
        return txHash.toEthSignedMessageHash();
    }

    function _signTransaction(
        uint256 privateKey,
        bytes32 digest
    ) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        return abi.encodePacked(r, s, v);
    }
}
