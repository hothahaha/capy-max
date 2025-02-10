// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {MultiSig} from "../../src/access/MultiSig.sol";
import {SignerManager} from "../../src/access/SignerManager.sol";
import {DeployScript} from "../../script/Deploy.s.sol";
import {HelperConfig} from "../../script/HelperConfig.s.sol";
import {UUPSUpgradeableBase} from "../../src/upgradeable/UUPSUpgradeableBase.sol";

contract MockTarget {
    uint256 public value;
    bool public called;

    function setValue(uint256 _value) external {
        value = _value;
        called = true;
    }
}

contract MultiSigTest is Test {
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

    event Upgraded(address indexed implementation);
    event OwnershipTransferred(
        address indexed previousOwner,
        address indexed newOwner
    );

    error InvalidInitialization();
    error OwnableUnauthorizedAccount(address account);

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
        assertEq(multiSig.owner(), vm.addr(signer1Key));
        assertEq(address(multiSig.signerManager()), address(signerManager));
        assertEq(multiSig.nonce(), 0);
    }

    function test_RevertWhen_ReinitializeMultiSig() public {
        vm.expectRevert(InvalidInitialization.selector);
        multiSig.initialize(signer1, address(signerManager));
    }

    function test_TransferOwnership() public {
        address newOwner = makeAddr("newOwner");

        vm.expectEmit(true, true, true, true);
        emit OwnershipTransferred(vm.addr(signer1Key), newOwner);

        vm.prank(vm.addr(signer1Key));
        multiSig.transferOwnership(newOwner);

        assertEq(multiSig.owner(), newOwner);
    }

    function test_RevertWhen_TransferOwnershipUnauthorized() public {
        address newOwner = makeAddr("newOwner");
        vm.prank(address(1));
        vm.expectRevert(
            abi.encodeWithSelector(
                OwnableUnauthorizedAccount.selector,
                address(1)
            )
        );
        multiSig.transferOwnership(newOwner);
    }

    function test_ExecuteTransaction() public {
        uint256 newValue = 42;
        bytes memory data = abi.encodeWithSelector(
            MockTarget.setValue.selector,
            newValue
        );
        uint256 deadline = block.timestamp + 1 days;

        bytes32 txHash = multiSig.hashTransaction(
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

        bytes32 txHash = multiSig.hashTransaction(
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

        bytes32 txHash = multiSig.hashTransaction(
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
        bytes32 addSignerTxHash = multiSig.hashTransaction(
            address(signerManager),
            addSignerData,
            multiSig.nonce(),
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

        bytes32 updateThresholdTxHash = multiSig.hashTransaction(
            address(signerManager),
            updateThresholdData,
            multiSig.nonce(),
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

        bytes32 targetTxHash = multiSig.hashTransaction(
            address(target),
            targetData,
            multiSig.nonce(),
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
        bytes32 addSignerTxHash = multiSig.hashTransaction(
            address(signerManager),
            addSignerData,
            multiSig.nonce(),
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

        bytes32 updateThresholdTxHash = multiSig.hashTransaction(
            address(signerManager),
            updateThresholdData,
            multiSig.nonce(),
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

        bytes32 targetTxHash = multiSig.hashTransaction(
            address(target),
            targetData,
            multiSig.nonce(),
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

        bytes32 txHash = multiSig.hashTransaction(
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

        bytes32 addSignerTxHash = multiSig.hashTransaction(
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
        bytes32 updateThresholdTxHash = multiSig.hashTransaction(
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
        bytes32 targetTxHash = multiSig.hashTransaction(
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
        assertTrue(signerManager.isSigner(signer2));
    }

    function _signTransaction(
        uint256 privateKey,
        bytes32 digest
    ) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        return abi.encodePacked(r, s, v);
    }
}
