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
        assertTrue(signerManager.isSigner(vm.addr(deployerKey)));
        assertEq(signerManager.getThreshold(), 1);
        assertEq(address(signerManager.multiSig()), address(multiSig));
    }

    function test_AddSigner() public {
        address newSigner = makeAddr("newSigner");
        bytes memory data = abi.encodeWithSelector(
            SignerManager.addSigner.selector,
            newSigner
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

        vm.expectEmit(true, true, true, true);
        emit SignerAdded(newSigner);

        vm.prank(vm.addr(deployerKey));
        multiSig.executeTransaction(
            address(signerManager),
            data,
            deadline,
            signatures
        );

        assertTrue(signerManager.isSigner(newSigner));
    }

    function test_RevertWhen_AddExistingSigner() public {
        // 记录当前的 nonce
        uint256 nonce = multiSig.nonce();

        // 首先添加签名者
        bytes memory addData = abi.encodeWithSelector(
            SignerManager.addSigner.selector,
            signer1
        );
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
        multiSig.executeTransaction(
            address(signerManager),
            addData,
            addDeadline,
            addSignatures
        );

        // 使用更新后的 nonce
        nonce = multiSig.nonce();

        // 然后尝试再次添加相同的签名者
        bytes memory data = abi.encodeWithSelector(
            SignerManager.addSigner.selector,
            signer1
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

        vm.expectRevert(MultiSig.MultiSig__ExecutionFailed.selector);

        vm.prank(vm.addr(deployerKey));
        multiSig.executeTransaction(
            address(signerManager),
            data,
            deadline,
            signatures
        );
    }

    function test_RemoveSigner() public {
        // 记录当前的 nonce
        uint256 nonce = multiSig.nonce();

        // 首先添加一个签名者
        bytes memory addData = abi.encodeWithSelector(
            SignerManager.addSigner.selector,
            signer1
        );
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
        multiSig.executeTransaction(
            address(signerManager),
            addData,
            addDeadline,
            addSignatures
        );

        // 使用更新后的 nonce
        nonce = multiSig.nonce();

        // 然后尝试移除该签名者
        bytes memory data = abi.encodeWithSelector(
            SignerManager.removeSigner.selector,
            signer1
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
        emit SignerRemoved(signer1);

        vm.prank(vm.addr(deployerKey));
        multiSig.executeTransaction(
            address(signerManager),
            data,
            deadline,
            signatures
        );

        assertFalse(signerManager.isSigner(signer1));
    }

    function test_RevertWhen_RemoveNonExistentSigner() public {
        address nonSigner = makeAddr("nonSigner");
        bytes memory data = abi.encodeWithSelector(
            SignerManager.removeSigner.selector,
            nonSigner
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
        multiSig.executeTransaction(
            address(signerManager),
            data,
            deadline,
            signatures
        );
    }

    function test_UpdateThreshold() public {
        // 记录当前的 nonce
        uint256 nonce = multiSig.nonce();

        // 首先添加一个签名者
        bytes memory addData = abi.encodeWithSelector(
            SignerManager.addSigner.selector,
            signer1
        );
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
        multiSig.executeTransaction(
            address(signerManager),
            addData,
            addDeadline,
            addSignatures
        );

        // 使用更新后的 nonce
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
        multiSig.executeTransaction(
            address(signerManager),
            data,
            deadline,
            signatures
        );

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
        multiSig.executeTransaction(
            address(signerManager),
            data,
            deadline,
            signatures
        );
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
