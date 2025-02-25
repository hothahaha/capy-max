// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test, console} from "forge-std/Test.sol";
import {MultiSig} from "../../src/access/MultiSig.sol";
import {SignerManager} from "../../src/access/SignerManager.sol";
import {ITransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import {IUpgradeableTest} from "./IUpgradeableTest.sol";
import {UUPSUpgradeableBase} from "../../src/upgradeable/UUPSUpgradeableBase.sol";
import {DeployScript} from "../../script/Deploy.s.sol";
import {HelperConfig} from "../../script/HelperConfig.s.sol";

abstract contract BaseContractUpgradeTest is Test, IUpgradeableTest {
    event Upgraded(address indexed implementation);

    struct UpgradeTestParams {
        address target;
        address implementation;
        bytes data;
        uint256 deadline;
        bytes[] signatures;
    }

    MultiSig internal multiSig;
    SignerManager internal signerManager;
    HelperConfig internal helperConfig;
    uint256 internal deployerKey;
    address internal deployer;

    function _prepareUpgradeTest(
        address target,
        address newImplementation
    ) internal returns (UpgradeTestParams memory) {
        uint256 deadline = block.timestamp + 1 days;
        bytes memory upgradeData = abi.encodeWithSelector(
            ITransparentUpgradeableProxy.upgradeToAndCall.selector,
            newImplementation,
            ""
        );

        (, uint256 signer2Key) = _setupSecondSigner();

        bytes[] memory signatures = new bytes[](2);
        bytes32 txHash = multiSig.hashTransaction(target, upgradeData, multiSig.nonce(), deadline);

        signatures[0] = _signTransaction(deployerKey, txHash);
        signatures[1] = _signTransaction(signer2Key, txHash);

        return
            UpgradeTestParams({
                target: target,
                implementation: newImplementation,
                data: upgradeData,
                deadline: deadline,
                signatures: signatures
            });
    }

    function _executeUpgradeTest(UpgradeTestParams memory params) internal {
        multiSig.executeTransaction(params.target, params.data, params.deadline, params.signatures);
    }

    function _setupSecondSigner() internal returns (address signer, uint256 signerKey) {
        (signer, signerKey) = makeAddrAndKey("signer2");
        _addSigner(signer);
        _updateThreshold(2);
    }

    function _signTransaction(
        uint256 privateKey,
        bytes32 txHash
    ) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, txHash);
        return abi.encodePacked(r, s, v);
    }

    function _addSigner(address signer) internal {
        _executeMultiSigTx(
            address(signerManager),
            abi.encodeWithSelector(SignerManager.addSigner.selector, signer)
        );
    }

    function _updateThreshold(uint256 newThreshold) internal {
        _executeMultiSigTx(
            address(signerManager),
            abi.encodeWithSelector(SignerManager.updateThreshold.selector, newThreshold)
        );
    }

    function _executeMultiSigTx(address target, bytes memory data) internal {
        uint256 deadline = block.timestamp + 1 days;
        bytes[] memory signatures = new bytes[](1);

        signatures[0] = _signTransaction(
            deployerKey,
            multiSig.hashTransaction(target, data, multiSig.nonce(), deadline)
        );

        vm.prank(vm.addr(deployerKey));
        multiSig.executeTransaction(target, data, deadline, signatures);
    }

    function test_UpgradeContract() public virtual {
        address implementation = getNewImplementation();
        UpgradeTestParams memory params = _prepareUpgradeTest(
            getUpgradeableContract(),
            implementation
        );

        _executeUpgradeTest(params);
        validateUpgrade();
    }

    function test_RevertWhen_UpgradeUnauthorized() public {
        address implementation = getNewImplementation();
        (, uint256 unauthorizedKey) = makeAddrAndKey("unauthorized");

        UpgradeTestParams memory params = _prepareUpgradeTest(
            getUpgradeableContract(),
            implementation
        );

        params.signatures[0] = _signTransaction(unauthorizedKey, keccak256("invalid"));

        vm.expectRevert(MultiSig.MultiSig__InvalidSignature.selector);
        _executeUpgradeTest(params);
    }

    function test_RevertWhen_UpgradeDirectly() public virtual {
        address implementation = getNewImplementation();
        address target = getUpgradeableContract();

        vm.prank(vm.addr(deployerKey));
        vm.expectRevert(UUPSUpgradeableBase.UUPSUpgradeableBase__Unauthorized.selector);
        UUPSUpgradeableBase(target).upgradeToAndCall(implementation, "");
    }
}
