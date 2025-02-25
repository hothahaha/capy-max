// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {MultiSig} from "../../src/access/MultiSig.sol";
import {SignerManager} from "../../src/access/SignerManager.sol";
import {ITransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import {IUpgradeableTest} from "./IUpgradeableTest.sol";
import {UUPSUpgradeableBase} from "../../src/upgradeable/UUPSUpgradeableBase.sol";
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

    // 存储槽常量
    bytes32 internal constant IMPLEMENTATION_SLOT =
        0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    function _prepareUpgradeTest(
        address target,
        address newImplementation
    ) internal returns (UpgradeTestParams memory) {
        // 准备升级数据
        bytes memory upgradeData = abi.encodeWithSelector(
            ITransparentUpgradeableProxy.upgradeToAndCall.selector,
            newImplementation,
            ""
        );

        uint256 deadline = block.timestamp + 1 days;
        bytes[] memory signatures = new bytes[](2);

        // 获取交易哈希
        bytes32 txHash = multiSig.hashTransaction(target, upgradeData, multiSig.nonce(), deadline);

        // 生成签名
        (address signer2, uint256 signer2Key) = makeAddrAndKey("signer2");
        _addSigner(signer2);
        _updateThreshold(2);

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

        // 验证升级成功
        bytes32 implSlot = vm.load(params.target, IMPLEMENTATION_SLOT);
        address currentImpl = address(uint160(uint256(implSlot)));
        assertEq(currentImpl, params.implementation);
    }

    function _signTransaction(
        uint256 privateKey,
        bytes32 txHash
    ) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, txHash);
        return abi.encodePacked(r, s, v);
    }

    function _addSigner(address signer) internal {
        vm.prank(address(multiSig));
        signerManager.addSigner(signer);
    }

    function _updateThreshold(uint256 newThreshold) internal {
        vm.prank(address(multiSig));
        signerManager.updateThreshold(newThreshold);
    }

    function test_RevertWhen_UpgradeDirectly() public virtual {
        address newImplementation = getNewImplementation();
        vm.prank(vm.addr(deployerKey));
        vm.expectRevert(UUPSUpgradeableBase.UUPSUpgradeableBase__Unauthorized.selector);
        UUPSUpgradeableBase(getUpgradeableContract()).upgradeToAndCall(newImplementation, "");
    }
}
