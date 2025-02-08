// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Script} from "forge-std/Script.sol";
import {DeployScript} from "./Deploy.s.sol";
import {HelperConfig} from "./HelperConfig.s.sol";
import {MultiSig} from "../src/access/MultiSig.sol";
import {SignerManager} from "../src/access/SignerManager.sol";
import {ITransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";

contract VerifyDeployment is Script {
    error VerifyDeployment__InvalidSignature();
    error VerifyDeployment__InsufficientSignatures();
    error VerifyDeployment__Expired();
    error VerifyDeployment__DuplicateSigner();
    error VerifyDeployment__UpgradeFailed();

    function verifyAndDeploy(
        address multiSig,
        bytes[] calldata signatures,
        uint256 deadline
    ) external {
        // 验证时间戳
        if (block.timestamp > deadline) revert VerifyDeployment__Expired();

        // 获取 SignerManager 地址
        SignerManager signerManager = SignerManager(
            MultiSig(multiSig).signerManager()
        );

        // 获取所需签名阈值
        uint256 threshold = signerManager.getThreshold();

        // 验证签名数量
        if (signatures.length < threshold) {
            revert VerifyDeployment__InsufficientSignatures();
        }

        // 构造部署数据
        bytes memory deployData = abi.encodeWithSelector(
            DeployScript.run.selector
        );

        // 获取交易哈希
        bytes32 txHash = MultiSig(multiSig).hashTransaction(
            address(this),
            deployData,
            MultiSig(multiSig).nonce(),
            deadline
        );

        // 验证每个签名
        address[] memory recoveredSigners = new address[](signatures.length);
        uint256 validSignersCount = 0;

        for (uint256 i = 0; i < signatures.length; i++) {
            // 验证签名长度
            if (signatures[i].length != 65) {
                revert VerifyDeployment__InvalidSignature();
            }

            // 恢复签名者地址
            address signer = _recoverSigner(txHash, signatures[i]);

            // 验证签名者权限
            if (!signerManager.isSigner(signer)) {
                revert VerifyDeployment__InvalidSignature();
            }

            // 检查重复签名
            for (uint256 j = 0; j < i; j++) {
                if (signer == recoveredSigners[j]) {
                    revert VerifyDeployment__DuplicateSigner();
                }
            }

            recoveredSigners[i] = signer;
            validSignersCount++;
        }

        // 再次验证有效签名数量
        if (validSignersCount < threshold) {
            revert VerifyDeployment__InsufficientSignatures();
        }

        // 如果验证通过，继续部署
        DeployScript deployer = new DeployScript();
        deployer.run();
    }

    function verifyAndUpgrade(
        address multiSig,
        address proxy,
        address newImplementation,
        bytes[] calldata signatures,
        uint256 deadline
    ) external {
        // 验证时间戳
        if (block.timestamp > deadline) revert VerifyDeployment__Expired();

        // 获取 SignerManager 地址
        SignerManager signerManager = SignerManager(
            MultiSig(multiSig).signerManager()
        );

        // 获取所需签名阈值
        uint256 threshold = signerManager.getThreshold();

        // 验证签名数量
        if (signatures.length < threshold) {
            revert VerifyDeployment__InsufficientSignatures();
        }

        // 构造升级数据
        bytes memory upgradeData = abi.encodeWithSelector(
            ITransparentUpgradeableProxy.upgradeToAndCall.selector,
            newImplementation,
            ""
        );

        // 获取交易哈希
        bytes32 txHash = MultiSig(multiSig).hashTransaction(
            proxy,
            upgradeData,
            MultiSig(multiSig).nonce(),
            deadline
        );

        // 验证每个签名
        address[] memory recoveredSigners = new address[](signatures.length);
        uint256 validSignersCount = 0;

        for (uint256 i = 0; i < signatures.length; i++) {
            // 验证签名长度
            if (signatures[i].length != 65) {
                revert VerifyDeployment__InvalidSignature();
            }

            // 恢复签名者地址
            address signer = _recoverSigner(txHash, signatures[i]);

            // 验证签名者权限
            if (!signerManager.isSigner(signer)) {
                revert VerifyDeployment__InvalidSignature();
            }

            // 检查重复签名
            for (uint256 j = 0; j < i; j++) {
                if (signer == recoveredSigners[j]) {
                    revert VerifyDeployment__DuplicateSigner();
                }
            }

            recoveredSigners[i] = signer;
            validSignersCount++;
        }

        // 再次验证有效签名数量
        if (validSignersCount < threshold) {
            revert VerifyDeployment__InsufficientSignatures();
        }

        // 如果验证通过，执行升级
        try
            MultiSig(multiSig).executeTransaction(
                proxy,
                upgradeData,
                deadline,
                signatures
            )
        {} catch {
            revert VerifyDeployment__UpgradeFailed();
        }
    }

    function _recoverSigner(
        bytes32 hash,
        bytes memory signature
    ) internal pure returns (address) {
        bytes32 r;
        bytes32 s;
        uint8 v;

        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := byte(0, mload(add(signature, 96)))
        }

        return ecrecover(hash, v, r, s);
    }
}
