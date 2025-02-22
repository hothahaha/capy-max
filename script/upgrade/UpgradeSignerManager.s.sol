// script/upgrade/UpgradeSignerManager.s.sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Script, console} from "forge-std/Script.sol";
import {SignerManager} from "../../src/access/SignerManager.sol";
import {MultiSig} from "../../src/access/MultiSig.sol";
import {ITransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";

contract UpgradeSignerManager is Script {
    function run() external {
        // 1. 从环境变量加载配置
        address proxyAddress = vm.envAddress("SIGNER_MANAGER_PROXY");
        address multiSig = vm.envAddress("MULTISIG_ADDRESS");
        uint256[] memory privateKeys = vm.envUint("PRIVATE_KEYS", ",");

        // 2. 部署新的实现合约
        vm.startBroadcast();
        SignerManager newImplementation = new SignerManager();
        console.log("New SignerManager implementation deployed at:", address(newImplementation));

        // 3. 设置截止时间
        uint256 deadline = block.timestamp + 1 days;

        // 4. Construct upgrade data
        bytes memory upgradeData = abi.encodeWithSelector(
            ITransparentUpgradeableProxy.upgradeToAndCall.selector,
            address(newImplementation),
            ""
        );

        bytes32 txHash = MultiSig(multiSig).hashTransaction(
            proxyAddress,
            upgradeData,
            MultiSig(multiSig).nonce(),
            deadline
        );

        // 5. Generate signatures
        bytes[] memory signatures = new bytes[](privateKeys.length);
        for (uint i = 0; i < privateKeys.length; i++) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKeys[i], txHash);
            signatures[i] = abi.encodePacked(r, s, v);
        }

        // 6. 执行升级
        MultiSig(multiSig).executeTransaction(proxyAddress, upgradeData, deadline, signatures);

        vm.stopBroadcast();

        // 8. 验证升级结果
        address newImpl = SignerManager(proxyAddress).implementation();
        console.log("Upgrade completed. New implementation:", newImpl);
        require(newImpl == address(newImplementation), "Upgrade failed");
    }
}
