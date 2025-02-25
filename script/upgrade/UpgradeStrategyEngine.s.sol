// script/upgrade/UpgradeStrategyEngine.s.sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Script, console} from "forge-std/Script.sol";
import {StrategyEngine} from "../../src/StrategyEngine.sol";
import {MultiSig} from "../../src/access/MultiSig.sol";
import {ITransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import {BaseUpgrade} from "./BaseUpgrade.s.sol";

contract UpgradeStrategyEngine is BaseUpgrade {
    function run() external {
        address proxyAddress = vm.envAddress("STRATEGY_ENGINE_PROXY");
        address multiSig = vm.envAddress("MULTISIG_ADDRESS");
        uint256[] memory privateKeys = vm.envUint("PRIVATE_KEYS", ",");

        vm.startBroadcast();
        StrategyEngine newImplementation = new StrategyEngine();
        console.log("New implementation deployed at:", address(newImplementation));

        UpgradeParams memory params = UpgradeParams({
            proxyAddress: proxyAddress,
            multiSig: multiSig,
            newImplementation: address(newImplementation),
            privateKeys: privateKeys,
            deadline: block.timestamp + 1 days
        });

        _executeUpgrade(params);
        vm.stopBroadcast();

        address newImpl = StrategyEngine(proxyAddress).implementation();
        console.log("Upgrade completed. New implementation:", newImpl);
        require(newImpl == address(newImplementation), "Upgrade failed");
    }
}
