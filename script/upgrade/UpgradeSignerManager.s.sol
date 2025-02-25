// script/upgrade/UpgradeSignerManager.s.sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Script, console} from "forge-std/Script.sol";
import {SignerManager} from "../../src/access/SignerManager.sol";
import {MultiSig} from "../../src/access/MultiSig.sol";
import {BaseUpgrade} from "./BaseUpgrade.s.sol";

contract UpgradeSignerManager is BaseUpgrade {
    function run() external {
        address proxyAddress = vm.envAddress("SIGNER_MANAGER_PROXY");
        address multiSig = vm.envAddress("MULTISIG_ADDRESS");
        uint256[] memory privateKeys = vm.envUint("PRIVATE_KEYS", ",");

        vm.startBroadcast();
        SignerManager newImplementation = new SignerManager();
        console.log("New SignerManager implementation deployed at:", address(newImplementation));

        UpgradeParams memory params = UpgradeParams({
            proxyAddress: proxyAddress,
            multiSig: multiSig,
            newImplementation: address(newImplementation),
            privateKeys: privateKeys,
            deadline: block.timestamp + 1 days
        });

        _executeUpgrade(params);
        vm.stopBroadcast();

        address newImpl = SignerManager(proxyAddress).implementation();
        console.log("Upgrade completed. New implementation:", newImpl);
        require(newImpl == address(newImplementation), "Upgrade failed");
    }
}
