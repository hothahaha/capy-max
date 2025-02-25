// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Script, console} from "forge-std/Script.sol";
import {MultiSig} from "../../src/access/MultiSig.sol";
import {BaseUpgrade} from "./BaseUpgrade.s.sol";

contract UpgradeMultiSig is BaseUpgrade {
    function run() external {
        address proxyAddress = vm.envAddress("MULTISIG_PROXY");
        address multiSig = vm.envAddress("MULTISIG_ADDRESS");
        uint256[] memory privateKeys = vm.envUint("PRIVATE_KEYS", ",");

        vm.startBroadcast();
        MultiSig newImplementation = new MultiSig();
        console.log("New MultiSig implementation deployed at:", address(newImplementation));

        UpgradeParams memory params = UpgradeParams({
            proxyAddress: proxyAddress,
            multiSig: multiSig,
            newImplementation: address(newImplementation),
            privateKeys: privateKeys,
            deadline: block.timestamp + 1 days
        });

        _executeUpgrade(params);
        vm.stopBroadcast();

        address newImpl = MultiSig(proxyAddress).implementation();
        console.log("Upgrade completed. New implementation:", newImpl);
        require(newImpl == address(newImplementation), "Upgrade failed");
    }
}
