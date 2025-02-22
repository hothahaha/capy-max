// script/upgrade/UpgradeMultiSig.s.sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Script, console} from "forge-std/Script.sol";
import {MultiSig} from "../../src/access/MultiSig.sol";
import {ITransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";

contract UpgradeMultiSig is Script {
    function run() external {
        // 1. Set proxy address and multiSig address
        address proxyAddress = vm.envAddress("MULTISIG_PROXY");
        address multiSig = vm.envAddress("MULTISIG_ADDRESS");
        uint256[] memory privateKeys = vm.envUint("PRIVATE_KEYS", ",");

        // 2. Deploy new implementation contract
        vm.startBroadcast();
        MultiSig newImplementation = new MultiSig();
        console.log("New MultiSig implementation deployed at:", address(newImplementation));

        // 3. Set deadline
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

        // 6. Execute upgrade
        MultiSig(multiSig).executeTransaction(proxyAddress, upgradeData, deadline, signatures);

        vm.stopBroadcast();

        // 7. Verify upgrade result
        address newImpl = MultiSig(proxyAddress).implementation();
        console.log("Upgrade completed. New implementation:", newImpl);
        require(newImpl == address(newImplementation), "Upgrade failed");
    }
}
