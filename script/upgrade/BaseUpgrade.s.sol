// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Script, console} from "forge-std/Script.sol";
import {MultiSig} from "../../src/access/MultiSig.sol";
import {ITransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";

contract BaseUpgrade is Script {
    struct UpgradeParams {
        address proxyAddress;
        address multiSig;
        address newImplementation;
        uint256[] privateKeys;
        uint256 deadline;
    }

    function _executeUpgrade(UpgradeParams memory params) internal {
        bytes memory upgradeData = abi.encodeWithSelector(
            ITransparentUpgradeableProxy.upgradeToAndCall.selector,
            params.newImplementation,
            ""
        );

        bytes32 txHash = MultiSig(params.multiSig).hashTransaction(
            params.proxyAddress,
            upgradeData,
            MultiSig(params.multiSig).nonce(),
            params.deadline
        );

        bytes[] memory signatures = new bytes[](params.privateKeys.length);
        for (uint i = 0; i < params.privateKeys.length; i++) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(params.privateKeys[i], txHash);
            signatures[i] = abi.encodePacked(r, s, v);
        }

        MultiSig(params.multiSig).executeTransaction(
            params.proxyAddress,
            upgradeData,
            params.deadline,
            signatures
        );
    }
}
