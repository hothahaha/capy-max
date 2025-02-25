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

    struct VerifyParams {
        address multiSig;
        address proxy;
        address newImplementation;
        bytes[] signatures;
        uint256 deadline;
        uint256 threshold;
        SignerManager signerManager;
    }

    struct TransactionParams {
        address to;
        bytes data;
        uint256 nonce;
        uint256 deadline;
    }

    struct SignatureVerifyParams {
        bytes signature;
        bytes32 txHash;
        SignerManager signerManager;
        address[] recoveredSigners;
        uint256 currentIndex;
    }

    function _verifyBasicChecks(
        uint256 deadline,
        uint256 sigCount,
        uint256 threshold
    ) internal view {
        if (block.timestamp > deadline) revert VerifyDeployment__Expired();
        if (sigCount < threshold) revert VerifyDeployment__InsufficientSignatures();
    }

    function _verifySignature(SignatureVerifyParams memory params) internal view returns (address) {
        if (params.signature.length != 65) revert VerifyDeployment__InvalidSignature();

        address signer = _recoverSigner(params.txHash, params.signature);
        if (!params.signerManager.isSigner(signer)) revert VerifyDeployment__InvalidSignature();

        for (uint256 j = 0; j < params.currentIndex; j++) {
            if (signer == params.recoveredSigners[j]) revert VerifyDeployment__DuplicateSigner();
        }

        return signer;
    }

    function _executeMultiSigTx(
        address multiSig,
        address to,
        bytes memory data,
        uint256 deadline,
        bytes[] memory signatures
    ) internal {
        try MultiSig(multiSig).executeTransaction(to, data, deadline, signatures) {} catch {
            revert VerifyDeployment__UpgradeFailed();
        }
    }

    function _verifySignatures(
        bytes[] calldata signatures,
        bytes32 txHash,
        SignerManager signerManager,
        uint256 threshold
    ) internal view returns (uint256) {
        address[] memory recoveredSigners = new address[](signatures.length);
        uint256 validSignersCount;

        unchecked {
            for (uint256 i; i < signatures.length; ++i) {
                recoveredSigners[i] = _verifySignature(
                    SignatureVerifyParams({
                        signature: signatures[i],
                        txHash: txHash,
                        signerManager: signerManager,
                        recoveredSigners: recoveredSigners,
                        currentIndex: i
                    })
                );
                ++validSignersCount;
            }
        }

        if (validSignersCount < threshold) revert VerifyDeployment__InsufficientSignatures();
        return validSignersCount;
    }

    function verifyAndDeploy(
        address multiSig,
        bytes[] calldata signatures,
        uint256 deadline
    ) external {
        SignerManager signerManager = SignerManager(MultiSig(multiSig).signerManager());
        uint256 threshold = signerManager.getThreshold();

        _verifyBasicChecks(deadline, signatures.length, threshold);

        bytes memory deployData = abi.encodeWithSelector(DeployScript.run.selector);
        bytes32 txHash = MultiSig(multiSig).hashTransaction(
            address(this),
            deployData,
            MultiSig(multiSig).nonce(),
            deadline
        );

        _verifySignatures(signatures, txHash, signerManager, threshold);

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
        SignerManager signerManager = SignerManager(MultiSig(multiSig).signerManager());
        _verifyBasicChecks(deadline, signatures.length, signerManager.getThreshold());

        bytes memory upgradeData = abi.encodeWithSelector(
            ITransparentUpgradeableProxy.upgradeToAndCall.selector,
            newImplementation,
            ""
        );

        _verifySignatures(
            signatures,
            MultiSig(multiSig).hashTransaction(
                proxy,
                upgradeData,
                MultiSig(multiSig).nonce(),
                deadline
            ),
            signerManager,
            signerManager.getThreshold()
        );

        _executeMultiSigTx(multiSig, proxy, upgradeData, deadline, signatures);
    }

    function _recoverSigner(bytes32 hash, bytes memory signature) internal pure returns (address) {
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
