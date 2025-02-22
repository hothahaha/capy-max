// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Script} from 'forge-std/Script.sol';
import {DeployScript} from './Deploy.s.sol';
import {HelperConfig} from './HelperConfig.s.sol';
import {MultiSig} from '../src/access/MultiSig.sol';
import {SignerManager} from '../src/access/SignerManager.sol';
import {ITransparentUpgradeableProxy} from '@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol';

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
    // Verify timestamp
    if (block.timestamp > deadline) revert VerifyDeployment__Expired();

    // Get SignerManager address
    SignerManager signerManager = SignerManager(
      MultiSig(multiSig).signerManager()
    );

    // Get required signature threshold
    uint256 threshold = signerManager.getThreshold();

    // Verify signature count
    if (signatures.length < threshold) {
      revert VerifyDeployment__InsufficientSignatures();
    }

    // Construct deployment data
    bytes memory deployData = abi.encodeWithSelector(DeployScript.run.selector);

    // Get transaction hash
    bytes32 txHash = MultiSig(multiSig).hashTransaction(
      address(this),
      deployData,
      MultiSig(multiSig).nonce(),
      deadline
    );

    // Verify each signature
    address[] memory recoveredSigners = new address[](signatures.length);
    uint256 validSignersCount = 0;

    for (uint256 i = 0; i < signatures.length; i++) {
      // Verify signature length
      if (signatures[i].length != 65) {
        revert VerifyDeployment__InvalidSignature();
      }

      // Recover signer address
      address signer = _recoverSigner(txHash, signatures[i]);

      // Verify signer permission
      if (!signerManager.isSigner(signer)) {
        revert VerifyDeployment__InvalidSignature();
      }

      // Check duplicate signature
      for (uint256 j = 0; j < i; j++) {
        if (signer == recoveredSigners[j]) {
          revert VerifyDeployment__DuplicateSigner();
        }
      }

      recoveredSigners[i] = signer;
      validSignersCount++;
    }

    // Verify again valid signature count
    if (validSignersCount < threshold) {
      revert VerifyDeployment__InsufficientSignatures();
    }

    // If verification passes, continue deployment
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
    // Verify timestamp
    if (block.timestamp > deadline) revert VerifyDeployment__Expired();

    // Get SignerManager address
    SignerManager signerManager = SignerManager(
      MultiSig(multiSig).signerManager()
    );

    // Get required signature threshold
    uint256 threshold = signerManager.getThreshold();

    // Verify signature count
    if (signatures.length < threshold) {
      revert VerifyDeployment__InsufficientSignatures();
    }

    // Construct upgrade data
    bytes memory upgradeData = abi.encodeWithSelector(
      ITransparentUpgradeableProxy.upgradeToAndCall.selector,
      newImplementation,
      ''
    );

    // Get transaction hash
    bytes32 txHash = MultiSig(multiSig).hashTransaction(
      proxy,
      upgradeData,
      MultiSig(multiSig).nonce(),
      deadline
    );

    // Verify each signature
    address[] memory recoveredSigners = new address[](signatures.length);
    uint256 validSignersCount = 0;

    for (uint256 i = 0; i < signatures.length; i++) {
      // Verify signature length
      if (signatures[i].length != 65) {
        revert VerifyDeployment__InvalidSignature();
      }

      // Recover signer address
      address signer = _recoverSigner(txHash, signatures[i]);

      // Verify signer permission
      if (!signerManager.isSigner(signer)) {
        revert VerifyDeployment__InvalidSignature();
      }

      // Check duplicate signature
      for (uint256 j = 0; j < i; j++) {
        if (signer == recoveredSigners[j]) {
          revert VerifyDeployment__DuplicateSigner();
        }
      }

      recoveredSigners[i] = signer;
      validSignersCount++;
    }

    // Verify again valid signature count
    if (validSignersCount < threshold) {
      revert VerifyDeployment__InsufficientSignatures();
    }

    // If verification passes, execute upgrade
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
