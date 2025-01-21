// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

struct TransferParameters {
    address token;
    uint256 amount;
    uint16 targetChain;
    bytes32 mintRecipient;
}

struct RedeemParameters {
    bytes encodedWormholeMessage;
    bytes circleBridgeMessage;
    bytes circleAttestation;
}

struct DepositWithPayload {
    bytes32 token;
    uint256 amount;
    uint32 sourceDomain;
    uint32 targetDomain;
    uint64 nonce;
    bytes32 fromAddress;
    bytes32 mintRecipient;
    bytes payload;
}

interface IWormholeCCTP {
    function transferTokensWithPayload(
        TransferParameters memory transferParams,
        uint32 batchId,
        bytes memory payload
    ) external returns (uint64 messageSequence);
}
