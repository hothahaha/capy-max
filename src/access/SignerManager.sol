// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {MultiSig} from "./MultiSig.sol";

contract SignerManager is Initializable, OwnableUpgradeable, UUPSUpgradeable {
    error SignerManager__InvalidSigner();
    error SignerManager__SignerAlreadyExists();
    error SignerManager__SignerDoesNotExist();
    error SignerManager__InvalidThreshold();
    error SignerManager__Unauthorized();

    MultiSig public multiSig;
    uint256 private threshold;
    mapping(address => bool) private signers;
    uint256 private signerCount;

    event SignerAdded(address indexed signer);
    event SignerRemoved(address indexed signer);
    event ThresholdUpdated(uint256 oldThreshold, uint256 newThreshold);

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(
        address _initialSigner,
        uint256 _threshold
    ) public initializer {
        __Ownable_init(msg.sender);
        __UUPSUpgradeable_init();

        if (_initialSigner == address(0)) revert SignerManager__InvalidSigner();
        if (_threshold == 0) revert SignerManager__InvalidThreshold();

        signers[_initialSigner] = true;
        signerCount = 1;
        threshold = _threshold;

        emit SignerAdded(_initialSigner);
        emit ThresholdUpdated(0, _threshold);
    }

    function _authorizeUpgrade(
        address newImplementation
    ) internal override onlyOwner {}

    modifier onlyMultiSig() {
        if (msg.sender != address(multiSig))
            revert SignerManager__Unauthorized();
        _;
    }

    function setMultiSig(address _multiSig) external onlyOwner {
        multiSig = MultiSig(_multiSig);
    }

    function addSigner(address _signer) external onlyMultiSig {
        if (_signer == address(0)) revert SignerManager__InvalidSigner();
        if (signers[_signer]) revert SignerManager__SignerAlreadyExists();

        signers[_signer] = true;
        signerCount++;

        emit SignerAdded(_signer);
    }

    function removeSigner(address _signer) external onlyMultiSig {
        if (!signers[_signer]) revert SignerManager__SignerDoesNotExist();
        if (signerCount <= threshold) revert SignerManager__InvalidThreshold();

        signers[_signer] = false;
        signerCount--;

        emit SignerRemoved(_signer);
    }

    function updateThreshold(uint256 _threshold) external onlyMultiSig {
        if (_threshold == 0 || _threshold > signerCount)
            revert SignerManager__InvalidThreshold();

        uint256 oldThreshold = threshold;
        threshold = _threshold;

        emit ThresholdUpdated(oldThreshold, _threshold);
    }

    function isSigner(address _signer) external view returns (bool) {
        return signers[_signer];
    }

    function getThreshold() external view returns (uint256) {
        return threshold;
    }

    function getSignerCount() external view returns (uint256) {
        return signerCount;
    }
}
