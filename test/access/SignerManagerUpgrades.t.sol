// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {SignerManager} from "../../src/access/SignerManager.sol";
import {MultiSig} from "../../src/access/MultiSig.sol";
import {DeployScript} from "../../script/Deploy.s.sol";
import {HelperConfig} from "../../script/HelperConfig.s.sol";

contract SignerManagerV2 is SignerManager {
    uint256 public newVariable;

    function setNewVariable(uint256 _value) external {
        newVariable = _value;
    }

    function version() external pure returns (string memory) {
        return "V2";
    }
}

contract SignerManagerUpgradesTest is Test {
    SignerManager public signerManager;
    MultiSig public multiSig;
    HelperConfig public helperConfig;
    uint256 public deployerKey;

    bytes32 public constant IMPLEMENTATION_SLOT =
        0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    event Upgraded(address indexed implementation);

    function setUp() public {
        DeployScript deployer = new DeployScript();
        (, , , signerManager, multiSig, helperConfig) = deployer.run();
        (, , deployerKey) = helperConfig.activeNetworkConfig();
    }

    function test_UpgradeToV2() public {
        SignerManagerV2 signerManagerV2 = new SignerManagerV2();

        uint256 deadline = block.timestamp + 1 days;

        // 构造升级数据
        bytes memory upgradeData = abi.encodeWithSelector(
            signerManager.upgradeToAndCall.selector,
            address(signerManagerV2),
            ""
        );

        // 生成签名
        bytes[] memory signatures = new bytes[](2);
        (address signer2, uint256 signer2Key) = makeAddrAndKey("signer2");

        _addSigner(signer2);
        _updateThreshold(2);

        // 确保使用正确的签名顺序
        address deployer = vm.addr(deployerKey);
        require(signerManager.isSigner(deployer), "Deployer not a signer");
        require(signerManager.isSigner(signer2), "Signer2 not a signer");

        // 获取交易哈希
        bytes32 txHash = multiSig.hashTransaction(
            address(signerManager),
            upgradeData,
            multiSig.nonce(),
            deadline
        );

        signatures[0] = _signTransaction(deployerKey, txHash);
        signatures[1] = _signTransaction(signer2Key, txHash);

        vm.expectEmit(true, true, true, true);
        emit Upgraded(address(signerManagerV2));

        multiSig.executeTransaction(
            address(signerManager),
            upgradeData,
            deadline,
            signatures
        );

        SignerManagerV2 upgradedSignerManager = SignerManagerV2(
            address(signerManager)
        );
        assertEq(upgradedSignerManager.version(), "V2");
    }

    function test_RevertWhen_UpgradeUnauthorized() public {
        SignerManagerV2 signerManagerV2 = new SignerManagerV2();

        uint256 deadline = block.timestamp + 1 days;

        // 构造升级数据
        bytes memory upgradeData = abi.encodeWithSelector(
            signerManager.upgradeToAndCall.selector,
            address(signerManagerV2),
            ""
        );

        // 生成签名
        bytes[] memory signatures = new bytes[](2);
        (address signer2, uint256 signer2Key) = makeAddrAndKey("signer2");

        _addSigner(signer2);
        _updateThreshold(2);

        // 使用未授权的签名者生成签名
        (, uint256 unauthorizedKey) = makeAddrAndKey("unauthorized");

        // 获取交易哈希
        bytes32 txHash = multiSig.hashTransaction(
            address(signerManager),
            upgradeData,
            multiSig.nonce(),
            deadline
        );

        signatures[0] = _signTransaction(unauthorizedKey, txHash);
        signatures[1] = _signTransaction(signer2Key, txHash);

        vm.expectRevert(MultiSig.MultiSig__InvalidSignature.selector);
        multiSig.executeTransaction(
            address(signerManager),
            upgradeData,
            deadline,
            signatures
        );
    }

    // Helper functions
    function _signTransaction(
        uint256 privateKey,
        bytes32 digest
    ) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        return abi.encodePacked(r, s, v);
    }

    function _addSigner(address signer) internal {
        bytes memory data = abi.encodeWithSelector(
            SignerManager.addSigner.selector,
            signer
        );
        uint256 deadline = block.timestamp + 1 days;

        bytes32 txHash = multiSig.hashTransaction(
            address(signerManager),
            data,
            multiSig.nonce(),
            deadline
        );

        bytes[] memory signatures = new bytes[](1);
        signatures[0] = _signTransaction(deployerKey, txHash);

        vm.prank(vm.addr(deployerKey));
        multiSig.executeTransaction(
            address(signerManager),
            data,
            deadline,
            signatures
        );
    }

    function _updateThreshold(uint256 newThreshold) internal {
        bytes memory data = abi.encodeWithSelector(
            SignerManager.updateThreshold.selector,
            newThreshold
        );
        uint256 deadline = block.timestamp + 1 days;

        bytes32 txHash = multiSig.hashTransaction(
            address(signerManager),
            data,
            multiSig.nonce(),
            deadline
        );

        bytes[] memory signatures = new bytes[](1);
        signatures[0] = _signTransaction(deployerKey, txHash);

        vm.prank(vm.addr(deployerKey));
        multiSig.executeTransaction(
            address(signerManager),
            data,
            deadline,
            signatures
        );
    }
} 