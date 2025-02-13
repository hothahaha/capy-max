// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {VerifyDeployment} from "../script/VerifyDeployment.s.sol";
import {DeployScript} from "../script/Deploy.s.sol";
import {HelperConfig} from "../script/HelperConfig.s.sol";
import {MultiSig} from "../src/access/MultiSig.sol";
import {SignerManager} from "../src/access/SignerManager.sol";
import {Vault} from "../src/vault/Vault.sol";
import {StrategyEngine} from "../src/StrategyEngine.sol";
import {UUPSUpgradeableBase} from "../src/upgradeable/UUPSUpgradeableBase.sol";

import {ITransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";

contract VerifyDeploymentTest is Test {
    VerifyDeployment public verifier;
    MultiSig public multiSig;
    SignerManager public signerManager;
    HelperConfig public helperConfig;
    address public owner;
    address public signer1;
    address public signer2;
    uint256 public signer1Key;
    uint256 public signer2Key;
    uint256 public deployerKey;
    Vault public vault;
    StrategyEngine public engine;
    address public vaultProxy;
    address public engineProxy;

    function setUp() public {
        // 部署基础设施
        DeployScript deployer = new DeployScript();
        (engine, , vault, signerManager, multiSig, helperConfig) = deployer
            .run();
        vaultProxy = address(vault);
        engineProxy = address(engine);
        (, , , , , deployerKey, , ) = helperConfig.activeNetworkConfig();
        verifier = new VerifyDeployment();

        // 设置测试账户
        (signer1, signer1Key) = makeAddrAndKey("signer1");
        (signer2, signer2Key) = makeAddrAndKey("signer2");

        // 添加签名者
        _addSigner(signer1);
        _addSigner(signer2);
        _updateThreshold(2); // 设置需要2个签名
    }

    function test_VerifyAndDeploy() public {
        uint256 deadline = block.timestamp + 1 days;
        bytes memory deployData = abi.encodeWithSelector(
            DeployScript.run.selector
        );

        // 获取交易哈希
        bytes32 txHash = multiSig.hashTransaction(
            address(verifier),
            deployData,
            multiSig.nonce(),
            deadline
        );

        // 获取签名
        bytes[] memory signatures = new bytes[](2);
        signatures[0] = _signTransaction(signer1Key, txHash);
        signatures[1] = _signTransaction(signer2Key, txHash);

        // 执行验证和部署
        verifier.verifyAndDeploy(address(multiSig), signatures, deadline);
    }

    function test_RevertWhen_DeadlineExpired() public {
        uint256 deadline = block.timestamp - 1;
        bytes[] memory signatures = new bytes[](2);

        vm.expectRevert(VerifyDeployment.VerifyDeployment__Expired.selector);
        verifier.verifyAndDeploy(address(multiSig), signatures, deadline);
    }

    function test_RevertWhen_InsufficientSignatures() public {
        uint256 deadline = block.timestamp + 1 days;
        bytes[] memory signatures = new bytes[](1);

        vm.expectRevert(
            VerifyDeployment.VerifyDeployment__InsufficientSignatures.selector
        );
        verifier.verifyAndDeploy(address(multiSig), signatures, deadline);
    }

    function test_RevertWhen_InvalidSignature() public {
        uint256 deadline = block.timestamp + 1 days;
        bytes memory deployData = abi.encodeWithSelector(
            DeployScript.run.selector
        );

        bytes32 txHash = multiSig.hashTransaction(
            address(verifier),
            deployData,
            multiSig.nonce(),
            deadline
        );

        // 使用未授权的签名者
        (, uint256 invalidKey) = makeAddrAndKey("invalidSigner");
        bytes[] memory signatures = new bytes[](2);
        signatures[0] = _signTransaction(signer1Key, txHash);
        signatures[1] = _signTransaction(invalidKey, txHash);

        vm.expectRevert(
            VerifyDeployment.VerifyDeployment__InvalidSignature.selector
        );
        verifier.verifyAndDeploy(address(multiSig), signatures, deadline);
    }

    function test_VerifyAndUpgrade() public {
        // 部署新的实现合约
        Vault newImplementation = new Vault();

        uint256 deadline = block.timestamp + 1 days;
        bytes memory upgradeData = abi.encodeWithSelector(
            ITransparentUpgradeableProxy.upgradeToAndCall.selector,
            address(newImplementation),
            ""
        );

        // 获取交易哈希
        bytes32 txHash = multiSig.hashTransaction(
            vaultProxy,
            upgradeData,
            multiSig.nonce(),
            deadline
        );

        // 获取签名
        bytes[] memory signatures = new bytes[](2);
        signatures[0] = _signTransaction(signer1Key, txHash);
        signatures[1] = _signTransaction(signer2Key, txHash);

        // 执行验证和升级
        verifier.verifyAndUpgrade(
            address(multiSig),
            vaultProxy,
            address(newImplementation),
            signatures,
            deadline
        );

        // 验证升级是否成功
        assertEq(
            Vault(vaultProxy).implementation(),
            address(newImplementation)
        );
    }

    function test_RevertWhen_UpgradeWithInvalidSignatures() public {
        Vault newImplementation = new Vault();
        uint256 deadline = block.timestamp + 1 days;
        bytes memory upgradeData = abi.encodeWithSelector(
            ITransparentUpgradeableProxy.upgradeToAndCall.selector,
            address(newImplementation),
            ""
        );

        bytes32 txHash = multiSig.hashTransaction(
            vaultProxy,
            upgradeData,
            multiSig.nonce(),
            deadline
        );

        // 使用未授权的签名者
        (, uint256 invalidKey) = makeAddrAndKey("invalidSigner");
        bytes[] memory signatures = new bytes[](2);
        signatures[0] = _signTransaction(signer1Key, txHash);
        signatures[1] = _signTransaction(invalidKey, txHash);

        vm.expectRevert(
            VerifyDeployment.VerifyDeployment__InvalidSignature.selector
        );
        verifier.verifyAndUpgrade(
            address(multiSig),
            vaultProxy,
            address(newImplementation),
            signatures,
            deadline
        );
    }

    function test_VerifyAndUpgradeEngine() public {
        // 部署新的实现合约
        StrategyEngine newImplementation = new StrategyEngine();

        uint256 deadline = block.timestamp + 1 days;
        bytes memory upgradeData = abi.encodeWithSelector(
            ITransparentUpgradeableProxy.upgradeToAndCall.selector,
            address(newImplementation),
            ""
        );

        bytes32 txHash = multiSig.hashTransaction(
            engineProxy,
            upgradeData,
            multiSig.nonce(),
            deadline
        );

        bytes[] memory signatures = new bytes[](2);
        signatures[0] = _signTransaction(signer1Key, txHash);
        signatures[1] = _signTransaction(signer2Key, txHash);

        verifier.verifyAndUpgrade(
            address(multiSig),
            engineProxy,
            address(newImplementation),
            signatures,
            deadline
        );

        assertEq(
            StrategyEngine(engineProxy).implementation(),
            address(newImplementation)
        );
    }

    function test_RevertWhen_UpgradeToZeroAddress() public {
        uint256 deadline = block.timestamp + 1 days;
        bytes memory upgradeData = abi.encodeWithSelector(
            ITransparentUpgradeableProxy.upgradeToAndCall.selector,
            address(0),
            ""
        );

        bytes32 txHash = multiSig.hashTransaction(
            vaultProxy,
            upgradeData,
            multiSig.nonce(),
            deadline
        );

        bytes[] memory signatures = new bytes[](2);
        signatures[0] = _signTransaction(signer1Key, txHash);
        signatures[1] = _signTransaction(signer2Key, txHash);

        vm.expectRevert(
            VerifyDeployment.VerifyDeployment__UpgradeFailed.selector
        );
        verifier.verifyAndUpgrade(
            address(multiSig),
            vaultProxy,
            address(0),
            signatures,
            deadline
        );
    }

    function test_RevertWhen_UpgradeWithExpiredDeadline() public {
        Vault newImplementation = new Vault();
        uint256 deadline = block.timestamp - 1;

        vm.expectRevert(VerifyDeployment.VerifyDeployment__Expired.selector);
        verifier.verifyAndUpgrade(
            address(multiSig),
            vaultProxy,
            address(newImplementation),
            new bytes[](2),
            deadline
        );
    }

    function test_RevertWhen_UpgradeWithInsufficientSignatures() public {
        Vault newImplementation = new Vault();
        uint256 deadline = block.timestamp + 1 days;

        bytes[] memory signatures = new bytes[](1);
        signatures[0] = _signTransaction(signer1Key, keccak256("dummy hash"));

        vm.expectRevert(
            VerifyDeployment.VerifyDeployment__InsufficientSignatures.selector
        );
        verifier.verifyAndUpgrade(
            address(multiSig),
            vaultProxy,
            address(newImplementation),
            signatures,
            deadline
        );
    }

    function test_RevertWhen_UpgradeWithDuplicateSignatures() public {
        Vault newImplementation = new Vault();
        uint256 deadline = block.timestamp + 1 days;
        bytes memory upgradeData = abi.encodeWithSelector(
            ITransparentUpgradeableProxy.upgradeToAndCall.selector,
            address(newImplementation),
            ""
        );

        bytes32 txHash = multiSig.hashTransaction(
            vaultProxy,
            upgradeData,
            multiSig.nonce(),
            deadline
        );

        bytes[] memory signatures = new bytes[](2);
        signatures[0] = _signTransaction(signer1Key, txHash);
        signatures[1] = _signTransaction(signer1Key, txHash); // 重复签名

        vm.expectRevert(
            VerifyDeployment.VerifyDeployment__DuplicateSigner.selector
        );
        verifier.verifyAndUpgrade(
            address(multiSig),
            vaultProxy,
            address(newImplementation),
            signatures,
            deadline
        );
    }

    // Helper functions
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

    function _signTransaction(
        uint256 privateKey,
        bytes32 digest
    ) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        return abi.encodePacked(r, s, v);
    }
}
