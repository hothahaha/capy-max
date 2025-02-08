// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test, console2} from "forge-std/Test.sol";
import {StrategyEngine} from "../src/StrategyEngine.sol";
import {CpToken} from "../src/tokens/CpToken.sol";
import {HelperConfig} from "../script/HelperConfig.s.sol";
import {DeployScript} from "../script/Deploy.s.sol";
import {Vault} from "../src/vault/Vault.sol";
import {SignerManager} from "../src/access/SignerManager.sol";
import {MultiSig} from "../src/access/MultiSig.sol";

import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {UUPSUpgradeableBase} from "../src/upgradeable/UUPSUpgradeableBase.sol";
import {ERC1967Utils} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Utils.sol";

contract StrategyEngineV2 is StrategyEngine {
    // 添加新功能用于测试升级
    uint256 public newVariable;
    bool public newFunctionCalled;

    function setNewVariable(uint256 _value) external {
        newVariable = _value;
    }

    function version() external pure returns (string memory) {
        return "V2";
    }

    // 添加新的平台费用相关函数
    function getDefaultPlatformFee() external pure returns (uint256) {
        return 1000; // 10%
    }

    function newFunction() external {
        newFunctionCalled = true;
    }
}

contract StrategyEngineUpgradesTest is Test {
    StrategyEngine public engine;
    StrategyEngine public implementation;
    CpToken public cpToken;
    Vault public vault;
    SignerManager public signerManager;
    MultiSig public multiSig;
    HelperConfig public helperConfig;

    uint256 public deployerKey;
    address public wbtc;
    address public usdc;
    address public owner;
    address public user = makeAddr("user");
    address public signer1;
    uint256 public signer1Key;

    // 存储槽常量
    bytes32 public constant IMPLEMENTATION_SLOT =
        0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
    bytes32 public constant ADMIN_SLOT =
        0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103;

    event Upgraded(address indexed implementation);

    error InvalidInitialization();
    error OwnableUnauthorizedAccount(address account);

    function setUp() public {
        owner = makeAddr("owner");
        user = makeAddr("user");
        (signer1, signer1Key) = makeAddrAndKey("signer1");

        DeployScript deployer = new DeployScript();
        (
            engine,
            cpToken,
            vault,
            signerManager,
            multiSig,
            helperConfig
        ) = deployer.run();
        (wbtc, usdc, deployerKey) = helperConfig.activeNetworkConfig();

        // 获取实现合约地址
        address implAddress = address(
            uint160(uint256(vm.load(address(engine), IMPLEMENTATION_SLOT)))
        );
        implementation = StrategyEngine(implAddress);
    }

    function test_InitialSetup() public view {
        // 验证代理合约设置
        bytes32 implSlot = vm.load(address(engine), IMPLEMENTATION_SLOT);
        address currentImpl = address(uint160(uint256(implSlot)));
        assertEq(currentImpl, address(implementation));
        assertEq(
            engine.owner(),
            vm.addr(deployerKey),
            "Owner should be deployer address"
        );
    }

    function test_UpgradeToV2() public {
        // 部署新版本合约
        StrategyEngineV2 newImplementation = new StrategyEngineV2();
        uint256 deadline = block.timestamp + 1 days;

        // 构造升级数据
        bytes memory upgradeData = abi.encodeWithSelector(
            engine.upgradeToAndCall.selector,
            address(newImplementation),
            ""
        );

        // 生成签名
        bytes[] memory signatures = new bytes[](2);
        (address signer2, uint256 signer2Key) = makeAddrAndKey("signer2");

        _addSigner(signer2);
        _updateThreshold(2);

        // 获取交易哈希
        bytes32 txHash = multiSig.hashTransaction(
            address(engine),
            upgradeData,
            multiSig.nonce(),
            deadline
        );

        signatures[0] = _signTransaction(deployerKey, txHash);
        signatures[1] = _signTransaction(signer2Key, txHash);

        // 执行升级
        multiSig.executeTransaction(
            address(engine),
            upgradeData,
            deadline,
            signatures
        );

        // 验证升级后的新功能
        StrategyEngineV2(address(engine)).newFunction();
        assertTrue(StrategyEngineV2(address(engine)).newFunctionCalled());
    }

    function test_UpgradePreservesState() public {
        vm.prank(vm.addr(deployerKey));
        engine.updatePlatformFee(800);

        StrategyEngineV2 engineV2 = new StrategyEngineV2();

        uint256 deadline = block.timestamp + 1 days;

        // 构造升级数据
        bytes memory upgradeData = abi.encodeWithSelector(
            engine.upgradeToAndCall.selector,
            address(engineV2),
            ""
        );

        // 生成签名
        bytes[] memory signatures = new bytes[](2);
        (address signer2, uint256 signer2Key) = makeAddrAndKey("signer2");

        // 添加第二个签名者并设置阈值
        _addSigner(signer2);
        _updateThreshold(2);

        // 确保使用正确的签名顺序
        address deployer = vm.addr(deployerKey);
        require(signerManager.isSigner(deployer), "Deployer not a signer");
        require(signerManager.isSigner(signer2), "Signer2 not a signer");

        // 获取交易哈希
        bytes32 txHash = multiSig.hashTransaction(
            address(engine),
            upgradeData,
            multiSig.nonce(),
            deadline
        );

        signatures[0] = _signTransaction(deployerKey, txHash);
        signatures[1] = _signTransaction(signer2Key, txHash);

        // 执行升级
        multiSig.executeTransaction(
            address(engine),
            upgradeData,
            deadline,
            signatures
        );

        // 验证状态保持
        StrategyEngineV2 upgradedEngine = StrategyEngineV2(address(engine));
        assertEq(
            upgradedEngine.getPlatformFee(),
            800,
            "Platform fee not preserved after upgrade"
        );
        assertTrue(
            signerManager.isSigner(vm.addr(deployerKey)),
            "Signer authorization not preserved"
        );
    }

    function test_CannotInitializeImplementation() public {
        // 尝试直接初始化实现合约
        vm.expectRevert(InvalidInitialization.selector);
        implementation.initialize(
            address(0),
            address(0),
            address(0),
            address(0),
            address(0)
        );
    }

    function test_StorageSlotConsistency() public {
        // 设置初始状态
        vm.prank(vm.addr(deployerKey));
        engine.updatePlatformFee(800);

        // 升级到新版本
        StrategyEngineV2 newImplementation = new StrategyEngineV2();

        // 确保部署者是签名者
        address deployer = vm.addr(deployerKey);
        if (!signerManager.isSigner(deployer)) {
            console2.log("Adding deployer as signer:", deployer);
            _addSigner(deployer);
        }

        uint256 deadline = block.timestamp + 1 days;

        // 构造升级数据
        bytes memory upgradeData = abi.encodeWithSelector(
            engine.upgradeToAndCall.selector,
            address(newImplementation),
            ""
        );

        // 生成签名
        bytes[] memory signatures = new bytes[](2);
        (address signer2, uint256 signer2Key) = makeAddrAndKey("signer2");

        // 添加第二个签名者并设置阈值
        _addSigner(signer2);
        _updateThreshold(2);

        // 验证签名者状态
        require(
            signerManager.isSigner(signer2),
            "Signer2 not added successfully"
        );
        console2.log("Deployer address:", deployer);
        console2.log("Signer2 address:", signer2);

        // 获取交易哈希
        bytes32 txHash = multiSig.hashTransaction(
            address(engine),
            upgradeData,
            multiSig.nonce(),
            deadline
        );

        signatures[0] = _signTransaction(deployerKey, txHash);
        signatures[1] = _signTransaction(signer2Key, txHash);

        // 执行升级
        multiSig.executeTransaction(
            address(engine),
            upgradeData,
            deadline,
            signatures
        );

        // 验证原有数据保持不变
        assertEq(engine.owner(), vm.addr(deployerKey));
        assertEq(
            StrategyEngineV2(address(engine)).getPlatformFee(),
            800,
            "Platform fee not preserved"
        );

        // 验证可以使用新功能
        vm.prank(vm.addr(deployerKey));
        StrategyEngineV2(address(engine)).setNewVariable(123);
        assertEq(StrategyEngineV2(address(engine)).newVariable(), 123);
    }

    function test_UpgradeToAndCall() public {
        StrategyEngineV2 newImplementation = new StrategyEngineV2();

        vm.prank(vm.addr(deployerKey));
        engine.updatePlatformFee(700);

        // 准备初始化数据
        bytes memory data = abi.encodeWithSelector(
            StrategyEngineV2.setNewVariable.selector,
            999
        );

        uint256 deadline = block.timestamp + 1 days;

        // 构造升级数据
        bytes memory upgradeData = abi.encodeWithSelector(
            engine.upgradeToAndCall.selector,
            address(newImplementation),
            data
        );

        // 生成签名
        bytes[] memory signatures = new bytes[](2);
        (address signer2, uint256 signer2Key) = makeAddrAndKey("signer2");

        // 添加第二个签名者并设置阈值
        _addSigner(signer2);
        _updateThreshold(2);

        // 确保使用正确的签名顺序
        address deployer = vm.addr(deployerKey);
        require(signerManager.isSigner(deployer), "Deployer not a signer");
        require(signerManager.isSigner(signer2), "Signer2 not a signer");

        // 获取交易哈希
        bytes32 txHash = multiSig.hashTransaction(
            address(engine),
            upgradeData,
            multiSig.nonce(),
            deadline
        );

        signatures[0] = _signTransaction(deployerKey, txHash);
        signatures[1] = _signTransaction(signer2Key, txHash);

        // 执行升级
        multiSig.executeTransaction(
            address(engine),
            upgradeData,
            deadline,
            signatures
        );

        // 验证初始化是否成功
        assertEq(StrategyEngineV2(address(engine)).newVariable(), 999);
        assertEq(
            StrategyEngineV2(address(engine)).getPlatformFee(),
            700,
            "Platform fee not preserved after upgrade and call"
        );
        assertTrue(
            signerManager.isSigner(vm.addr(deployerKey)),
            "Signer status lost"
        );
    }

    function test_ProxyAdmin() public view {
        // 验证代理管理员
        bytes32 adminSlot = vm.load(address(engine), ADMIN_SLOT);
        address admin = address(uint160(uint256(adminSlot)));
        assertEq(admin, address(0), "Proxy admin should be zero for UUPS");
    }

    function test_RevertWhen_UpgradeToSameImplementation() public {
        // 获取当前实现合约地址
        bytes32 implSlot = vm.load(address(engine), IMPLEMENTATION_SLOT);
        address currentImpl = address(uint160(uint256(implSlot)));

        // 先添加签名者并设置阈值
        (address signer2, uint256 signer2Key) = makeAddrAndKey("signer2");
        _addSigner(signer2);
        _updateThreshold(2);

        uint256 deadline = block.timestamp + 1 days;

        // 构造升级数据
        bytes memory upgradeData = abi.encodeWithSelector(
            engine.upgradeToAndCall.selector,
            currentImpl,
            ""
        );

        // 获取交易哈希
        bytes32 txHash = multiSig.hashTransaction(
            address(engine),
            upgradeData,
            multiSig.nonce(),
            deadline
        );

        // 生成签名
        bytes[] memory signatures = new bytes[](2);

        // 确保使用正确的签名顺序
        address deployer = vm.addr(deployerKey);
        require(signerManager.isSigner(deployer), "Deployer not a signer");
        require(signerManager.isSigner(signer2), "Signer2 not a signer");

        signatures[0] = _signTransaction(deployerKey, txHash);
        signatures[1] = _signTransaction(signer2Key, txHash);

        vm.expectRevert(MultiSig.MultiSig__ExecutionFailed.selector);
        multiSig.executeTransaction(
            address(engine),
            upgradeData,
            deadline,
            signatures
        );
    }

    function test_UpgradeEvent() public {
        StrategyEngineV2 engineV2 = new StrategyEngineV2();

        uint256 deadline = block.timestamp + 1 days;

        // 构造升级数据
        bytes memory upgradeData = abi.encodeWithSelector(
            engine.upgradeToAndCall.selector,
            address(engineV2),
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
            address(engine),
            upgradeData,
            multiSig.nonce(),
            deadline
        );

        signatures[0] = _signTransaction(deployerKey, txHash);
        signatures[1] = _signTransaction(signer2Key, txHash);

        vm.expectEmit(true, true, true, true);
        emit Upgraded(address(engineV2));

        multiSig.executeTransaction(
            address(engine),
            upgradeData,
            deadline,
            signatures
        );
    }

    function test_UpgradeWithEmptyData() public {
        StrategyEngineV2 engineV2 = new StrategyEngineV2();

        // 先添加签名者并设置阈值
        (address signer2, uint256 signer2Key) = makeAddrAndKey("signer2");
        _addSigner(signer2);
        _updateThreshold(2);

        uint256 deadline = block.timestamp + 1 days;

        // 构造升级数据
        bytes memory upgradeData = abi.encodeWithSelector(
            engine.upgradeToAndCall.selector,
            engineV2,
            ""
        );

        // 生成签名
        bytes[] memory signatures = new bytes[](2);

        // 确保使用正确的签名顺序
        address deployer = vm.addr(deployerKey);
        require(signerManager.isSigner(deployer), "Deployer not a signer");
        require(signerManager.isSigner(signer2), "Signer2 not a signer");

        // 获取交易哈希
        bytes32 txHash = multiSig.hashTransaction(
            address(engine),
            upgradeData,
            multiSig.nonce(),
            deadline
        );

        signatures[0] = _signTransaction(deployerKey, txHash);
        signatures[1] = _signTransaction(signer2Key, txHash);

        multiSig.executeTransaction(
            address(engine),
            upgradeData,
            deadline,
            signatures
        );

        // 验证升级成功
        bytes32 implSlot = vm.load(address(engine), IMPLEMENTATION_SLOT);
        address currentImpl = address(uint160(uint256(implSlot)));
        assertEq(currentImpl, address(engineV2));
    }

    function test_RevertWhen_UpgradeUnauthorized() public {
        // 先部署新合约
        StrategyEngineV2 engineV2 = new StrategyEngineV2();

        uint256 deadline = block.timestamp + 1 days;

        // 构造升级数据
        bytes memory upgradeData = abi.encodeWithSelector(
            engine.upgradeToAndCall.selector,
            address(engineV2),
            ""
        );

        // 生成签名
        bytes[] memory signatures = new bytes[](2);
        (address signer2, uint256 signer2Key) = makeAddrAndKey("signer2");

        // 添加第二个签名者并设置阈值
        _addSigner(signer2);
        _updateThreshold(2);

        // 使用未授权的签名者生成签名
        (, uint256 unauthorizedKey) = makeAddrAndKey("unauthorized");

        // 获取交易哈希
        bytes32 txHash = multiSig.hashTransaction(
            address(engine),
            upgradeData,
            multiSig.nonce(),
            deadline
        );

        signatures[0] = _signTransaction(unauthorizedKey, txHash);
        signatures[1] = _signTransaction(signer2Key, txHash);

        vm.expectRevert(MultiSig.MultiSig__InvalidSignature.selector);
        multiSig.executeTransaction(
            address(engine),
            upgradeData,
            deadline,
            signatures
        );
    }

    function test_RevertWhen_InitializeAgain() public {
        vm.startBroadcast(vm.addr(deployerKey));
        vm.expectRevert(InvalidInitialization.selector);
        engine.initialize(
            address(wbtc),
            address(usdc),
            address(cpToken),
            address(vault),
            address(signerManager)
        );
        vm.stopBroadcast();
    }

    // Helper functions
    function _hashTransaction(
        address verifyingContract,
        address to,
        bytes memory data,
        uint256 nonce,
        uint256 deadline
    ) internal view returns (bytes32) {
        bytes32 txHash = MultiSig(verifyingContract).hashTransaction(
            to,
            data,
            nonce,
            deadline
        );
        return txHash;
    }

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
