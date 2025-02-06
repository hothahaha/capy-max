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
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

contract StrategyEngineV2 is StrategyEngine {
    // 添加新功能用于测试升级
    uint256 public newVariable;

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
        vm.startPrank(vm.addr(deployerKey));

        // 设置初始平台费用
        engine.updatePlatformFee(1000);

        // 部署新版本合约
        StrategyEngineV2 engineV2 = new StrategyEngineV2();

        // 升级到新版本
        engine.upgradeToAndCall(address(engineV2), "");

        // 验证升级后的功能
        StrategyEngineV2 upgradedEngine = StrategyEngineV2(address(engine));
        assertEq(upgradedEngine.version(), "V2");

        // 验证原有功能保持不变
        assertEq(
            upgradedEngine.getPlatformFee(),
            1000,
            "Platform fee changed after upgrade"
        );
        assertTrue(
            signerManager.isSigner(vm.addr(deployerKey)),
            "Signer status lost after upgrade"
        );

        // 验证新功能
        assertEq(
            upgradedEngine.getDefaultPlatformFee(),
            1000,
            "Default platform fee incorrect"
        );

        engine.updatePlatformFee(500);

        assertEq(
            upgradedEngine.getPlatformFee(),
            500,
            "Platform fee update failed after upgrade"
        );

        vm.stopPrank();
    }

    function test_UpgradePreservesState() public {
        vm.startPrank(vm.addr(deployerKey));
        engine.updatePlatformFee(800);

        StrategyEngineV2 engineV2 = new StrategyEngineV2();
        engine.upgradeToAndCall(address(engineV2), "");
        vm.stopPrank();

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
        vm.startPrank(vm.addr(deployerKey));
        engine.updatePlatformFee(800);

        // 升级到新版本
        StrategyEngineV2 newImplementation = new StrategyEngineV2();
        engine.upgradeToAndCall(address(newImplementation), "");

        // 验证原有数据保持不变
        assertEq(engine.owner(), vm.addr(deployerKey));
        assertEq(
            StrategyEngineV2(address(engine)).getPlatformFee(),
            800,
            "Platform fee not preserved"
        );

        // 验证可以使用新功能
        StrategyEngineV2(address(engine)).setNewVariable(123);
        assertEq(StrategyEngineV2(address(engine)).newVariable(), 123);

        vm.stopPrank();
    }

    function test_UpgradeToAndCall() public {
        vm.startPrank(vm.addr(deployerKey));

        StrategyEngineV2 newImplementation = new StrategyEngineV2();

        engine.updatePlatformFee(700);

        // 准备初始化数据
        bytes memory data = abi.encodeWithSelector(
            StrategyEngineV2.setNewVariable.selector,
            999
        );

        // 升级并调用初始化函数
        engine.upgradeToAndCall(address(newImplementation), data);

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

        vm.stopPrank();
    }

    function test_ProxyAdmin() public view {
        // 验证代理管理员
        bytes32 adminSlot = vm.load(address(engine), ADMIN_SLOT);
        address admin = address(uint160(uint256(adminSlot)));
        assertEq(admin, address(0), "Proxy admin should be zero for UUPS");
    }

    function test_RevertWhen_UpgradeToSameImplementation() public {
        vm.startPrank(vm.addr(deployerKey));

        // 获取当前实现合约地址
        bytes32 implSlot = vm.load(address(engine), IMPLEMENTATION_SLOT);
        address currentImpl = address(uint160(uint256(implSlot)));

        vm.expectRevert(
            StrategyEngine.StrategyEngine__InvalidImplementation.selector
        );
        engine.upgradeToAndCall(currentImpl, "");
        vm.stopPrank();
    }

    function test_UpgradeEvent() public {
        vm.startPrank(vm.addr(deployerKey));
        StrategyEngineV2 engineV2 = new StrategyEngineV2();

        vm.expectEmit(true, true, true, true);
        emit Upgraded(address(engineV2));

        engine.upgradeToAndCall(address(engineV2), "");
        vm.stopPrank();
    }

    function test_UpgradeWithEmptyData() public {
        vm.startPrank(vm.addr(deployerKey));
        StrategyEngineV2 engineV2 = new StrategyEngineV2();
        engine.upgradeToAndCall(address(engineV2), "");

        // 验证升级成功
        bytes32 implSlot = vm.load(address(engine), IMPLEMENTATION_SLOT);
        address currentImpl = address(uint160(uint256(implSlot)));
        assertEq(currentImpl, address(engineV2));
        vm.stopPrank();
    }

    function test_RevertWhen_UpgradeUnauthorized() public {
        // 先部署新合约
        StrategyEngineV2 engineV2 = new StrategyEngineV2();

        // 然后以 user 身份尝试升级
        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(OwnableUnauthorizedAccount.selector, user)
        );
        engine.upgradeToAndCall(address(engineV2), "");
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
        return MessageHashUtils.toEthSignedMessageHash(txHash);
    }

    function _signTransaction(
        uint256 privateKey,
        bytes32 digest
    ) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        return abi.encodePacked(r, s, v);
    }
}
