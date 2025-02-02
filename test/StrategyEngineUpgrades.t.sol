// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test, console2} from "forge-std/Test.sol";
import {StrategyEngine} from "../src/StrategyEngine.sol";
import {CpToken} from "../src/tokens/CpToken.sol";
import {HelperConfig} from "../script/HelperConfig.s.sol";
import {DeployScript} from "../script/Deploy.s.sol";

import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

contract StrategyEngineV2 is StrategyEngine {
    // 添加新功能用于测试升级
    uint256 public newVariable;

    function setNewVariable(uint256 _value) external {
        newVariable = _value;
    }
}

contract StrategyEngineUpgradesTest is Test {
    StrategyEngine public engine;
    StrategyEngine public implementation;
    HelperConfig public helperConfig;
    address public owner;
    address public user = makeAddr("user");

    // 存储槽常量
    bytes32 public constant IMPLEMENTATION_SLOT =
        0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
    bytes32 public constant ADMIN_SLOT =
        0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103;

    event Upgraded(address indexed implementation);

    error InvalidInitialization();

    function setUp() public {
        DeployScript deployer = new DeployScript();
        (engine, , helperConfig) = deployer.run();
        owner = engine.owner();

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
        assertEq(engine.owner(), owner);
    }

    function test_UpgradeToV2() public {
        // 部署新版本
        StrategyEngineV2 newImplementation = new StrategyEngineV2();

        // 只有 owner 可以升级
        vm.startPrank(owner);

        // 验证升级事件
        vm.expectEmit(true, true, true, true);
        emit Upgraded(address(newImplementation));

        // 执行升级
        engine.upgradeToAndCall(address(newImplementation), "");

        // 验证新的实现合约地址
        bytes32 implSlot = vm.load(address(engine), IMPLEMENTATION_SLOT);
        address currentImpl = address(uint160(uint256(implSlot)));
        assertEq(currentImpl, address(newImplementation));

        // 测试新功能
        StrategyEngineV2(address(engine)).setNewVariable(42);
        assertEq(StrategyEngineV2(address(engine)).newVariable(), 42);

        vm.stopPrank();
    }

    function testFail_UpgradeToV2_NotOwner() public {
        StrategyEngineV2 newImplementation = new StrategyEngineV2();

        // 非 owner 尝试升级
        vm.prank(user);
        engine.upgradeToAndCall(address(newImplementation), "");
    }

    function test_CannotInitializeImplementation() public {
        // 尝试直接初始化实现合约
        vm.expectRevert(InvalidInitialization.selector);
        implementation.initialize(
            address(0),
            address(0),
            address(0),
            address(0)
        );
    }

    function test_StorageSlotConsistency() public {
        // 存储一些数据
        vm.startPrank(owner);

        // 升级到新版本
        StrategyEngineV2 newImplementation = new StrategyEngineV2();
        engine.upgradeToAndCall(address(newImplementation), "");

        // 验证原有数据保持不变
        assertEq(engine.owner(), owner);

        // 验证可以使用新功能
        StrategyEngineV2(address(engine)).setNewVariable(123);
        assertEq(StrategyEngineV2(address(engine)).newVariable(), 123);

        vm.stopPrank();
    }

    function test_UpgradeToAndCall() public {
        StrategyEngineV2 newImplementation = new StrategyEngineV2();

        bytes memory data = abi.encodeWithSelector(
            StrategyEngineV2.setNewVariable.selector,
            999
        );

        vm.startPrank(owner);

        // 升级并调用初始化函数
        engine.upgradeToAndCall(address(newImplementation), data);

        // 验证初始化是否成功
        assertEq(StrategyEngineV2(address(engine)).newVariable(), 999);

        vm.stopPrank();
    }

    function testFail_InvalidUpgrade() public {
        // 尝试升级到非合约地址
        vm.prank(owner);
        engine.upgradeToAndCall(address(0), "");
    }

    function test_ProxyAdmin() public view {
        // 验证代理管理员
        bytes32 adminSlot = vm.load(address(engine), ADMIN_SLOT);
        address admin = address(uint160(uint256(adminSlot)));
        assertEq(admin, address(0), "Proxy admin should be zero for UUPS");
    }
}
