// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {CpToken} from "../../src/tokens/CpToken.sol";
import {StrategyEngine} from "../../src/StrategyEngine.sol";
import {DeployScript} from "../../script/Deploy.s.sol";
import {HelperConfig} from "../../script/HelperConfig.s.sol";

contract CpTokenV2 is CpToken {
    uint256 public newVariable;

    function setNewVariable(uint256 _value) external {
        newVariable = _value;
    }

    function version() external pure returns (string memory) {
        return "V2";
    }
}

contract CpTokenTest is Test {
    StrategyEngine public engine;
    CpToken public cpToken;
    CpToken public implementation;
    HelperConfig public helperConfig;
    address public owner;
    address public user;

    bytes32 public constant IMPLEMENTATION_SLOT =
        0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Upgraded(address indexed implementation);

    error OwnableUnauthorizedAccount(address account);

    function setUp() public {
        owner = makeAddr("owner");
        user = makeAddr("user");

        DeployScript deployer = new DeployScript();
        (engine, cpToken, , , , helperConfig) = deployer.run();
        owner = address(engine);
    }

    function test_Initialize() public view {
        assertEq(cpToken.name(), "Compound BTC");
        assertEq(cpToken.symbol(), "cpBTC");
        assertEq(cpToken.owner(), owner);
    }

    function test_Mint() public {
        uint256 amount = 100e18;
        vm.prank(address(engine));
        vm.expectEmit(true, true, true, true);
        emit Transfer(address(0), user, amount);
        cpToken.mint(user, amount);

        assertEq(cpToken.balanceOf(user), amount);
        assertEq(cpToken.totalSupply(), amount);
    }

    function test_RevertWhen_MintZeroAmount() public {
        vm.prank(owner);
        vm.expectRevert(CpToken.CpToken__InvalidAmount.selector);
        cpToken.mint(user, 0);
    }

    function test_RevertWhen_MintUnauthorized() public {
        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(OwnableUnauthorizedAccount.selector, user)
        );
        cpToken.mint(user, 100e18);
    }

    function test_Burn() public {
        uint256 amount = 100e18;
        vm.startPrank(address(engine));
        cpToken.mint(user, amount);

        vm.expectEmit(true, true, true, true);
        emit Transfer(user, address(0), amount);
        cpToken.burn(user, amount);
        vm.stopPrank();

        assertEq(cpToken.balanceOf(user), 0);
        assertEq(cpToken.totalSupply(), 0);
    }

    function test_RevertWhen_BurnZeroAmount() public {
        vm.prank(owner);
        vm.expectRevert(CpToken.CpToken__InvalidAmount.selector);
        cpToken.burn(user, 0);
    }

    function test_RevertWhen_BurnUnauthorized() public {
        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(OwnableUnauthorizedAccount.selector, user)
        );
        cpToken.burn(user, 100e18);
    }

    function test_RevertWhen_Transfer() public {
        vm.prank(owner);
        cpToken.mint(user, 100e18);
        vm.expectRevert(CpToken.CpToken__TransferNotAllowed.selector);
        vm.prank(user);
        cpToken.transfer(owner, 50e18);
    }

    function test_RevertWhen_TransferFrom() public {
        vm.prank(owner);
        cpToken.mint(user, 100e18);
        vm.startPrank(user);
        vm.expectRevert(CpToken.CpToken__TransferNotAllowed.selector);
        cpToken.approve(owner, 50e18);
        vm.expectRevert(CpToken.CpToken__TransferNotAllowed.selector);
        cpToken.transferFrom(user, owner, 50e18);
        vm.stopPrank();
    }

    function test_UpgradeToV2() public {
        vm.startPrank(address(engine));

        CpTokenV2 tokenV2 = new CpTokenV2();
        vm.expectEmit(true, true, true, true);
        emit Upgraded(address(tokenV2));

        cpToken.upgradeToAndCall(address(tokenV2), "");

        CpTokenV2 upgradedToken = CpTokenV2(address(cpToken));
        assertEq(upgradedToken.version(), "V2");

        vm.stopPrank();
    }

    function test_RevertWhen_UpgradeUnauthorized() public {
        CpTokenV2 tokenV2 = new CpTokenV2();
        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(OwnableUnauthorizedAccount.selector, user)
        );
        cpToken.upgradeToAndCall(address(tokenV2), "");
    }

    function test_RevertWhen_InvalidUpgrade() public {
        vm.prank(owner);
        vm.expectRevert(CpToken.CpToken__InvalidUpgrade.selector);
        cpToken.upgradeToAndCall(address(0), "");
    }
}
