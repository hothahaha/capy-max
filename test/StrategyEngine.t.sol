// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test, console2} from "forge-std/Test.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IERC20Permit} from "@chainlink/contracts/src/v0.8/vendor/openzeppelin-solidity/v5.0.2/contracts/token/ERC20/extensions/IERC20Permit.sol";
import {IERC20Metadata} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import {AaveV3Arbitrum, AaveV3ArbitrumAssets} from "@bgd-labs/aave-address-book/AaveV3Arbitrum.sol";

import {MockERC20} from "../src/erc20/MockERC20.sol";
import {IAavePool} from "../src/aave/interface/IAavePool.sol";
import {IPoolDataProvider} from "../src/aave/interface/IAaveProtocolDataProvider.sol";
import {IVariableDebtToken} from "../src/aave/interface/IVariableDebtToken.sol";
import {StrategyEngine} from "../src/StrategyEngine.sol";
import {DeployScript} from "../script/Deploy.s.sol";
import {HelperConfig} from "../script/HelperConfig.s.sol";

contract StrategyEngineTest is Test {
    IPoolDataProvider public aaveProtocolDataProvider;
    StrategyEngine public engine;
    address public wbtc;
    address public usdc;
    address public USER;
    uint256 public USER_PRIVATE_KEY;
    uint256 public constant INITIAL_ETH_BALANCE = 10 ether;
    uint256 public constant INITIAL_WBTC_BALANCE = 1000e8;
    uint256 public constant GMX_EXECUTION_FEE = 0.011 ether;

    // GMX related addresses
    address public constant GMX_ROUTER =
        0x7C68C7866A64FA2160F78EEaE12217FFbf871fa8;
    address public constant GMX_ROUTER_PLUGIN =
        0x7452c558d45f8afC8c83dAe62C3f8A5BE19c71f6;
    bytes32 public constant ROUTER_PLUGIN_ROLE = keccak256("ROUTER_PLUGIN");

    function setUp() public {
        DeployScript deployer = new DeployScript();
        HelperConfig config = new HelperConfig();
        (engine, , config) = deployer.run();
        (wbtc, usdc, , , ) = config.activeNetworkConfig();

        (USER, USER_PRIVATE_KEY) = makeAddrAndKey("user");

        // Deal ETH and tokens to user
        vm.deal(USER, INITIAL_ETH_BALANCE);
        deal(wbtc, USER, INITIAL_WBTC_BALANCE);
    }

    function test_Deposit() public {
        uint256 amount = 1e7;
        uint256 deadline = block.timestamp + 1 days;

        // Get current nonce for the user
        uint256 nonce = IERC20Permit(wbtc).nonces(USER);

        // _setTokenBalance(wbtc, USER, amount);

        // Generate signature for deposit - adjusted parameters
        (uint8 v, bytes32 r, bytes32 s) = _getPermitSignature(
            wbtc,
            USER,
            address(engine),
            amount,
            nonce,
            deadline,
            USER_PRIVATE_KEY
        );

        vm.startPrank(USER);

        _approveDelegation(usdc, USER, type(uint256).max);

        engine.deposit{value: GMX_EXECUTION_FEE}(
            amount,
            USER,
            0, // referralCode
            deadline,
            v,
            r,
            s
        );

        vm.stopPrank();

        // Verify deposit
        (uint256 depositAmount, , ) = engine.userInfo(USER);
        assertEq(depositAmount, amount, "Incorrect deposit amount");

        // Verify user is in active users list
        address[] memory users = _getActiveUsers(0, 1);
        assertEq(users[0], USER, "User not added to active users");
    }

    // Helper functions
    function _getPermitSignature(
        address token,
        address owner,
        address spender,
        uint256 amount,
        uint256 nonce,
        uint256 deadline,
        uint256 privateKey
    ) internal view returns (uint8 v, bytes32 r, bytes32 s) {
        bytes32 PERMIT_TYPEHASH = keccak256(
            "Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"
        );

        // Use the token's own DOMAIN_SEPARATOR
        bytes32 DOMAIN_SEPARATOR = IERC20Permit(token).DOMAIN_SEPARATOR();

        // messageHash
        bytes32 messageHash = keccak256(
            abi.encode(PERMIT_TYPEHASH, owner, spender, amount, nonce, deadline)
        );

        // Compute the digest
        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, messageHash)
        );

        // Generate signature
        (v, r, s) = vm.sign(privateKey, digest);
    }

    function _getActiveUsers(
        uint256 start,
        uint256 end
    ) internal view returns (address[] memory) {
        (address[] memory users, ) = engine.batchGetUserInfo(start, end);
        return users;
    }

    function _approveDelegation(
        address token,
        address user,
        uint256 amount
    ) internal {
        aaveProtocolDataProvider = IPoolDataProvider(
            address(AaveV3Arbitrum.AAVE_PROTOCOL_DATA_PROVIDER)
        );

        // 3. Approve delegation to AavePool
        (, , address variableDebtTokenAddress) = aaveProtocolDataProvider
            .getReserveTokensAddresses(token);

        IVariableDebtToken(variableDebtTokenAddress).approveDelegation(
            address(engine),
            amount
        );

        uint256 borrowAllowance = IVariableDebtToken(variableDebtTokenAddress)
            .borrowAllowance(user, address(engine));
        assertEq(borrowAllowance, amount, "Incorrect borrow allowance");
    }
}
