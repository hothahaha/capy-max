// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function mint(address to, uint256 amount) external;
}

contract MockERC20 {
    IERC20 public token;

    constructor(address wbtcAddress) {
        token = IERC20(wbtcAddress);
    }

    function mint(address user, uint256 amount) external {
        token.mint(user, amount);
    }
}
