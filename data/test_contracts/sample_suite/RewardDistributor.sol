// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./Ownable.sol";
import "./IERC20.sol";

contract RewardDistributor is Ownable {
    IERC20 public rewardToken;
    uint256 public rewardRatePerBlock = 100;

    event RewardPaid(address indexed user, uint256 amount);

    constructor(address _token) {
        require(_token != address(0), "Invalid token");
        rewardToken = IERC20(_token);
    }

    function setRewardRate(uint256 newRate) external onlyOwner {
        rewardRatePerBlock = newRate;
    }

    function payout(address user, uint256 amount) external returns (bool) {
        require(amount > 0, "Zero payout");
        return rewardToken.transfer(user, amount);
    }
}
