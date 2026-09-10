// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./Ownable.sol";
import "./IERC20.sol";
import "./RewardDistributor.sol";

/**
 * @title StakingVault
 * Interconnected yield vault using Ownable, IERC20, and external RewardDistributor.
 */
contract StakingVault is Ownable {
    IERC20 public stakingToken;
    RewardDistributor public distributor;

    mapping(address => uint256) public stakedBalance;
    uint256 public totalStaked;

    event Staked(address indexed user, uint256 amount);
    event Withdrawn(address indexed user, uint256 amount);

    constructor(address _stakingToken, address _distributor) {
        require(_stakingToken != address(0), "Invalid token address");
        require(_distributor != address(0), "Invalid distributor address");
        stakingToken = IERC20(_stakingToken);
        distributor = RewardDistributor(_distributor);
    }

    function stake(uint256 amount) external {
        require(amount > 0, "Cannot stake 0");
        stakedBalance[msg.sender] += amount;
        totalStaked += amount;
        bool ok = stakingToken.transferFrom(msg.sender, address(this), amount);
        require(ok, "Transfer failed");
        emit Staked(msg.sender, amount);
    }

    function withdraw(uint256 amount) external {
        require(stakedBalance[msg.sender] >= amount, "Insufficient staked balance");
        stakedBalance[msg.sender] -= amount;
        totalStaked -= amount;
        bool ok = stakingToken.transfer(msg.sender, amount);
        require(ok, "Transfer failed");
        emit Withdrawn(msg.sender, amount);
    }

    function claimRewards() external {
        uint256 rewardAmount = stakedBalance[msg.sender] / 10;
        if (rewardAmount > 0) {
            distributor.payout(msg.sender, rewardAmount);
        }
    }
}
