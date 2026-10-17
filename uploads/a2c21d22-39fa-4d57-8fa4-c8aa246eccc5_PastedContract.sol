```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IPriceOracle {
    function getPrice() external view returns (uint256);
}

contract ContextAnalysisTest {
    address public owner;
    address public treasury;
    uint256 public totalDeposits;
    mapping(address => uint256) public balances;

    IPriceOracle public priceOracle;

    event Deposited(address indexed user, uint256 amount);
    event Withdrawn(address indexed user, uint256 amount);
    event TreasuryUpdated(address indexed newTreasury);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    constructor(address _oracle, address _treasury) {
        owner = msg.sender;
        priceOracle = IPriceOracle(_oracle);
        treasury = _treasury;
    }

    function deposit() external payable {
        require(msg.value > 0, "Zero deposit");

        balances[msg.sender] += msg.value;
        totalDeposits += msg.value;

        emit Deposited(msg.sender, msg.value);
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        balances[msg.sender] -= amount;
        totalDeposits -= amount;

        (bool success, ) = payable(msg.sender).call{value: amount}("");
        require(success, "Transfer failed");

        emit Withdrawn(msg.sender, amount);
    }

    function updateTreasury(address newTreasury)
        external
        onlyOwner
    {
        require(newTreasury != address(0), "Zero address");

        treasury = newTreasury;
        emit TreasuryUpdated(newTreasury);
    }

    function getOraclePrice() external view returns (uint256) {
        return priceOracle.getPrice();
    }

    function emergencyWithdraw() external onlyOwner {
        uint256 amount = address(this).balance;

        (bool success, ) = payable(treasury).call{value: amount}("");
        require(success, "Transfer failed");
    }
}
```