// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VulnerableBank {
    mapping(address => uint256) public balances;
    uint256 public totalDeposits;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
        totalDeposits += msg.value;
    }

    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        // Vulnerability: Reentrancy
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        
        balances[msg.sender] -= amount;
        totalDeposits -= amount;
    }

    function transfer(address to, uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        // Vulnerability: Integer overflow (in Solidity versions < 0.8.0)
        balances[to] += amount;
        balances[msg.sender] -= amount;
    }

    // Vulnerability: Improper access control
    function drainContract() public {
        uint256 balance = address(this).balance;
        payable(msg.sender).transfer(balance);
    }

    // Vulnerability: Unprotected self-destruct
    function destroyContract() public {
        selfdestruct(payable(msg.sender));
    }

    // Vulnerability: Use of tx.origin
    function transferToOwner() public {
        require(tx.origin != msg.sender, "Owner cannot call directly");
        payable(tx.origin).transfer(address(this).balance);
    }

    // Vulnerability: Weak random number generation
    function generateRandomNumber() public view returns (uint256) {
        return uint256(keccak256(abi.encodePacked(block.timestamp, block.difficulty, msg.sender))) % 100;
    }

    receive() external payable {
        deposit();
    }
}