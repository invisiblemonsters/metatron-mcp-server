/**
 * Test Script for Metatron Contract Auditor
 * Tests with known vulnerable contract patterns
 */

import { analyzeContract } from './contract-audit.js';

// Known vulnerable contract (reentrancy + other issues)
const VULNERABLE_CONTRACT = `
// SPDX-License-Identifier: MIT
pragma solidity ^0.7.6;

contract VulnerableBank {
    mapping(address => uint256) public balances;
    address public owner;
    
    constructor() {
        owner = tx.origin;  // tx.origin usage
    }
    
    function deposit() public payable {
        balances[msg.sender] += msg.value;  // No SafeMath in 0.7.6
    }
    
    // VULNERABLE: Classic reentrancy
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount);
        
        // External call BEFORE state update (reentrancy!)
        (bool success, ) = msg.sender.call{value: amount}("");
        
        // State update AFTER external call
        balances[msg.sender] -= amount;
    }
    
    // Unchecked send
    function withdrawUnsafe(uint256 amount) public {
        require(balances[msg.sender] >= amount);
        balances[msg.sender] -= amount;
        payable(msg.sender).send(amount);  // Unchecked!
    }
    
    // Dangerous delegatecall
    function execute(address target, bytes memory data) public {
        target.delegatecall(data);
    }
    
    // Timestamp manipulation
    function lottery() public view returns (bool) {
        return block.timestamp % 2 == 0;
    }
    
    // Unprotected selfdestruct
    function destroy() public {
        selfdestruct(payable(owner));
    }
    
    // Weak randomness
    function random() public view returns (uint256) {
        return uint256(keccak256(abi.encodePacked(block.timestamp, msg.sender)));
    }
}
`;

// Secure contract for comparison
const SECURE_CONTRACT = `
// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract SecureBank is ReentrancyGuard, Ownable {
    mapping(address => uint256) public balances;
    
    constructor() Ownable(msg.sender) {}
    
    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }
    
    function withdraw(uint256 amount) external nonReentrant {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        // State update BEFORE external call
        balances[msg.sender] -= amount;
        
        // External call AFTER state update
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
    }
    
    function emergencyWithdraw() external onlyOwner {
        payable(owner()).transfer(address(this).balance);
    }
}
`;

console.log("\n" + "═".repeat(60));
console.log("⚡ METATRON CONTRACT AUDITOR — TEST SUITE");
console.log("═".repeat(60) + "\n");

// Test 1: Vulnerable Contract
console.log("\n📋 TEST 1: Analyzing VULNERABLE contract...\n");
const vulnResult = analyzeContract(VULNERABLE_CONTRACT, "VulnerableBank");

console.log("Contract: " + vulnResult.contractName);
console.log("Score:    " + vulnResult.score + "/100 (Grade: " + vulnResult.grade + ")");
console.log("\nSummary:");
console.log("  🔴 Critical: " + vulnResult.summary.critical);
console.log("  🟠 High:     " + vulnResult.summary.high);
console.log("  🟡 Medium:   " + vulnResult.summary.medium);
console.log("  🟢 Low:      " + vulnResult.summary.low);
console.log("  🔵 Info:     " + vulnResult.summary.info);

console.log("\nFindings:");
for (const finding of vulnResult.findings) {
  const emoji = finding.severity === 'Critical' ? '🔴' : 
                finding.severity === 'High' ? '🟠' :
                finding.severity === 'Medium' ? '🟡' : '🟢';
  console.log("\n  " + emoji + " [" + finding.severity + "] " + finding.title);
  console.log("     " + finding.description);
  if (finding.line) console.log("     Line: " + finding.line);
}

// Test 2: Secure Contract
console.log("\n\n" + "─".repeat(60));
console.log("\n📋 TEST 2: Analyzing SECURE contract...\n");
const secureResult = analyzeContract(SECURE_CONTRACT, "SecureBank");

console.log("Contract: " + secureResult.contractName);
console.log("Score:    " + secureResult.score + "/100 (Grade: " + secureResult.grade + ")");
console.log("\nSummary:");
console.log("  🔴 Critical: " + secureResult.summary.critical);
console.log("  🟠 High:     " + secureResult.summary.high);
console.log("  🟡 Medium:   " + secureResult.summary.medium);
console.log("  🟢 Low:      " + secureResult.summary.low);
console.log("  🔵 Info:     " + secureResult.summary.info);

if (secureResult.findings.length > 0) {
  console.log("\nFindings:");
  for (const finding of secureResult.findings) {
    console.log("  [" + finding.severity + "] " + finding.title);
  }
} else {
  console.log("\n✅ No significant issues found!");
}

// Summary
console.log("\n\n" + "═".repeat(60));
console.log("📊 TEST SUMMARY");
console.log("═".repeat(60));
console.log("\nVulnerable Contract: Score " + vulnResult.score + " (Grade " + vulnResult.grade + ")");
console.log("Secure Contract:     Score " + secureResult.score + " (Grade " + secureResult.grade + ")");
console.log("\nExpected: Vulnerable should score LOW, Secure should score HIGH");

const passed = vulnResult.score < 50 && secureResult.score > 80;
console.log("\nTest Status: " + (passed ? '✅ PASSED' : '❌ FAILED'));
console.log("\n");
