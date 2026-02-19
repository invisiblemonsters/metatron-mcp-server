/**
 * Script to update the on-chain agentURI for Metatron Agent #23984
 * DO NOT EXECUTE without review — this sends an ETH transaction.
 * 
 * Usage: node update-agent-uri.js
 * Requires: PRIVATE_KEY env var (DO NOT hardcode)
 */

import { ethers } from "ethers";

const AGENT_ID = 23984;
const NEW_CID = "QmV9iny8fixpxP5nBhLCKXSUpoDf7S6B62KmPmW424eyaA";
const NEW_URI = `ipfs://${NEW_CID}`;
const REGISTRY = "0x8004A169FB4a3325136EB29fA0ceB6D2e539a432";

// Minimal ABI for setAgentURI
const ABI = [
  "function setAgentURI(uint256 agentId, string calldata uri) external",
  "function agentURI(uint256 agentId) external view returns (string memory)"
];

async function main() {
  const pk = process.env.PRIVATE_KEY;
  if (!pk) { console.error("Set PRIVATE_KEY env var"); process.exit(1); }

  const provider = new ethers.JsonRpcProvider("https://eth.llamarpc.com");
  const wallet = new ethers.Wallet(pk, provider);
  const registry = new ethers.Contract(REGISTRY, ABI, wallet);

  console.log(`Current URI: ${await registry.agentURI(AGENT_ID)}`);
  console.log(`New URI:     ${NEW_URI}`);
  
  const tx = await registry.setAgentURI(AGENT_ID, NEW_URI);
  console.log(`TX: ${tx.hash}`);
  await tx.wait();
  console.log("Done.");
}

main().catch(console.error);
