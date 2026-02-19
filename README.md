# Metatron MCP Server — Agent #23984

Smart Contract Security Auditor with ERC-8004/x402 payment monetization.

## Features

- **Smart Contract Audits** — Slither-style static analysis for EVM contracts
- **x402 Payment Protocol** — USDC payments on Base chain
- **MCP Integration** — Full Model Context Protocol support via SSE
- **Multi-chain Support** — Ethereum, Base, Polygon, Arbitrum, Optimism, BSC, Avalanche

## Pricing

| Service | Price | Description |
|---------|-------|-------------|
| Contract Audit | $100 USDC | Full security audit with verified source analysis |
| Quick Scan | $10 USDC | Analyze provided Solidity source code |

## Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Service health and status |
| `/x402/pricing` | GET | x402 payment information |
| `/x402/verify` | POST | Verify payment transaction |
| `/x402/status/:txHash` | GET | Check payment status |
| `/api/contract-audit` | POST | Full audit (requires payment) |
| `/api/quick-scan` | POST | Quick scan (requires payment) |
| `/api/preview` | POST | Free preview (summary only) |
| `/mcp/sse` | GET | MCP SSE endpoint |

## Vulnerability Checks

- Reentrancy
- Integer Overflow/Underflow
- Unchecked Call Returns
- Selfdestruct
- Delegatecall to Untrusted Callee
- tx.origin Authentication
- Access Control Issues
- Floating Pragma
- Timestamp Dependence

## Quick Start

```bash
# Install dependencies
npm install

# Set Etherscan API key (optional but recommended)
export ETHERSCAN_API_KEY=your_key_here

# Start server
npm start
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PORT` | Server port | 3402 |
| `ETHERSCAN_API_KEY` | Etherscan API key for fetching verified source | (none) |

## Payment Flow (x402)

1. Client calls `/api/contract-audit` without payment header
2. Server returns 402 with payment instructions
3. Client sends USDC to wallet on Base chain
4. Client retries with `X-Payment: <txHash>` header
5. Server verifies on-chain payment
6. Server returns audit results

## Files

- `index.js` — Main server with MCP and REST endpoints
- `contract-audit.js` — Static analysis engine
- `verify-payment.js` — x402 payment verification module
- `agent-metadata.json` — ERC-8004 agent metadata
- `cloudflare-tunnel-setup.ps1` — Stable tunnel setup script

## Wallet

**Address:** `0x11B185ceFcB2A001FFDddf0f226437D16EbF5437`  
**Network:** Base (Chain ID 8453)  
**Currency:** USDC (`0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913`)

## Agent Info

- **Agent ID:** 23984
- **Name:** Metatron
- **Nostr:** `npub1jhfp70rew48zlk4l53zr7cuxef76w722pxfgpsa2yxjdrgfpx7csgsj69f`
- **Lightning:** `metatronscribe@coinos.io`
