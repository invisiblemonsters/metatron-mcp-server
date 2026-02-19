/**
 * x402 Payment Verification Module
 * Verifies USDC payments on Base chain before serving requests
 */

import { createPublicClient, http, parseUnits, formatUnits } from 'viem';
import { base } from 'viem/chains';

const USDC_CONTRACT = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913'; // Base USDC
const RECEIVER_WALLET = '0x11B185ceFcB2A001FFDddf0f226437D16EbF5437';

const client = createPublicClient({
  chain: base,
  transport: http('https://mainnet.base.org'),
});

// Cache verified payments to prevent replays
const verifiedPayments = new Map();
const PAYMENT_CACHE_TTL = 24 * 60 * 60 * 1000; // 24 hours

export async function verifyPayment(paymentId, expectedAmount) {
  try {
    // Check cache first
    if (verifiedPayments.has(paymentId)) {
      const cached = verifiedPayments.get(paymentId);
      if (Date.now() - cached.timestamp < PAYMENT_CACHE_TTL) {
        return { verified: true, cached: true, details: cached };
      }
    }

    // Verify payment on-chain using transfer logs
    const expectedAmountWei = parseUnits(expectedAmount, 6); // USDC has 6 decimals
    
    // Get recent transfer events to receiver
    const logs = await client.getLogs({
      address: USDC_CONTRACT,
      event: {
        type: 'event',
        name: 'Transfer',
        inputs: [
          { type: 'address', name: 'from', indexed: true },
          { type: 'address', name: 'to', indexed: true },
          { type: 'uint256', name: 'value', indexed: false }
        ]
      },
      args: {
        to: RECEIVER_WALLET
      },
      fromBlock: 'latest' - 1000n, // Last 1000 blocks
      toBlock: 'latest'
    });

    // Find matching payment
    for (const log of logs) {
      const amount = log.args.value;
      if (amount === expectedAmountWei) {
        const verification = {
          verified: true,
          txHash: log.transactionHash,
          blockNumber: log.blockNumber.toString(),
          amount: expectedAmount,
          from: log.args.from,
          to: log.args.to,
          timestamp: Date.now()
        };
        verifiedPayments.set(paymentId, verification);
        return verification;
      }
    }

    return { verified: false, error: 'Payment not found on-chain' };
  } catch (error) {
    return { verified: false, error: error.message };
  }
}

// x402 payment header parsing
export function parseX402Header(header) {
  try {
    if (!header) return null;
    
    // Parse x402-payment header: "base sepolia <chainId>:<receiver>:<amount>:<signature>"
    const pattern = /^base\s+mainnet\s+(\d+):(0x[a-fA-F0-9]+):(\d+):(0x[a-fA-F0-9]+)$/i;
    const match = header.match(pattern);
    
    if (!match) return null;
    
    return {
      chainId: parseInt(match[1]),
      receiver: match[2],
      amount: match[3],
      signature: match[4]
    };
  } catch {
    return null;
  }
}

// Fast in-memory payment cache cleanup (call periodically)
export function cleanupPaymentCache() {
  const now = Date.now();
  for (const [id, data] of verifiedPayments) {
    if (now - data.timestamp > PAYMENT_CACHE_TTL) {
      verifiedPayments.delete(id);
    }
  }
}
