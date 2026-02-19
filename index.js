import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse.js";
import { z } from "zod";
import express from "express";
import { verifyPayment, parseX402Header } from "./verify-payment.js";

const AGENT_ID = 23984;
const AGENT_NAME = "Metatron";
const WALLET = "0x11B185ceFcB2A001FFDddf0f226437D16EbF5437";
const PORT = process.env.PORT || 3402;
const ETHERSCAN_API_KEY = process.env.ETHERSCAN_API_KEY || "";

const SERVICES = {
  "quick-scan": { price: "1", description: "Quick pattern scan - basic vulnerability check", tier: "basic" },
  "deep-audit": { price: "50", description: "Deep contract audit with full analysis", tier: "premium" },
  "sentiment": { price: "0.10", description: "Sentiment analysis on text/token", tier: "basic" },
};

// ── Contract Analysis ──────────────────────────────────────────────
async function fetchContractSource(address, chainId = 1) {
  const chainToApi = {
    1: "https://api.etherscan.io/api",
    8453: "https://api.basescan.org/api",
    42161: "https://api.arbiscan.io/api",
    10: "https://api-optimistic.etherscan.io/api",
  };
  const apiUrl = chainToApi[chainId] || chainToApi[1];
  const response = await fetch(
    `${apiUrl}?module=contract&action=getsourcecode&address=${address}&apikey=${ETHERSCAN_API_KEY}`
  );
  const data = await response.json();
  if (data.result?.[0]?.SourceCode) {
    return {
      source: data.result[0].SourceCode,
      compiler: data.result[0].CompilerVersion,
      name: data.result[0].ContractName,
      abi: data.result[0].ABI,
    };
  }
  return null;
}

function analyzeContract(source) {
  const code = typeof source === "string" ? source : "";
  const findings = [];
  const checks = [
    { pattern: /\.call\{value:|\.call\.value/gi, severity: "Critical", name: "Reentrancy Risk", desc: "External calls with value transfer - check state updates" },
    { pattern: /tx\.origin/gi, severity: "High", name: "tx.origin Auth", desc: "Phishing vulnerability via tx.origin" },
    { pattern: /selfdestruct|suicide/gi, severity: "High", name: "Selfdestruct", desc: "Contract can be destroyed" },
    { pattern: /delegatecall/gi, severity: "Critical", name: "Delegatecall", desc: "Context hijacking risk via delegatecall" },
    { pattern: /block\.timestamp/gi, severity: "Low", name: "Timestamp Dependency", desc: "Miner manipulation possible" },
    { pattern: /ecrecover/gi, severity: "Medium", name: "Signature Validation", desc: "Verify signature malleability protection" },
    { pattern: /assembly\s*\{/gi, severity: "Medium", name: "Inline Assembly", desc: "Manual memory management risk" },
    { pattern: /unchecked\s*\{/gi, severity: "Low", name: "Unchecked Arithmetic", desc: "Intentional overflow/underflow" },
    { pattern: /\.transfer\(|\.send\(/gi, severity: "Low", name: "Fixed Gas Transfer", desc: "2300 gas limit may cause failures" },
    { pattern: /approve\s*\(/gi, severity: "Low", name: "Approval Pattern", desc: "Check for approval race condition" },
  ];
  for (const check of checks) {
    const matches = code.match(check.pattern);
    if (matches) {
      findings.push({ ...check, count: matches.length });
    }
  }
  const critCount = findings.filter(f => f.severity === "Critical").length;
  const highCount = findings.filter(f => f.severity === "High").length;
  const score = Math.max(0, 100 - critCount * 25 - highCount * 15 - findings.length * 3);
  return {
    findings,
    score,
    grade: critCount > 0 ? "D" : highCount > 0 ? "C" : score > 80 ? "A" : "B",
    linesOfCode: code.split("\n").length,
  };
}

function analyzeSentiment(text) {
  const positive = ["good", "great", "bullish", "moon", "pump", "up", "strong", "growth", "profit", "gain", "buy", "love", "amazing", "excellent"];
  const negative = ["bad", "bearish", "dump", "crash", "down", "weak", "loss", "scam", "rug", "sell", "hate", "terrible", "fear", "risk"];
  const words = text.toLowerCase().split(/\s+/);
  let pos = 0, neg = 0;
  for (const w of words) {
    if (positive.some(p => w.includes(p))) pos++;
    if (negative.some(n => w.includes(n))) neg++;
  }
  const total = pos + neg || 1;
  const score = ((pos - neg) / total + 1) / 2; // 0-1 scale
  return {
    score: Math.round(score * 100) / 100,
    label: score > 0.6 ? "bullish" : score < 0.4 ? "bearish" : "neutral",
    positive: pos,
    negative: neg,
    wordCount: words.length,
  };
}

// ── MCP Server ─────────────────────────────────────────────────────
const server = new McpServer({ name: "metatron-agent-23984", version: "2.0.0" });

server.tool(
  "quickScan",
  { contractAddress: z.string().regex(/^0x[a-fA-F0-9]{40}$/), chainId: z.number().default(1) },
  async ({ contractAddress, chainId }) => {
    const source = await fetchContractSource(contractAddress, chainId);
    if (!source) return { content: [{ type: "text", text: JSON.stringify({ error: "Contract not verified or source unavailable" }) }] };
    const analysis = analyzeContract(source.source);
    return {
      content: [{ type: "text", text: JSON.stringify({
        agentId: AGENT_ID, service: "quick-scan",
        contract: { address: contractAddress, chainId, name: source.name },
        findings: analysis.findings, score: analysis.score, grade: analysis.grade,
        linesOfCode: analysis.linesOfCode,
      }, null, 2) }],
    };
  }
);

server.tool(
  "sentimentAnalysis",
  { text: z.string().min(1).max(10000) },
  async ({ text }) => {
    const result = analyzeSentiment(text);
    return { content: [{ type: "text", text: JSON.stringify({ agentId: AGENT_ID, service: "sentiment", ...result }, null, 2) }] };
  }
);

// ── Express Server ─────────────────────────────────────────────────
const app = express();
app.use(express.json());

// Request counter for stats
let requestCount = 0;
let paidRequests = 0;
const startTime = Date.now();

// x402 Payment Middleware
function requirePayment(serviceId) {
  return (req, res, next) => {
    const service = SERVICES[serviceId];
    if (!service) return next();
    
    const x402Header = req.headers["x402-payment"];
    if (!x402Header) {
      return res.status(402).json({
        error: "Payment Required",
        x402: {
          version: "0.1.0",
          network: "base",
          receiver: WALLET,
          amount: service.price,
          currency: "USDC",
          description: service.description,
          requiredHeaders: ["x402-payment"],
        },
      });
    }
    const paymentId = `${x402Header}:${Date.now().toString().slice(0, -6)}`;
    verifyPayment(paymentId, service.price).then(verification => {
      if (!verification.verified) {
        return res.status(402).json({ error: "Invalid or unverified payment", details: verification.error });
      }
      paidRequests++;
      req.paymentVerified = verification;
      next();
    }).catch(err => res.status(500).json({ error: err.message }));
  };
}

// ── Free Endpoints ─────────────────────────────────────────────────
app.get("/", (req, res) => {
  requestCount++;
  res.json({
    agent: AGENT_NAME,
    agentId: AGENT_ID,
    erc8004: `https://etherscan.io/nft/0x8004A169FB4a3325136EB29fA0ceB6D2e539a432/${AGENT_ID}`,
    wallet: WALLET,
    services: Object.entries(SERVICES).map(([id, s]) => ({ id, ...s, currency: "USDC" })),
    mcp: "/mcp/sse",
    uptime: Math.floor((Date.now() - startTime) / 1000),
    requests: { total: requestCount, paid: paidRequests },
  });
});

app.get("/health", (req, res) => {
  res.json({ status: "ok", agent: AGENT_ID, uptime: Math.floor((Date.now() - startTime) / 1000) });
});

app.get("/status", (req, res) => {
  requestCount++;
  res.json({
    agent: AGENT_NAME,
    agentId: AGENT_ID,
    wallet: WALLET,
    services: SERVICES,
    stats: { uptime: Math.floor((Date.now() - startTime) / 1000), requests: requestCount, paidRequests },
    identity: {
      erc8004: AGENT_ID,
      registry: "0x8004A169FB4a3325136EB29fA0ceB6D2e539a432",
      agentURI: "ipfs://QmV9iny8fixpxP5nBhLCKXSUpoDf7S6B62KmPmW424eyaA",
    },
  });
});

// ── Paid Endpoints ─────────────────────────────────────────────────
app.post("/api/scan", requirePayment("quick-scan"), async (req, res) => {
  requestCount++;
  const { address, chainId = 1 } = req.body;
  if (!address) return res.status(400).json({ error: "address required" });
  const source = await fetchContractSource(address, chainId);
  if (!source) return res.status(404).json({ error: "Contract not verified" });
  const analysis = analyzeContract(source.source);
  res.json({
    agentId: AGENT_ID, service: "quick-scan",
    contract: { address, name: source.name, chainId },
    ...analysis,
    paymentVerified: req.paymentVerified?.cached ? "cached" : "fresh",
  });
});

app.post("/api/sentiment", requirePayment("sentiment"), async (req, res) => {
  requestCount++;
  const { text } = req.body;
  if (!text) return res.status(400).json({ error: "text required" });
  res.json({ agentId: AGENT_ID, service: "sentiment", ...analyzeSentiment(text) });
});

// ── MCP SSE ────────────────────────────────────────────────────────
app.get("/mcp/sse", async (req, res) => {
  requestCount++;
  const transport = new SSEServerTransport("/mcp", res);
  await server.connect(transport);
});

app.listen(PORT, () => {
  console.log(`\n  Metatron Agent #${AGENT_ID} — Online`);
  console.log(`  Wallet: ${WALLET}`);
  console.log(`  Port:   ${PORT}`);
  console.log(`  Services:`);
  for (const [id, s] of Object.entries(SERVICES)) {
    console.log(`    - ${id}: $${s.price} USDC — ${s.description}`);
  }
  console.log(`  Endpoints:`);
  console.log(`    GET  /          Agent info (free)`);
  console.log(`    GET  /health    Health check (free)`);
  console.log(`    GET  /status    Full status (free)`);
  console.log(`    GET  /mcp/sse   MCP SSE stream`);
  console.log(`    POST /api/scan      Contract scan ($1 USDC)`);
  console.log(`    POST /api/sentiment Sentiment ($0.10 USDC)\n`);
});
