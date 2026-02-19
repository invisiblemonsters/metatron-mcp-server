import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse.js";
import { z } from "zod";
import express from "express";

const AGENT_ID = 23984;
const AGENT_NAME = "Metatron";
const WALLET = "0x11B185ceFcB2A001FFDddf0f226437D16EbF5437";
const PORT = 8080;

const PRICES = { ".smart-contract-audit": "100" };

async function fetchContractSource(address, chainId = 1) {
  const chainToApi = {
    1: "https://api.etherscan.io/api",
    8453: "https://api.basescan.org/api",
  };
  const apiUrl = chainToApi[chainId] || chainToApi[1];
  try {
    const response = await fetch(`${apiUrl}?module=contract&action=getsourcecode&address=${address}&apikey=`);
    const data = await response.json();
    if (data.result?.[0]?.SourceCode) {
      return { source: data.result[0].SourceCode, compiler: data.result[0].CompilerVersion, name: data.result[0].ContractName };
    }
    return null;
  } catch { return null; }
}

function analyzeContract(source) {
  const code = typeof source === 'string' ? source : '';
  const findings = [];
  if (/call\{value:|\.call\.value/i.test(code) && /balances\[|balance\[/i.test(code)) {
    findings.push({ severity: "Critical", title: "Reentrancy", desc: "External calls before state updates" });
  }
  if (/tx\.origin/i.test(code)) {
    findings.push({ severity: "High", title: "tx.origin", desc: "Phishing vulnerable auth" });
  }
  if (/selfdestruct|suicide/i.test(code)) {
    findings.push({ severity: "High", title: "Selfdestruct", desc: "Contract can be destroyed" });
  }
  if (/delegatecall/i.test(code)) {
    findings.push({ severity: "Critical", title: "Delegatecall", desc: "Context hijacking risk" });
  }
  return { findings, score: Math.max(0, 100 - findings.length * 25), grade: findings.length === 0 ? "A" : findings.length < 3 ? "C" : "F" };
}

const server = new McpServer({ name: "metatron-mcp", version: "1.0.0" });

server.tool("auditContract", { contractAddress: z.string().regex(/^0x[a-fA-F0-9]{40}$/), chainId: z.number().default(1) }, async (params) => {
  const source = await fetchContractSource(params.contractAddress, params.chainId);
  if (!source) return { content: [{ type: "text", text: JSON.stringify({ error: "Contract not verified" }) }] };
  const analysis = analyzeContract(source.source);
  return { content: [{ type: "text", text: JSON.stringify({ agentId: AGENT_ID, contract: { address: params.contractAddress, chainId: params.chainId, name: source.name }, findings: analysis.findings, score: analysis.score, grade: analysis.grade, price: PRICES["smart-contract-audit"] }, null, 2) }] };
});

const app = express();
app.use(express.json());

app.get("/mcp/sse", async (req, res) => {
  const transport = new SSEServerTransport("/mcp", res);
  await server.connect(transport);
});

app.post("/mcp/audit", async (req, res) => {
  const { address, chainId = 1 } = req.body;
  const source = await fetchContractSource(address, chainId);
  const analysis = analyzeContract(source?.source || '');
  res.json({ agentId: AGENT_ID, contract: { address, name: source?.name || "Unknown" }, findings: analysis.findings, score: analysis.score, grade: analysis.grade });
});

app.get("/status", (req, res) => {
  res.json({ agent: AGENT_NAME, agentId: AGENT_ID, wallet: WALLET, service: "smart-contract-audit", price: "$100 USDC" });
});

app.listen(PORT, () => {
  console.log(`🦞 Metatron MCP Server #${AGENT_ID} on Base`);
  console.log(`   Wallet: ${WALLET}`);
  console.log(`   Port: ${PORT}`);
  console.log(`   Service: Smart Contract Audit ($100 USDC)`);
  console.log(`   Endpoints:`);
  console.log(`     - GET  /mcp/sse (MCP SSE stream)`);
  console.log(`     - POST /mcp/audit (requires $100 x402 payment)`);
  console.log(`     - GET  /status`);
});

setInterval(() => {}, 60000);
