/**
 * Smart Contract Security Analyzer
 * Production-grade static analysis for EVM contracts
 * ERC-8004 Monetizable Service - $50-$200 USDC on Base
 */

import https from 'https';
import http from 'http';
import { URL } from 'url';

// Severity levels
const SEVERITY = {
  CRITICAL: 'critical',
  HIGH: 'high',
  MEDIUM: 'medium',
  LOW: 'low',
  INFO: 'info'
};

// Chain configurations
const CHAIN_CONFIGS = {
  ethereum: {
    name: 'Ethereum Mainnet',
    chainId: 1,
    etherscanApi: 'https://api.etherscan.io/api',
    sourcifyUrl: 'https://repo.sourcify.dev/contracts/full_match/1',
    explorer: 'https://etherscan.io'
  },
  base: {
    name: 'Base',
    chainId: 8453,
    etherscanApi: 'https://api.basescan.org/api',
    sourcifyUrl: 'https://repo.sourcify.dev/contracts/full_match/8453',
    explorer: 'https://basescan.org'
  },
  arbitrum: {
    name: 'Arbitrum One',
    chainId: 42161,
    etherscanApi: 'https://api.arbiscan.io/api',
    sourcifyUrl: 'https://repo.sourcify.dev/contracts/full_match/42161',
    explorer: 'https://arbiscan.io'
  },
  optimism: {
    name: 'Optimism',
    chainId: 10,
    etherscanApi: 'https://api-optimistic.etherscan.io/api',
    sourcifyUrl: 'https://repo.sourcify.dev/contracts/full_match/10',
    explorer: 'https://optimistic.etherscan.io'
  },
  polygon: {
    name: 'Polygon PoS',
    chainId: 137,
    etherscanApi: 'https://api.polygonscan.com/api',
    sourcifyUrl: 'https://repo.sourcify.dev/contracts/full_match/137',
    explorer: 'https://polygonscan.com'
  }
};

// Vulnerability patterns for static analysis
const VULNERABILITY_PATTERNS = [
  // Reentrancy patterns
  {
    id: 'REENTRANCY-001',
    name: 'Reentrancy Vulnerability',
    severity: SEVERITY.CRITICAL,
    pattern: /function\s+\w+[^)]*\)[^{]*\{[^}]*\..*call\s*\{[^}]*\}\s*\([^)]*\)\s*\([^)]*\)[^{;]*;/is,
    description: 'External call before state update - potential reentrancy',
    recommendation: 'Use Checks-Effects-Interactions pattern or ReentrancyGuard'
  },
  {
    id: 'REENTRANCY-002',
    name: 'Unchecked External Call Return',
    severity: SEVERITY.HIGH,
    pattern: /\.(call|staticcall|delegatecall)\s*\([^)]*\)\s*;[\s\S]*?(?!(require|if\s*\(|revert))/i,
    description: 'External call return value not checked',
    recommendation: 'Check return value of external calls or use .call{value: x}() format'
  },
  // Access control patterns
  {
    id: 'ACCESS-001',
    name: 'Missing Access Control',
    severity: SEVERITY.CRITICAL,
    pattern: /function\s+(mint|burn|transferOwnership|withdraw|pause|unpause)\s*\([^)]*\)\s+public\s+(?:(?!onlyOwner|onlyRole|require|modifier).)*\{/is,
    description: 'Critical function lacks access control',
    recommendation: 'Add appropriate access control modifiers (onlyOwner, onlyRole, etc.)'
  },
  {
    id: 'ACCESS-002',
    name: 'TxOrigin Auth',
    severity: SEVERITY.HIGH,
    pattern: /tx\.origin\s*==\s*owner/i,
    description: 'Using tx.origin for authorization',
    recommendation: 'Use msg.sender instead of tx.origin for authorization'
  },
  // Integer overflow/underflow
  {
    id: 'MATH-001',
    name: 'Potential Integer Overflow',
    severity: SEVERITY.HIGH,
    pattern: /[^\d\w](\w+)\s*[\+\-\*]\s*=\s*\w+[^;]*[^!><=]=[^=][^;]*;/i,
    description: 'Unchecked arithmetic operation',
    recommendation: 'Use SafeMath library (pre-0.8) or solidity ^0.8.0 with unchecked blocks where safe'
  },
  // Randomness
  {
    id: 'RANDOM-001',
    name: 'Weak Randomness',
    severity: SEVERITY.HIGH,
    pattern: /(block\.timestamp|block\.number|blockhash)\s*%\s*\w+/i,
    description: 'Predictable randomness source',
    recommendation: 'Use Chainlink VRF or commit-reveal scheme'
  },
  // Delegate call
  {
    id: 'DELEGATE-001', 
    name: 'Dangerous Delegatecall',
    severity: SEVERITY.CRITICAL,
    pattern: /\.delegatecall\s*\(/i,
    description: 'Use of delegatecall detected',
    recommendation: 'Ensure delegatecall target is trusted and validated'
  },
  // Selfdestruct
  {
    id: 'LIFE-001',
    name: 'Contract Can Be Destroyed',
    severity: SEVERITY.MEDIUM,
    pattern: /selfdestruct\s*\(|suicide\s*\(/i,
    description: 'Contract contains selfdestruct/suicide',
    recommendation: 'Verify proper access controls on selfdestruct'
  },
  // Timestamp dependence
  {
    id: 'TIME-001',
    name: 'Timestamp Dependence',
    severity: SEVERITY.MEDIUM,
    pattern: /block\.timestamp\s*[<>=!]+\s*\d+/i,
    description: 'Contract logic depends on block timestamp',
    recommendation: 'Consider that miners can manipulate timestamps slightly'
  },
  // Storage collision in proxies
  {
    id: 'PROXY-001',
    name: 'Proxy Storage Collision Risk',
    severity: SEVERITY.HIGH,
    pattern: /(implementation|_implementation)\s*=\s*\w+\s*;/i,
    description: 'Proxy pattern detected - check storage layout',
    recommendation: 'Verify use of unstructured storage or EIP-1967 slots'
  },
  // Approval race condition
  {
    id: 'ERC20-001',
    name: 'ERC20 Approval Race Condition',
    severity: SEVERITY.MEDIUM,
    pattern: /function\s+approve\s*\([^)]*\)\s*\{[^}]*\}/is,
    description: 'Standard approve function - potential race condition',
    recommendation: 'Use increaseAllowance/decreaseAllowance or safeApprove pattern'
  },
  // Unchecked transfers
  {
    id: 'ERC20-002',
    name: 'Unchecked ERC20 Transfer',
    severity: SEVERITY.MEDIUM,
    pattern: /\.transfer\s*\([^)]*\)\s*;(?![^}]*require)/i,
    description: 'ERC20 transfer return value not checked',
    recommendation: 'Use SafeERC20 or check return value'
  },
  // Assembly usage
  {
    id: 'ASM-001',
    name: 'Assembly Code Detected',
    severity: SEVERITY.INFO,
    pattern: /assembly\s*\{/i,
    description: 'Low-level assembly usage',
    recommendation: 'Review assembly code carefully for correctness'
  },
  // Low-level call with value
  {
    id: 'CALL-001',
    name: 'Unchecked Call with Value',
    severity: SEVERITY.HIGH,
    pattern: /call\s*\{[^}]*value\s*:\s*[^}]+\}\s*\([^)]*\)/i,
    description: 'Low-level call with ETH transfer',
    recommendation: 'Check call return value and handle failures'
  },
  // Ether transfers to arbitrary addresses
  {
    id: 'TRANSFER-001',
    name: 'Arbitrary ETH Transfer',
    severity: SEVERITY.MEDIUM,
    pattern: /(transfer|send)\s*\(\s*\w+\s*\)/i,
    description: 'ETH transfer to untrusted address',
    recommendation: 'Ensure recipient is trusted or implement withdraw pattern'
  },
  // Floating pragma
  {
    id: 'SOL-001',
    name: 'Floating Pragma',
    severity: SEVERITY.INFO,
    pattern: /pragma\s+solidity\s*\^0\.\d+\.\d+\s*;/i,
    description: 'Using caret (^) in pragma allows compiler version changes',
    recommendation: 'Lock pragma to specific version for determinism'
  }
];

// Security best practice patterns to verify
const BEST_PRACTICES = [
  {
    id: 'BP-001',
    name: 'Events Emitted',
    pattern: /emit\s+\w+\s*\(/i,
    description: 'Contract emits events'
  },
  {
    id: 'BP-002',
    name: 'NatSpec Comments',
    pattern: /\/\*\*[\s\S]*?@/i,
    description: 'Contract uses NatSpec documentation'
  },
  {
    id: 'BP-003',
    name: 'Custom Errors',
    pattern: /error\s+\w+\s*\(/i,
    description: 'Uses custom errors for gas efficiency'
  }
];

/**
 * Fetch contract source from Etherscan
 */
async function fetchFromEtherscan(address, chainConfig, apiKey = null) {
  return new Promise((resolve, reject) => {
    const url = new URL(chainConfig.etherscanApi);
    url.searchParams.append('module', 'contract');
    url.searchParams.append('action', 'getsourcecode');
    url.searchParams.append('address', address);
    if (apiKey) url.searchParams.append('apikey', apiKey);

    const client = url.protocol === 'https:' ? https : http;
    
    const req = client.get(url.toString(), { timeout: 30000 }, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          const response = JSON.parse(data);
          if (response.status === '0' || !response.result || response.result.length === 0) {
            reject(new Error(`Etherscan error: ${response.message || 'No source code'}`));
            return;
          }
          
          const source = response.result[0];
          if (!source.SourceCode || source.SourceCode === '') {
            reject(new Error('Contract source code not verified'));
            return;
          }
          
          let parsedSource = source.SourceCode;
          // Handle JSON-wrapped source (multi-file contracts)
          if (parsedSource.startsWith('{{') && parsedSource.endsWith('}}')) {
            try {
              parsedSource = JSON.parse(parsedSource.slice(1, -1));
            } catch (e) {
              // Not valid JSON, keep as string
            }
          }
          
          resolve({
            sourceCode: parsedSource,
            contractName: source.ContractName,
            compilerVersion: source.CompilerVersion,
            optimizationUsed: source.OptimizationUsed,
            runs: source.Runs,
            constructorArguments: source.ConstructorArguments,
            evmVersion: source.EVMVersion,
            library: source.Library,
            licenseType: source.LicenseType,
            proxy: source.Proxy === '1',
            implementation: source.Implementation,
            swarmSource: source.SwarmSource,
            abi: source.ABI ? JSON.parse(source.ABI) : null
          });
        } catch (err) {
          reject(new Error(`Failed to parse Etherscan response: ${err.message}`));
        }
      });
    });
    
    req.on('error', reject);
    req.on('timeout', () => {
      req.destroy();
      reject(new Error('Request timed out'));
    });
  });
}

/**
 * Analyze source code for vulnerabilities
 */
function analyzeVulnerabilities(sourceCode, contractName) {
  const findings = [];
  
  // Convert source to string if object (multi-file)
  const sourceString = typeof sourceCode === 'object' 
    ? Object.values(sourceCode).map(f => f.content || JSON.stringify(f)).join('\n')
    : sourceCode;
  
  const lines = sourceString.split('\n');
  
  // Run vulnerability patterns
  for (const pattern of VULNERABILITY_PATTERNS) {
    let match;
    while ((match = pattern.pattern.exec(sourceString)) !== null) {
      // Find line number
      const position = match.index;
      let lineNum = 1;
      let currentPos = 0;
      for (let i = 0; i < lines.length; i++) {
        currentPos += lines[i].length + 1;
        if (currentPos > position) {
          lineNum = i + 1;
          break;
        }
      }
      
      // Extract context (surrounding lines)
      const contextStart = Math.max(0, lineNum - 2);
      const contextEnd = Math.min(lines.length, lineNum + 2);
      const context = lines.slice(contextStart, contextEnd).join('\n');
      
      findings.push({
        id: pattern.id,
        name: pattern.name,
        severity: pattern.severity,
        line: lineNum,
        description: pattern.description,
        recommendation: pattern.recommendation,
        context: context.trim()
      });
    }
    // Reset lastIndex for next pattern search
    pattern.pattern.lastIndex = 0;
  }
  
  // Check for best practices
  const bestPractices = [];
  for (const bp of BEST_PRACTICES) {
    if (bp.pattern.test(sourceString)) {
      bestPractices.push({
        id: bp.id,
        name: bp.name,
        description: bp.description
      });
    }
    bp.pattern.lastIndex = 0;
  }
  
  // Calculate complexity metrics
  const functionCount = (sourceString.match(/function\s+\w+/g) || []).length;
  const modifierCount = (sourceString.match(/modifier\s+\w+/g) || []).length;
  const eventCount = (sourceString.match(/event\s+\w+/g) || []).length;
  const requireCount = (sourceString.match(/require\s*\(/g) || []).length;
  const customErrorCount = (sourceString.match(/error\s+\w+/g) || []).length;
  
  // Line of code
  const loc = lines.filter(l => l.trim() && !l.trim().startsWith('//') && !l.trim().startsWith('*')).length;
  
  return {
    findings: findings.sort((a, b) => {
      const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
      return severityOrder[a.severity] - severityOrder[b.severity];
    }),
    bestPractices,
    metrics: {
      linesOfCode: loc,
      functionCount,
      modifierCount,
      eventCount,
      requireStatements: requireCount,
      customErrors: customErrorCount
    }
  };
}

/**
 * Generate security score
 */
function calculateSecurityScore(analysis) {
  const { findings, metrics } = analysis;
  
  // Base score
  let score = 100;
  
  // Deduct for critical and high severity issues
  const criticalCount = findings.filter(f => f.severity === SEVERITY.CRITICAL).length;
  const highCount = findings.filter(f => f.severity === SEVERITY.HIGH).length;
  const mediumCount = findings.filter(f => f.severity === SEVERITY.MEDIUM).length;
  const lowCount = findings.filter(f => f.severity === SEVERITY.LOW).length;
  
  score -= criticalCount * 25;
  score -= highCount * 15;
  score -= mediumCount * 5;
  score -= lowCount * 2;
  
  // Boost for best practices
  if (analysis.bestPractices.some(bp => bp.id === 'BP-001')) score += 3; // Events
  if (analysis.bestPractices.some(bp => bp.id === 'BP-002')) score += 2; // NatSpec
  
  // Check for access control
  const hasAccessControl = findings.some(f => f.id.startsWith('ACCESS')) === false;
  if (hasAccessControl) score += 5;
  
  return {
    overall: Math.max(0, Math.min(100, score)),
    breakdown: {
      critical: criticalCount,
      high: highCount,
      medium: mediumCount,
      low: lowCount,
      info: findings.filter(f => f.severity === SEVERITY.INFO).length
    },
    riskLevel: score >= 90 ? 'Low' : score >= 70 ? 'Medium' : score >= 50 ? 'High' : 'Critical'
  };
}

/**
 * Main analysis function
 */
export async function analyzeContract(address, chain = 'base', options = {}) {
  const chainConfig = CHAIN_CONFIGS[chain.toLowerCase()];
  if (!chainConfig) {
    throw new Error(`Unsupported chain: ${chain}. Supported: ${Object.keys(CHAIN_CONFIGS).join(', ')}`);
  }
  
  // Normalize address
  const normalizedAddress = address.toLowerCase();
  
  // Fetch source code
  const sourceData = await fetchFromEtherscan(
    normalizedAddress, 
    chainConfig, 
    options.etherscanApiKey
  );
  
  // Analyze
  const analysis = analyzeVulnerabilities(sourceData.sourceCode, sourceData.contractName);
  const score = calculateSecurityScore(analysis);
  
  // Determine pricing tier based on complexity
  const complexity = analysis.metrics.linesOfCode;
  let recommendedPrice = 50; // Base price
  if (complexity > 500) recommendedPrice = 75;
  if (complexity > 1000) recommendedPrice = 100;
  if (complexity > 2000) recommendedPrice = 150;
  if (complexity > 5000) recommendedPrice = 200;
  
  return {
    agentId: 23984,
    agentName: 'Metatron',
    serviceVersion: '2.0.0',
    contract: {
      address: normalizedAddress,
      name: sourceData.contractName || 'Unknown',
      chain: chainConfig.name,
      chainId: chainConfig.chainId,
      isProxy: sourceData.proxy,
      implementation: sourceData.implementation,
      compiler: sourceData.compilerVersion,
      optimization: sourceData.optimizationUsed === '1',
      runs: sourceData.runs,
      evmVersion: sourceData.evmVersion,
      license: sourceData.licenseType,
      abi: !!sourceData.abi
    },
    analysis: {
      ...analysis,
      score,
      severityCounts: score.breakdown
    },
    pricing: {
      recommendedUSD: recommendedPrice,
      complexity: complexity < 500 ? 'low' : complexity < 2000 ? 'medium' : 'high'
    },
    timestamp: new Date().toISOString(),
    links: {
      explorer: `${chainConfig.explorer}/address/${normalizedAddress}`,
      sourcify: `${chainConfig.sourcifyUrl}/${normalizedAddress}`
    }
  };
}

// Export for use in MCP server
export { CHAIN_CONFIGS, SEVERITY };