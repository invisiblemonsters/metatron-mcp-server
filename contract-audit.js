/**
 * Smart Contract Security Audit Module
 * Slither-style static analysis for EVM contracts
 * Metatron Agent #23984
 */

import https from 'https';
import http from 'http';

// Etherscan API endpoints by chain
const ETHERSCAN_APIS = {
  ethereum: { url: 'api.etherscan.io', name: 'Etherscan' },
  base: { url: 'api.basescan.org', name: 'BaseScan' },
  polygon: { url: 'api.polygonscan.com', name: 'PolygonScan' },
  arbitrum: { url: 'api.arbiscan.io', name: 'Arbiscan' },
  optimism: { url: 'api-optimistic.etherscan.io', name: 'Optimism Etherscan' },
  bsc: { url: 'api.bscscan.com', name: 'BscScan' },
  avalanche: { url: 'api.snowtrace.io', name: 'Snowtrace' },
};

// Sourcify API (fallback, no key needed)
const SOURCIFY_API = 'https://sourcify.dev/server';

// Severity levels
const SEVERITY = {
  CRITICAL: { level: 'Critical', score: 10, color: '🔴' },
  HIGH: { level: 'High', score: 8, color: '🟠' },
  MEDIUM: { level: 'Medium', score: 5, color: '🟡' },
  LOW: { level: 'Low', score: 2, color: '🟢' },
  INFO: { level: 'Info', score: 0, color: '🔵' },
};

/**
 * Fetch verified source code from Etherscan-compatible API
 */
async function fetchFromEtherscan(address, chain, apiKey) {
  const api = ETHERSCAN_APIS[chain];
  if (!api) throw new Error(`Unsupported chain: ${chain}`);

  const url = `https://${api.url}/api?module=contract&action=getsourcecode&address=${address}&apikey=${apiKey || ''}`;
  
  return new Promise((resolve, reject) => {
    https.get(url, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          const json = JSON.parse(data);
          if (json.status === '1' && json.result && json.result[0]) {
            const contract = json.result[0];
            if (contract.SourceCode === '') {
              reject(new Error('Contract source not verified'));
              return;
            }
            resolve({
              source: contract.SourceCode,
              name: contract.ContractName,
              compiler: contract.CompilerVersion,
              optimization: contract.OptimizationUsed === '1',
              runs: parseInt(contract.Runs) || 200,
              abi: contract.ABI,
              constructorArguments: contract.ConstructorArguments,
              implementation: contract.Implementation, // For proxies
            });
          } else {
            reject(new Error(json.message || 'Failed to fetch from Etherscan'));
          }
        } catch (e) {
          reject(e);
        }
      });
    }).on('error', reject);
  });
}

/**
 * Fetch from Sourcify (fallback)
 */
async function fetchFromSourcify(address, chainId) {
  const chainIds = {
    ethereum: 1,
    base: 8453,
    polygon: 137,
    arbitrum: 42161,
    optimism: 10,
    bsc: 56,
    avalanche: 43114,
  };

  const id = chainIds[chainId] || chainId;
  const url = `${SOURCIFY_API}/files/tree/any/${id}/${address}`;

  return new Promise((resolve, reject) => {
    https.get(url, (res) => {
      if (res.statusCode === 404) {
        reject(new Error('Contract not found on Sourcify'));
        return;
      }
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          const files = JSON.parse(data);
          // Fetch the main source file
          const sourceFile = files.find(f => f.endsWith('.sol'));
          if (!sourceFile) {
            reject(new Error('No Solidity source found'));
            return;
          }
          // Fetch actual source
          https.get(`${SOURCIFY_API}/files/any/${id}/${address}`, (res2) => {
            let sourceData = '';
            res2.on('data', chunk => sourceData += chunk);
            res2.on('end', () => {
              try {
                const sourceJson = JSON.parse(sourceData);
                const mainFile = sourceJson.find(f => f.name.endsWith('.sol'));
                resolve({
                  source: mainFile?.content || '',
                  name: mainFile?.name?.replace('.sol', '') || 'Unknown',
                  compiler: 'unknown',
                  fromSourcify: true,
                });
              } catch (e) {
                reject(e);
              }
            });
          }).on('error', reject);
        } catch (e) {
          reject(e);
        }
      });
    }).on('error', reject);
  });
}

/**
 * Fetch contract source code
 */
export async function fetchContractSource(address, chain, apiKey) {
  // Normalize address
  address = address.toLowerCase();
  if (!address.startsWith('0x')) address = '0x' + address;

  try {
    // Try Etherscan first
    return await fetchFromEtherscan(address, chain, apiKey);
  } catch (etherscanError) {
    console.log(`[Audit] Etherscan failed: ${etherscanError.message}, trying Sourcify...`);
    try {
      return await fetchFromSourcify(address, chain);
    } catch (sourcifyError) {
      throw new Error(`Failed to fetch source: ${etherscanError.message}. Sourcify: ${sourcifyError.message}`);
    }
  }
}

// ═══════════════════════════════════════════════════════════════════
// STATIC ANALYSIS DETECTORS
// ═══════════════════════════════════════════════════════════════════

/**
 * Detect reentrancy vulnerabilities
 */
function detectReentrancy(source) {
  const findings = [];
  const lines = source.split('\n');
  
  // Pattern: external call followed by state change
  const externalCallPatterns = [
    /\.call\s*\{?\s*value\s*:/i,
    /\.call\s*\(/i,
    /\.send\s*\(/i,
    /\.transfer\s*\(/i,
    /payable\s*\([^)]*\)\.transfer/i,
  ];

  const stateChangePatterns = [
    /balances?\s*\[/i,
    /mapping\s*\(/i,
    /=\s*[^=]/,
  ];

  let inFunction = false;
  let functionName = '';
  let hasExternalCall = false;
  let externalCallLine = 0;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const lineNum = i + 1;

    // Track function boundaries
    const funcMatch = line.match(/function\s+(\w+)/);
    if (funcMatch) {
      inFunction = true;
      functionName = funcMatch[1];
      hasExternalCall = false;
    }

    if (inFunction) {
      // Check for external calls
      for (const pattern of externalCallPatterns) {
        if (pattern.test(line)) {
          hasExternalCall = true;
          externalCallLine = lineNum;
        }
      }

      // Check for state changes after external call
      if (hasExternalCall && lineNum > externalCallLine) {
        if (/\w+\s*\[.*\]\s*=/.test(line) || /\w+\s*=\s*\w+/.test(line)) {
          findings.push({
            type: 'reentrancy',
            severity: SEVERITY.CRITICAL,
            title: 'Potential Reentrancy Vulnerability',
            description: `State change after external call in function '${functionName}'. External call at line ${externalCallLine}, state change at line ${lineNum}.`,
            line: lineNum,
            recommendation: 'Use checks-effects-interactions pattern. Update state before making external calls, or use ReentrancyGuard.',
            code: line.trim(),
          });
        }
      }

      if (line.includes('}') && !line.includes('{')) {
        inFunction = false;
      }
    }
  }

  // Also check for lack of ReentrancyGuard with external calls
  const hasReentrancyGuard = /ReentrancyGuard|nonReentrant|_notEntered/i.test(source);
  const hasExternalCalls = externalCallPatterns.some(p => p.test(source));
  
  if (hasExternalCalls && !hasReentrancyGuard) {
    findings.push({
      type: 'reentrancy',
      severity: SEVERITY.HIGH,
      title: 'Missing Reentrancy Protection',
      description: 'Contract makes external calls but does not use ReentrancyGuard or similar protection.',
      recommendation: 'Inherit from OpenZeppelin\'s ReentrancyGuard and use the nonReentrant modifier on functions with external calls.',
    });
  }

  return findings;
}

/**
 * Detect integer overflow/underflow (pre-0.8.0)
 */
function detectOverflow(source) {
  const findings = [];
  
  // Check compiler version
  const versionMatch = source.match(/pragma\s+solidity\s+[\^~>=<]*\s*([\d.]+)/);
  const version = versionMatch ? versionMatch[1] : '0.8.0';
  const majorMinor = version.split('.').slice(0, 2).map(Number);
  
  if (majorMinor[0] < 8 || (majorMinor[0] === 0 && majorMinor[1] < 8)) {
    // Pre-0.8.0, check for SafeMath
    const hasSafeMath = /SafeMath|using\s+SafeMath/i.test(source);
    
    // Look for arithmetic operations
    const arithmeticOps = source.match(/[\w\[\]]+\s*[\+\-\*]\s*[\w\[\]]+/g) || [];
    
    if (arithmeticOps.length > 0 && !hasSafeMath) {
      findings.push({
        type: 'overflow',
        severity: SEVERITY.HIGH,
        title: 'Integer Overflow/Underflow Risk',
        description: `Solidity ${version} does not have built-in overflow protection. Contract uses arithmetic operations without SafeMath.`,
        recommendation: 'Upgrade to Solidity 0.8.0+ for built-in overflow checks, or use OpenZeppelin SafeMath library.',
      });
    }
  }

  // Check for unchecked blocks in 0.8.0+
  const uncheckedBlocks = source.match(/unchecked\s*\{[^}]+\}/g) || [];
  for (const block of uncheckedBlocks) {
    if (/[\+\-\*\/]/.test(block)) {
      findings.push({
        type: 'overflow',
        severity: SEVERITY.MEDIUM,
        title: 'Unchecked Arithmetic',
        description: 'Arithmetic operations in unchecked block bypass overflow protection.',
        code: block.slice(0, 100) + (block.length > 100 ? '...' : ''),
        recommendation: 'Ensure unchecked arithmetic is intentional and values are bounded.',
      });
    }
  }

  return findings;
}

/**
 * Detect unchecked call return values
 */
function detectUncheckedCalls(source) {
  const findings = [];
  const lines = source.split('\n');

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const lineNum = i + 1;

    // Low-level call without return value check
    if (/\.call\s*[\({]/.test(line) && !/\(\s*bool\s+\w+/.test(line) && !/=\s*\w+\.call/.test(line)) {
      findings.push({
        type: 'unchecked-call',
        severity: SEVERITY.MEDIUM,
        title: 'Unchecked Low-Level Call',
        description: 'Low-level call return value not checked.',
        line: lineNum,
        code: line.trim(),
        recommendation: 'Always check the return value of low-level calls: (bool success, ) = addr.call{...}(); require(success);',
      });
    }

    // send() without check
    if (/\.send\s*\(/.test(line) && !/require\s*\(.*\.send/.test(line) && !/if\s*\(.*\.send/.test(line)) {
      findings.push({
        type: 'unchecked-call',
        severity: SEVERITY.MEDIUM,
        title: 'Unchecked send()',
        description: 'send() can fail silently if return value is not checked.',
        line: lineNum,
        code: line.trim(),
        recommendation: 'Use transfer() or check send() return value: require(addr.send(amount), "Send failed");',
      });
    }
  }

  return findings;
}

/**
 * Detect selfdestruct usage
 */
function detectSelfdestruct(source) {
  const findings = [];
  const lines = source.split('\n');

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const lineNum = i + 1;

    if (/selfdestruct\s*\(/.test(line) || /suicide\s*\(/.test(line)) {
      findings.push({
        type: 'selfdestruct',
        severity: SEVERITY.HIGH,
        title: 'Selfdestruct Detected',
        description: 'Contract can be permanently destroyed. This is deprecated in newer Solidity versions.',
        line: lineNum,
        code: line.trim(),
        recommendation: 'Avoid selfdestruct. If necessary, ensure only authorized addresses can call it with proper access controls.',
      });
    }
  }

  return findings;
}

/**
 * Detect dangerous delegatecall usage
 */
function detectDelegatecall(source) {
  const findings = [];
  const lines = source.split('\n');

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const lineNum = i + 1;

    if (/\.delegatecall\s*\(/.test(line)) {
      // Check if target is user-controlled
      const isUserInput = /\(\s*\w+\s*\)/.test(line) || /abi\.encode/.test(line);
      
      findings.push({
        type: 'delegatecall',
        severity: isUserInput ? SEVERITY.CRITICAL : SEVERITY.HIGH,
        title: 'Delegatecall Usage',
        description: 'delegatecall executes code in the context of the calling contract, which can modify storage.',
        line: lineNum,
        code: line.trim(),
        recommendation: 'Ensure delegatecall target is trusted and immutable. Never delegatecall to user-supplied addresses.',
      });
    }
  }

  return findings;
}

/**
 * Detect tx.origin authentication
 */
function detectTxOrigin(source) {
  const findings = [];
  const lines = source.split('\n');

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const lineNum = i + 1;

    if (/tx\.origin/.test(line)) {
      // Check if used for auth
      if (/require\s*\(.*tx\.origin/.test(line) || /==\s*tx\.origin/.test(line) || /tx\.origin\s*==/.test(line)) {
        findings.push({
          type: 'tx-origin',
          severity: SEVERITY.HIGH,
          title: 'tx.origin Authentication',
          description: 'Using tx.origin for authentication is vulnerable to phishing attacks.',
          line: lineNum,
          code: line.trim(),
          recommendation: 'Use msg.sender instead of tx.origin for authentication.',
        });
      } else {
        findings.push({
          type: 'tx-origin',
          severity: SEVERITY.LOW,
          title: 'tx.origin Usage',
          description: 'tx.origin used (not for authentication).',
          line: lineNum,
          code: line.trim(),
          recommendation: 'Consider if msg.sender would be more appropriate.',
        });
      }
    }
  }

  return findings;
}

/**
 * Detect access control issues
 */
function detectAccessControl(source) {
  const findings = [];
  const lines = source.split('\n');

  // Check for unprotected sensitive functions
  const sensitivePatterns = [
    { pattern: /function\s+(\w*withdraw\w*)/i, name: 'withdraw' },
    { pattern: /function\s+(\w*transfer\w*)/i, name: 'transfer' },
    { pattern: /function\s+(\w*mint\w*)/i, name: 'mint' },
    { pattern: /function\s+(\w*burn\w*)/i, name: 'burn' },
    { pattern: /function\s+(\w*pause\w*)/i, name: 'pause' },
    { pattern: /function\s+(\w*upgrade\w*)/i, name: 'upgrade' },
    { pattern: /function\s+(\w*setOwner\w*)/i, name: 'setOwner' },
    { pattern: /function\s+(\w*admin\w*)/i, name: 'admin' },
  ];

  let inFunction = false;
  let functionStart = 0;
  let functionName = '';
  let hasModifier = false;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const lineNum = i + 1;

    for (const { pattern, name } of sensitivePatterns) {
      const match = line.match(pattern);
      if (match) {
        functionName = match[1];
        functionStart = lineNum;
        inFunction = true;
        // Check for access control modifiers on same or next lines
        const funcBlock = lines.slice(i, i + 3).join(' ');
        hasModifier = /onlyOwner|onlyAdmin|onlyRole|require\s*\(\s*msg\.sender\s*==|require\s*\(\s*hasRole/i.test(funcBlock);
        
        if (!hasModifier && /public|external/.test(funcBlock)) {
          findings.push({
            type: 'access-control',
            severity: SEVERITY.HIGH,
            title: 'Potentially Unprotected Function',
            description: `Sensitive function '${functionName}' appears to lack access control.`,
            line: lineNum,
            code: line.trim(),
            recommendation: `Add access control modifier (onlyOwner, onlyRole, etc.) to ${name} function.`,
          });
        }
      }
    }
  }

  // Check for missing Ownable or AccessControl
  if (!/(Ownable|AccessControl|Owned)/i.test(source)) {
    const hasSensitiveFunctions = sensitivePatterns.some(p => p.pattern.test(source));
    if (hasSensitiveFunctions) {
      findings.push({
        type: 'access-control',
        severity: SEVERITY.MEDIUM,
        title: 'No Access Control Pattern',
        description: 'Contract has sensitive functions but does not inherit from Ownable or AccessControl.',
        recommendation: 'Consider using OpenZeppelin Ownable or AccessControl for standardized access control.',
      });
    }
  }

  return findings;
}

/**
 * Detect floating pragma
 */
function detectFloatingPragma(source) {
  const findings = [];
  
  const pragmaMatch = source.match(/pragma\s+solidity\s+([^;]+)/);
  if (pragmaMatch) {
    const version = pragmaMatch[1].trim();
    if (version.startsWith('^') || version.startsWith('>=') || version.startsWith('>')) {
      findings.push({
        type: 'floating-pragma',
        severity: SEVERITY.LOW,
        title: 'Floating Pragma',
        description: `Pragma is not locked: ${version}. Contract could compile with different versions.`,
        recommendation: 'Lock pragma to a specific version (e.g., pragma solidity 0.8.20;).',
      });
    }
  }

  return findings;
}

/**
 * Detect timestamp dependence
 */
function detectTimestamp(source) {
  const findings = [];
  const lines = source.split('\n');

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const lineNum = i + 1;

    if (/block\.timestamp/.test(line) || /now\s*[^a-zA-Z]/.test(line)) {
      // Check if used for randomness or critical logic
      if (/random|seed|hash\s*\(.*block\.timestamp/i.test(line)) {
        findings.push({
          type: 'timestamp',
          severity: SEVERITY.HIGH,
          title: 'Timestamp Used for Randomness',
          description: 'Block timestamp is miner-manipulable and should not be used for randomness.',
          line: lineNum,
          code: line.trim(),
          recommendation: 'Use Chainlink VRF or commit-reveal scheme for randomness.',
        });
      } else if (/<|>|==|!=/.test(line)) {
        findings.push({
          type: 'timestamp',
          severity: SEVERITY.LOW,
          title: 'Timestamp Dependence',
          description: 'Block timestamp can be manipulated by miners within ~15 second range.',
          line: lineNum,
          code: line.trim(),
          recommendation: 'Be aware of potential manipulation. Use block.number for longer timeframes.',
        });
      }
    }
  }

  return findings;
}

/**
 * Run all detectors
 */
export function analyzeContract(source, contractName = 'Unknown') {
  const findings = [
    ...detectReentrancy(source),
    ...detectOverflow(source),
    ...detectUncheckedCalls(source),
    ...detectSelfdestruct(source),
    ...detectDelegatecall(source),
    ...detectTxOrigin(source),
    ...detectAccessControl(source),
    ...detectFloatingPragma(source),
    ...detectTimestamp(source),
  ];

  // Sort by severity
  findings.sort((a, b) => b.severity.score - a.severity.score);

  // Calculate overall score
  let totalDeductions = 0;
  for (const finding of findings) {
    totalDeductions += finding.severity.score;
  }
  const score = Math.max(0, 100 - totalDeductions);

  // Determine grade
  let grade = 'A';
  if (score < 90) grade = 'B';
  if (score < 75) grade = 'C';
  if (score < 60) grade = 'D';
  if (score < 40) grade = 'F';

  // Count by severity
  const summary = {
    critical: findings.filter(f => f.severity.level === 'Critical').length,
    high: findings.filter(f => f.severity.level === 'High').length,
    medium: findings.filter(f => f.severity.level === 'Medium').length,
    low: findings.filter(f => f.severity.level === 'Low').length,
    info: findings.filter(f => f.severity.level === 'Info').length,
  };

  return {
    contractName,
    score,
    grade,
    summary,
    findings: findings.map(f => ({
      type: f.type,
      severity: f.severity.level,
      title: f.title,
      description: f.description,
      line: f.line,
      code: f.code,
      recommendation: f.recommendation,
    })),
    analyzedAt: new Date().toISOString(),
    analyzer: 'Metatron Security Auditor v1.0',
    agentId: 23984,
  };
}

/**
 * Full audit: fetch source + analyze
 */
export async function auditContract(address, chain = 'ethereum', apiKey = null) {
  const startTime = Date.now();
  
  try {
    // Fetch source code
    const contractData = await fetchContractSource(address, chain, apiKey);
    
    // Handle multi-file contracts (JSON format from Etherscan)
    let source = contractData.source;
    if (source.startsWith('{')) {
      try {
        // Multi-file format: {{...}}
        const parsed = JSON.parse(source.startsWith('{{') ? source.slice(1, -1) : source);
        source = Object.values(parsed.sources || parsed)
          .map(s => s.content || s)
          .join('\n\n');
      } catch {
        // Single file in JSON format
      }
    }

    // Run analysis
    const analysis = analyzeContract(source, contractData.name);
    
    return {
      success: true,
      address: address.toLowerCase(),
      chain,
      contractName: contractData.name,
      compiler: contractData.compiler,
      optimization: contractData.optimization,
      isProxy: !!contractData.implementation,
      implementation: contractData.implementation || null,
      ...analysis,
      sourceLines: source.split('\n').length,
      auditDuration: Date.now() - startTime,
    };
  } catch (error) {
    return {
      success: false,
      address: address.toLowerCase(),
      chain,
      error: error.message,
      auditDuration: Date.now() - startTime,
    };
  }
}
