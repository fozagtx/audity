/**
 * ═══════════════════════════════════════════════════════════════════════════
 * Audity — Smart Contract Security Platform
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * A production-grade backend that implements:
 *   - x402 payment-gated endpoints (STT — Somnia Testnet)
 *   - 3 LLM-powered security agents (scanner, validator, exploit sim)
 *   - Real-time SSE for live dashboard updates
 *   - Protocol transparency (raw 402 headers)
 *   - LLM-powered autonomous audit orchestration (Groq llama-3.3-70b)
 *
 * Endpoints (Paid):
 *   POST /api/scan-contract      — Scanner Agent       (0.010 STT)
 *   POST /api/validate-finding   — Validator Agent     (0.005 STT)
 *   POST /api/simulate-exploit   — Exploit Sim Agent   (0.020 STT)
 *
 * Endpoints (Free):
 *   GET  /health                — Server health
 *   GET  /api/tools             — Tool discovery for agents
 *   GET  /api/registry          — Agent registry
 *   GET  /api/payments          — Payment log
 *   GET  /api/findings          — Finding log (last 50)
 *   GET  /api/stats             — Platform statistics
 *   GET  /api/agent/events      — SSE stream
 *   POST /api/agent/query       — Manager agent orchestration
 */

import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import dotenv from 'dotenv';
import Groq from 'groq-sdk';
import { ethers } from 'ethers';
import {
  createPublicClient,
  createWalletClient,
  http,
  defineChain,
  keccak256,
  toBytes,
  decodeEventLog,
  parseGwei,
  type Hex,
} from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { SDK, type SubscriptionCallback } from '@somnia-chain/reactivity';
import { SOMNIA } from './network.js';

// ═══════════════════════════════════════════════════════════════════════════
// Configuration
// ═══════════════════════════════════════════════════════════════════════════

dotenv.config();

const PORT    = parseInt(process.env.PORT || '4002', 10);
const HOST    = '0.0.0.0';
const NETWORK = 'somnia-testnet';
const CHAIN_ID    = String(SOMNIA.chainId);
const RPC_HTTP    = SOMNIA.rpcHttp;
const RPC_WSS     = SOMNIA.rpcWss;
const RPC_URL     = RPC_HTTP;
const EXPLORER_BASE = SOMNIA.explorer;
const SERVER_ADDRESS = '0xDe5df44009FD2E13bBAcfED2b8e3833B5Dc4Bf21';
const AGENT_PRIVATE_KEY = process.env.AGENT_PRIVATE_KEY || '';
const SECURITY_REGISTRY_ADDRESS  = '0x542A1352b7a62f1D2EF320DC1353f6ECbB1Be4dB' as Hex;
const WATCHLIST_HANDLER_ADDRESS   = '0x32A69a587488EB9664A7F7E6f6a6a2B33657446A' as Hex;

// ═══════════════════════════════════════════════════════════════════════════
// EVM Wallet — real on-chain STT payments
// ═══════════════════════════════════════════════════════════════════════════

const evmProvider = new ethers.JsonRpcProvider(RPC_URL);
const agentWallet = AGENT_PRIVATE_KEY
  ? new ethers.Wallet(AGENT_PRIVATE_KEY.startsWith('0x') ? AGENT_PRIVATE_KEY : `0x${AGENT_PRIVATE_KEY}`, evmProvider)
  : null;

if (agentWallet) {
  console.log(`[WALLET] Agent wallet: ${agentWallet.address}`);
} else {
  console.warn('[WALLET] No AGENT_PRIVATE_KEY set — STT payments will fail');
}

// ═══════════════════════════════════════════════════════════════════════════
// Somnia Viem Chain + Reactivity SDK
// ═══════════════════════════════════════════════════════════════════════════

const somniaTestnet = defineChain({
  id:             SOMNIA.chainId,
  name:           SOMNIA.chainName,
  nativeCurrency: { name: SOMNIA.symbol, symbol: SOMNIA.symbol, decimals: 18 },
  rpcUrls: {
    default: {
      http:      [SOMNIA.rpcHttp],
      webSocket: [SOMNIA.rpcWss],
    },
  },
  blockExplorers: {
    default: { name: 'Somnia Explorer', url: SOMNIA.explorer },
  },
});

const viemPublicClient = createPublicClient({
  chain: somniaTestnet,
  transport: http(RPC_HTTP),
});

// Viem wallet client — only available if private key is configured
const viemAccount = AGENT_PRIVATE_KEY
  ? privateKeyToAccount(
      (AGENT_PRIVATE_KEY.startsWith('0x') ? AGENT_PRIVATE_KEY : `0x${AGENT_PRIVATE_KEY}`) as Hex
    )
  : null;

const viemWalletClient = viemAccount
  ? createWalletClient({ account: viemAccount, chain: somniaTestnet, transport: http(RPC_HTTP) })
  : null;

// Somnia Reactivity SDK
const reactivitySDK = viemWalletClient
  ? new SDK({ public: viemPublicClient, wallet: viemWalletClient })
  : new SDK({ public: viemPublicClient });

// ─── SecurityRegistry ABI (minimal — functions + events we use) ────────────

const SECURITY_REGISTRY_ABI = [
  {
    name: 'submitFinding',
    type: 'function',
    stateMutability: 'nonpayable',
    inputs: [
      { name: 'contractAddress', type: 'address' },
      { name: 'vulnType',        type: 'string'  },
      { name: 'severity',        type: 'string'  },
      { name: 'description',     type: 'string'  },
      { name: 'scannerAgent',    type: 'string'  },
      { name: 'rewardSTT',       type: 'uint256' },
    ],
    outputs: [{ name: 'findingId', type: 'bytes32' }],
  },
  {
    name: 'confirmFinding',
    type: 'function',
    stateMutability: 'nonpayable',
    inputs: [{ name: 'findingId', type: 'bytes32' }],
    outputs: [],
  },
  {
    name: 'rejectFinding',
    type: 'function',
    stateMutability: 'nonpayable',
    inputs: [{ name: 'findingId', type: 'bytes32' }],
    outputs: [],
  },
  {
    name: 'scannerReputation',
    type: 'function',
    stateMutability: 'view',
    inputs:  [{ name: 'scanner', type: 'address' }],
    outputs: [{ name: '', type: 'uint256' }],
  },
  {
    name: 'agentHireCount',
    type: 'function',
    stateMutability: 'view',
    inputs:  [{ name: 'agentId', type: 'string' }],
    outputs: [{ name: '', type: 'uint256' }],
  },
  {
    name: 'recordHire',
    type: 'function',
    stateMutability: 'nonpayable',
    inputs:  [{ name: 'agentId', type: 'string' }],
    outputs: [],
  },
  {
    name: 'AgentHired',
    type: 'event',
    inputs: [
      { name: 'agentId',    type: 'string',  indexed: true  },
      { name: 'payer',      type: 'address', indexed: true  },
      { name: 'totalHires', type: 'uint256', indexed: false },
    ],
  },
  {
    name: 'FindingSubmitted',
    type: 'event',
    inputs: [
      { name: 'findingId',       type: 'bytes32', indexed: true  },
      { name: 'contractAddress', type: 'address', indexed: true  },
      { name: 'vulnType',        type: 'string',  indexed: false },
      { name: 'severity',        type: 'string',  indexed: false },
      { name: 'description',     type: 'string',  indexed: false },
      { name: 'scannerAgent',    type: 'string',  indexed: false },
    ],
  },
  {
    name: 'FindingConfirmed',
    type: 'event',
    inputs: [
      { name: 'findingId', type: 'bytes32', indexed: true },
      { name: 'validator',  type: 'address', indexed: true },
      { name: 'scanner',    type: 'address', indexed: true },
    ],
  },
  {
    name: 'FindingRejected',
    type: 'event',
    inputs: [
      { name: 'findingId', type: 'bytes32', indexed: true },
      { name: 'validator',  type: 'address', indexed: true },
      { name: 'scanner',    type: 'address', indexed: true },
    ],
  },
  {
    name: 'totalFindings',
    type: 'function',
    stateMutability: 'view',
    inputs: [],
    outputs: [{ name: '', type: 'uint256' }],
  },
  {
    name: 'getFindingIds',
    type: 'function',
    stateMutability: 'view',
    inputs: [],
    outputs: [{ name: '', type: 'bytes32[]' }],
  },
  {
    name: 'getFinding',
    type: 'function',
    stateMutability: 'view',
    inputs: [{ name: 'findingId', type: 'bytes32' }],
    outputs: [{
      name: '',
      type: 'tuple',
      components: [
        { name: 'contractAddress', type: 'address' },
        { name: 'vulnType',        type: 'string'  },
        { name: 'severity',        type: 'string'  },
        { name: 'description',     type: 'string'  },
        { name: 'scannerAgent',    type: 'string'  },
        { name: 'scanner',         type: 'address' },
        { name: 'validator',       type: 'address' },
        { name: 'status',          type: 'uint8'   },
        { name: 'rewardSTT',       type: 'uint256' },
        { name: 'submittedAt',     type: 'uint256' },
        { name: 'reviewedAt',      type: 'uint256' },
      ],
    }],
  },
] as const;

// ─── WatchlistHandler ABI ─────────────────────────────────────────────────

const WATCHLIST_HANDLER_ABI = [
  {
    name: 'addContract',
    type: 'function',
    stateMutability: 'nonpayable',
    inputs:  [{ name: 'contractAddress', type: 'address' }],
    outputs: [],
  },
  {
    name: 'removeContract',
    type: 'function',
    stateMutability: 'nonpayable',
    inputs:  [{ name: 'contractAddress', type: 'address' }],
    outputs: [],
  },
  {
    name: 'getWatchedContracts',
    type: 'function',
    stateMutability: 'view',
    inputs:  [],
    outputs: [{ name: '', type: 'address[]' }],
  },
  {
    name: 'RescanRequested',
    type: 'event',
    inputs: [
      { name: 'contractAddress', type: 'address', indexed: true  },
      { name: 'blockNumber',      type: 'uint256', indexed: false },
    ],
  },
  {
    name: 'ContractAdded',
    type: 'event',
    inputs: [
      { name: 'contractAddress', type: 'address', indexed: true },
      { name: 'addedBy',          type: 'address', indexed: true },
    ],
  },
  {
    name: 'ContractRemoved',
    type: 'event',
    inputs: [
      { name: 'contractAddress', type: 'address', indexed: true },
    ],
  },
] as const;

// ─── Watchlist State ──────────────────────────────────────────────────────

interface WatchlistEntry {
  contractAddress: string;
  contractSource?: string;
  label?: string;
  addedAt: number;
  lastScannedAt?: number;
  scanCount: number;
  subscriptionType: 'periodic' | 'scheduled';
  subscriptionTxHash?: string;
  nextScanAt?: number;
}

const watchlist: WatchlistEntry[] = [];

// ─── Cron Helpers — BlockTick + Schedule ─────────────────────────────────

/**
 * Register a contract for periodic re-scanning via Somnia BlockTick.
 * Every block (or targeted block) the WatchlistHandler fires → RescanRequested.
 */
async function createPeriodicRescan(entry: WatchlistEntry): Promise<string | null> {
  if (!WATCHLIST_HANDLER_ADDRESS || !viemWalletClient) {
    console.warn('[WATCHLIST] WatchlistHandler not configured — skipping BlockTick subscription');
    return null;
  }
  try {
    // Register the contract on-chain so the handler emits RescanRequested for it
    const addHash = await viemWalletClient.writeContract({
      address: WATCHLIST_HANDLER_ADDRESS,
      abi: WATCHLIST_HANDLER_ABI,
      functionName: 'addContract',
      args: [entry.contractAddress as Hex],
    });
    await viemPublicClient.waitForTransactionReceipt({ hash: addHash });
    console.log(`[WATCHLIST] addContract on-chain: ${addHash}`);

    // Create the BlockTick subscription — fires on every block
    const txHash = await reactivitySDK.createOnchainBlockTickSubscription({
      handlerContractAddress: WATCHLIST_HANDLER_ADDRESS,
      priorityFeePerGas: parseGwei('2'),
      maxFeePerGas:      parseGwei('10'),
      // gasLimit scales with watchlist size: 50_000 per watched contract + base 100_000
      gasLimit: BigInt(100_000 + 50_000),
      isGuaranteed: true,
      isCoalesced:  false,
    });

    console.log(`[WATCHLIST] BlockTick subscription created: ${txHash}`);
    return txHash as string;
  } catch (err: any) {
    console.error('[WATCHLIST] createPeriodicRescan failed:', err.message);
    return null;
  }
}

/**
 * Schedule a one-off re-scan at a specific timestamp (ms).
 * Fires WatchlistHandler once → RescanRequested → auto LLM scan.
 * The subscription is automatically deleted after triggering.
 */
async function scheduleOneOffRescan(
  entry: WatchlistEntry,
  rescanAtMs: number
): Promise<string | null> {
  if (!WATCHLIST_HANDLER_ADDRESS || !viemWalletClient) {
    console.warn('[WATCHLIST] WatchlistHandler not configured — skipping Schedule subscription');
    return null;
  }
  if (rescanAtMs < Date.now() + 12_000) {
    throw new Error('rescanAt must be at least 12 seconds in the future');
  }
  try {
    // Ensure the contract is registered on-chain in the handler
    const isWatched = watchlist.some(e => e.contractAddress === entry.contractAddress);
    if (!isWatched) {
      const addHash = await viemWalletClient.writeContract({
        address: WATCHLIST_HANDLER_ADDRESS,
        abi: WATCHLIST_HANDLER_ABI,
        functionName: 'addContract',
        args: [entry.contractAddress as Hex],
      });
      await viemPublicClient.waitForTransactionReceipt({ hash: addHash });
    }

    const txHash = await reactivitySDK.scheduleOnchainCronJob({
      timestampMs: rescanAtMs,
      handlerContractAddress: WATCHLIST_HANDLER_ADDRESS,
      priorityFeePerGas: parseGwei('2'),
      maxFeePerGas:      parseGwei('10'),
      gasLimit:          BigInt(100_000 + 50_000),
      isGuaranteed:      true,
      isCoalesced:       false,
    });

    console.log(`[WATCHLIST] Schedule subscription created: ${txHash} → fires at ${new Date(rescanAtMs).toISOString()}`);
    return txHash as string;
  } catch (err: any) {
    console.error('[WATCHLIST] scheduleOneOffRescan failed:', err.message);
    return null;
  }
}

/**
 * Subscribe to RescanRequested events from WatchlistHandler.
 * When fired, automatically runs the LLM scanner on the contract.
 */
async function initWatchlistSubscription(): Promise<void> {
  if (!WATCHLIST_HANDLER_ADDRESS) {
    console.warn('[WATCHLIST] WATCHLIST_HANDLER_ADDRESS not set — skipping RescanRequested subscription');
    return;
  }

  const RESCAN_REQUESTED_SIG = keccak256(toBytes('RescanRequested(address,uint256)'));

  try {
    await reactivitySDK.subscribe({
      ethCalls: [],
      eventContractSources: [WATCHLIST_HANDLER_ADDRESS],
      topicOverrides: [RESCAN_REQUESTED_SIG],
      onlyPushChanges: false,
      onData: async (data: SubscriptionCallback) => {
        const topics  = data.result.topics as Hex[];
        const rawData = data.result.data   as Hex;
        if (!topics || topics.length === 0) return;

        try {
          const decoded = decodeEventLog({
            abi: WATCHLIST_HANDLER_ABI,
            data: rawData,
            topics: topics as [Hex, ...Hex[]],
          });

          if (decoded.eventName !== 'RescanRequested') return;

          const { contractAddress, blockNumber } = decoded.args as any;
          console.log(`[WATCHLIST] RescanRequested for ${contractAddress} at block ${blockNumber}`);

          // Find the watchlist entry to get the contract source
          const entry = watchlist.find(
            e => e.contractAddress.toLowerCase() === (contractAddress as string).toLowerCase()
          );
          if (!entry) return;

          // Broadcast auto-rescan notice to SSE clients
          broadcastSSE('watchlist_rescan_started', {
            contractAddress,
            blockNumber: blockNumber.toString(),
            label: entry.label,
            source: 'somnia-reactivity-blocktick',
          });

          // Run LLM scanner on the contract
          const systemPrompt = `You are an expert smart contract security auditor. Analyze the provided Solidity contract for vulnerabilities and return a structured findings list. Focus on reentrancy, overflow, access-control, logic errors, and flash-loan vectors.`;
          const userPrompt = entry.contractSource
            ? `Re-scan this Solidity contract for vulnerabilities (block ${blockNumber}):\n\n\`\`\`solidity\n${entry.contractSource}\n\`\`\``
            : `Re-scan contract at address ${contractAddress} for vulnerabilities (block ${blockNumber}).`;

          let rawFindings: any[] = [];
          try {
            const completion = await groq.chat.completions.create({
              messages: [
                { role: 'system', content: systemPrompt },
                { role: 'user',   content: userPrompt   },
              ],
              model: 'llama-3.3-70b-versatile',
              temperature: 0.2,
              max_tokens: 1000,
              response_format: { type: 'json_object' },
            });
            rawFindings = JSON.parse(completion.choices[0]?.message?.content || '{"findings":[]}').findings || [];
          } catch (err) {
            console.error('[WATCHLIST] LLM error:', err);
          }

          // Submit new findings to SecurityRegistry + broadcast
          for (const f of rawFindings) {
            const rewardSTT = f.severity === 'critical' ? 0.05 : f.severity === 'high' ? 0.03 : 0.01;
            const onChainId = await submitFindingOnChain(
              contractAddress,
              f.vulnType  || 'logic',
              f.severity  || 'medium',
              f.description || '',
              'watchlist-auto-scanner',
              rewardSTT
            );
            const logEntry: FindingLog = {
              id:              `finding_${(++findingIdCounter).toString(36)}`,
              timestamp:       Date.now(),
              contractAddress: contractAddress,
              vulnType:        (f.vulnType  || 'logic')  as FindingLog['vulnType'],
              severity:        (f.severity  || 'medium') as FindingLog['severity'],
              description:     f.description || '',
              scannerAgent:    'watchlist-auto-scanner',
              confirmed:       false,
              rewardSTT,
              txHash:          onChainId || undefined,
            };
            findingLogs.push(logEntry);
            broadcastSSE('finding', { ...logEntry, onChainId, autoRescan: true });
          }

          // Update entry metadata
          entry.lastScannedAt = Date.now();
          entry.scanCount++;

          broadcastSSE('watchlist_rescan_complete', {
            contractAddress,
            blockNumber:    blockNumber.toString(),
            newFindings:    rawFindings.length,
            label:          entry.label,
          });
        } catch (decodeErr) {
          console.warn('[WATCHLIST] Could not decode RescanRequested event');
        }
      },
      onError: (err: Error) => {
        console.error('[WATCHLIST] Subscription error:', err.message);
      },
    });

    console.log(`[WATCHLIST] Subscribed to RescanRequested events at ${WATCHLIST_HANDLER_ADDRESS}`);
  } catch (err: any) {
    console.error('[WATCHLIST] Failed to initialise watchlist subscription:', err.message);
  }
}

// ─── On-Chain Finding Submission ──────────────────────────────────────────

/**
 * Submit a finding to SecurityRegistry on-chain.
 * Returns the on-chain findingId (bytes32 hex) or null if contract not configured.
 */
async function submitFindingOnChain(
  contractAddress: string,
  vulnType: string,
  severity: string,
  description: string,
  scannerAgent: string,
  rewardSTT: number
): Promise<Hex | null> {
  if (!SECURITY_REGISTRY_ADDRESS || !viemWalletClient || !viemAccount) {
    console.warn('[REACTIVITY] SecurityRegistry not configured — skipping on-chain submission');
    return null;
  }
  try {
    const addr = (contractAddress === 'source-provided' || !contractAddress.startsWith('0x'))
      ? '0x0000000000000000000000000000000000000000' as Hex
      : contractAddress as Hex;

    const rewardWei = BigInt(Math.round(rewardSTT * 1e18));

    const hash = await viemWalletClient.writeContract({
      address: SECURITY_REGISTRY_ADDRESS,
      abi: SECURITY_REGISTRY_ABI,
      functionName: 'submitFinding',
      args: [addr, vulnType, severity, description, scannerAgent, rewardWei],
    });

    console.log(`[REACTIVITY] submitFinding tx: ${hash}`);
    const receipt = await viemPublicClient.waitForTransactionReceipt({ hash });

    // Parse the findingId from the FindingSubmitted event in the receipt
    for (const log of receipt.logs) {
      try {
        const decoded = decodeEventLog({
          abi: SECURITY_REGISTRY_ABI,
          data: log.data,
          topics: log.topics,
        });
        if (decoded.eventName === 'FindingSubmitted') {
          return (decoded.args as any).findingId as Hex;
        }
      } catch { /* not our event */ }
    }
    return null;
  } catch (err: any) {
    console.error('[REACTIVITY] submitFinding failed:', err.message);
    return null;
  }
}

/**
 * Confirm a finding on-chain (validator approves).
 */
async function confirmFindingOnChain(onChainId: Hex): Promise<void> {
  if (!SECURITY_REGISTRY_ADDRESS || !viemWalletClient) return;
  try {
    const hash = await viemWalletClient.writeContract({
      address: SECURITY_REGISTRY_ADDRESS,
      abi: SECURITY_REGISTRY_ABI,
      functionName: 'confirmFinding',
      args: [onChainId],
    });
    console.log(`[REACTIVITY] confirmFinding tx: ${hash}`);
  } catch (err: any) {
    console.error('[REACTIVITY] confirmFinding failed:', err.message);
  }
}

/**
 * Reject a finding on-chain (validator rejects).
 */
async function rejectFindingOnChain(onChainId: Hex): Promise<void> {
  if (!SECURITY_REGISTRY_ADDRESS || !viemWalletClient) return;
  try {
    const hash = await viemWalletClient.writeContract({
      address: SECURITY_REGISTRY_ADDRESS,
      abi: SECURITY_REGISTRY_ABI,
      functionName: 'rejectFinding',
      args: [onChainId],
    });
    console.log(`[REACTIVITY] rejectFinding tx: ${hash}`);
  } catch (err: any) {
    console.error('[REACTIVITY] rejectFinding failed:', err.message);
  }
}

// ─── On-Chain Reputation Sync ─────────────────────────────────────────────

/**
 * Read scannerReputation(address) from SecurityRegistry on Somnia and update
 * all agents that share that address. Broadcasts agent_reputation_update via SSE.
 */
async function syncReputationFromChain(scannerAddress: string): Promise<void> {
  if (!SECURITY_REGISTRY_ADDRESS || !viemPublicClient) return;
  try {
    const basisPoints = await viemPublicClient.readContract({
      address: SECURITY_REGISTRY_ADDRESS,
      abi: SECURITY_REGISTRY_ABI,
      functionName: 'scannerReputation',
      args: [scannerAddress as Hex],
    }) as bigint;

    const reputationPct = Number(basisPoints) / 100;

    agentRegistry.forEach(a => {
      if (a.address.toLowerCase() === scannerAddress.toLowerCase()) {
        a.reputation = reputationPct;
      }
    });

    broadcastSSE('agent_reputation_update', {
      scannerAddress,
      reputation: reputationPct,
      basisPoints: Number(basisPoints),
      source: 'somnia-chain',
    });

    console.log(`[CHAIN] Reputation for ${scannerAddress}: ${reputationPct}% (${basisPoints} bp)`);
  } catch (err: any) {
    console.error('[CHAIN] syncReputationFromChain failed:', err.message);
  }
}

/**
 * Call SecurityRegistry.recordHire(agentId) on Somnia — emits AgentHired.
 * Reactivity SDK picks it up and broadcasts agent_hired_update via SSE.
 */
async function recordHireOnChain(agentId: string): Promise<void> {
  if (!SECURITY_REGISTRY_ADDRESS || !viemWalletClient) return;
  try {
    const hash = await viemWalletClient.writeContract({
      address: SECURITY_REGISTRY_ADDRESS,
      abi: SECURITY_REGISTRY_ABI,
      functionName: 'recordHire',
      args: [agentId],
    });
    console.log(`[CHAIN] recordHire(${agentId}) tx: ${hash}`);
  } catch (err: any) {
    console.error('[CHAIN] recordHire failed:', err.message);
  }
}

/**
 * Read agentHireCount(agentId) from SecurityRegistry and update local registry.
 */
async function syncHireCountFromChain(agentId: string): Promise<void> {
  if (!SECURITY_REGISTRY_ADDRESS || !viemPublicClient) return;
  try {
    const count = await viemPublicClient.readContract({
      address: SECURITY_REGISTRY_ADDRESS,
      abi: SECURITY_REGISTRY_ABI,
      functionName: 'agentHireCount',
      args: [agentId],
    }) as bigint;

    const agent = agentRegistry.find(a => a.id === agentId);
    if (agent) {
      agent.jobsCompleted = Number(count);
      broadcastSSE('agent_hired_update', {
        agentId,
        jobsCompleted: Number(count),
        source: 'somnia-chain',
      });
      console.log(`[CHAIN] Hire count for ${agentId}: ${count}`);
    }
  } catch (err: any) {
    console.error('[CHAIN] syncHireCountFromChain failed:', err.message);
  }
}

/**
 * On startup: read all findings from SecurityRegistry on-chain and
 * re-hydrate findingLogs so stats/feeds survive server restarts.
 * status: 0=Pending, 1=Confirmed, 2=Rejected
 */
async function syncFindingsFromChain(): Promise<void> {
  if (!SECURITY_REGISTRY_ADDRESS || !viemPublicClient) return;
  try {
    const ids = await viemPublicClient.readContract({
      address: SECURITY_REGISTRY_ADDRESS,
      abi: SECURITY_REGISTRY_ABI,
      functionName: 'getFindingIds',
      args: [],
    }) as `0x${string}`[];

    if (!ids || ids.length === 0) {
      console.log('[CHAIN] No findings on-chain yet');
      return;
    }

    const onChainFindings: FindingLog[] = [];
    for (const id of ids) {
      try {
        const f = await viemPublicClient.readContract({
          address: SECURITY_REGISTRY_ADDRESS,
          abi: SECURITY_REGISTRY_ABI,
          functionName: 'getFinding',
          args: [id],
        }) as any;

        const statusMap: Record<number, boolean | null> = { 0: null, 1: true, 2: false };
        const confirmed = statusMap[Number(f.status)];

        onChainFindings.push({
          id: id,
          timestamp: Number(f.submittedAt) * 1000,
          contractAddress: f.contractAddress === '0x0000000000000000000000000000000000000000'
            ? 'source-provided'
            : f.contractAddress,
          vulnType: f.vulnType,
          severity: f.severity as FindingLog['severity'],
          description: f.description,
          scannerAgent: f.scannerAgent,
          confirmed: confirmed === true,
          rewardSTT: Number(f.rewardSTT) / 1e18,
          txHash: id,
        });
      } catch (e: any) {
        console.warn(`[CHAIN] Could not read finding ${id}: ${e.message}`);
      }
    }

    // Merge: keep any in-session findings that aren't on-chain yet
    const existingIds = new Set(findingLogs.map(f => f.id));
    for (const f of onChainFindings) {
      if (!existingIds.has(f.id)) findingLogs.push(f);
    }

    console.log(`[CHAIN] Synced ${onChainFindings.length} findings from SecurityRegistry`);
  } catch (err: any) {
    console.error('[CHAIN] syncFindingsFromChain failed:', err.message);
  }
}

// ─── Somnia Reactivity WebSocket Subscription ─────────────────────────────

/**
 * Subscribe to FindingSubmitted / FindingConfirmed / FindingRejected events
 * from the SecurityRegistry contract via Somnia Reactivity.
 * When events arrive they are forwarded to SSE clients in real-time.
 */
async function initReactivitySubscription(): Promise<void> {
  if (!SECURITY_REGISTRY_ADDRESS) {
    console.warn('[REACTIVITY] SECURITY_REGISTRY_ADDRESS not set — skipping WebSocket subscription');
    return;
  }

  const FINDING_SUBMITTED_SIG = keccak256(
    toBytes('FindingSubmitted(bytes32,address,string,string,string,string)')
  );
  const FINDING_CONFIRMED_SIG = keccak256(
    toBytes('FindingConfirmed(bytes32,address,address)')
  );
  const FINDING_REJECTED_SIG = keccak256(
    toBytes('FindingRejected(bytes32,address,address)')
  );
  const AGENT_HIRED_SIG = keccak256(
    toBytes('AgentHired(string,address,uint256)')
  );

  try {
    await reactivitySDK.subscribe({
      ethCalls: [],
      eventContractSources: [SECURITY_REGISTRY_ADDRESS],
      topicOverrides: [FINDING_SUBMITTED_SIG, FINDING_CONFIRMED_SIG, FINDING_REJECTED_SIG, AGENT_HIRED_SIG],
      onlyPushChanges: false,
      onData: (data: SubscriptionCallback) => {
        const topics = data.result.topics as Hex[];
        const rawData = data.result.data as Hex;
        if (!topics || topics.length === 0) return;

        const sig = topics[0];

        try {
          const decoded = decodeEventLog({
            abi: SECURITY_REGISTRY_ABI,
            data: rawData,
            topics: topics as [Hex, ...Hex[]],
          });

          if (decoded.eventName === 'FindingSubmitted') {
            const args = decoded.args as any;
            console.log(`[REACTIVITY] FindingSubmitted on-chain: ${args.findingId}`);
            broadcastSSE('finding_onchain', {
              findingId:       args.findingId,
              contractAddress: args.contractAddress,
              vulnType:        args.vulnType,
              severity:        args.severity,
              description:     args.description,
              scannerAgent:    args.scannerAgent,
              source:          'somnia-reactivity',
            });
          } else if (decoded.eventName === 'FindingConfirmed') {
            const args = decoded.args as any;
            console.log(`[REACTIVITY] FindingConfirmed on-chain: ${args.findingId}`);
            broadcastSSE('finding_confirmed_onchain', {
              findingId: args.findingId,
              validator:  args.validator,
              scanner:    args.scanner,
              source:     'somnia-reactivity',
            });
            // Pull updated reputation from chain — this is the source of truth
            syncReputationFromChain(args.scanner);
          } else if (decoded.eventName === 'FindingRejected') {
            const args = decoded.args as any;
            console.log(`[REACTIVITY] FindingRejected on-chain: ${args.findingId}`);
            broadcastSSE('finding_rejected_onchain', {
              findingId: args.findingId,
              validator:  args.validator,
              scanner:    args.scanner,
              source:     'somnia-reactivity',
            });
            // Pull updated reputation from chain — this is the source of truth
            syncReputationFromChain(args.scanner);
          } else if (decoded.eventName === 'AgentHired') {
            // NOTE: `agentId` is a `string indexed` in Solidity → stored as keccak256 hash in topics.
            // The original string is unrecoverable from the event. Re-sync all hire counts from chain.
            console.log(`[REACTIVITY] AgentHired on-chain — re-syncing all hire counts`);
            for (const a of agentRegistry) {
              try {
                const count = await viemPublicClient.readContract({
                  address: SECURITY_REGISTRY_ADDRESS,
                  abi: SECURITY_REGISTRY_ABI,
                  functionName: 'agentHireCount',
                  args: [a.id],
                }) as bigint;
                a.jobsCompleted = Number(count);
                broadcastSSE('agent_hired_update', {
                  agentId:      a.id,
                  jobsCompleted: Number(count),
                  source:       'somnia-reactivity',
                });
              } catch { /* skip failed agent */ }
            }
          }
        } catch (decodeErr) {
          console.warn('[REACTIVITY] Could not decode event log:', sig);
        }
      },
      onError: (err: Error) => {
        console.error('[REACTIVITY] Subscription error:', err.message);
      },
    });

    console.log(`[REACTIVITY] Subscribed to SecurityRegistry events at ${SECURITY_REGISTRY_ADDRESS}`);
  } catch (err: any) {
    console.error('[REACTIVITY] Failed to initialise subscription:', err.message);
  }
}

async function sendSTTPayment(toAddress: string, amountSTT: number): Promise<string> {
  if (!agentWallet) throw new Error('Agent wallet not configured');
  const amountWei = ethers.parseEther(amountSTT.toFixed(18));
  const tx = await agentWallet.sendTransaction({
    to: toAddress,
    value: amountWei,
  });
  console.log(`[PAYMENT] Sent ${amountSTT} STT → ${toAddress} | txHash: ${tx.hash}`);
  await tx.wait(1);
  return tx.hash;
}

// ═══════════════════════════════════════════════════════════════════════════
// Express App
// ═══════════════════════════════════════════════════════════════════════════

const app = express();

// AI Client
const groq = new Groq({ apiKey: process.env.GROQ_API_KEY || '' });

app.use(helmet({ crossOriginResourcePolicy: { policy: 'cross-origin' } }));
app.use(cors({
  origin: process.env.CORS_ORIGIN || '*',
  exposedHeaders: ['X-Payment-Response', 'Payment-Response', 'X-402-Version', 'WWW-Authenticate'],
}));
app.use(morgan('short'));
app.use(express.json({ limit: '2mb' }));

// ═══════════════════════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════════════════════

interface PaymentLog {
  id: string;
  timestamp: string;
  endpoint: string;
  payer: string;
  worker: string;
  transaction: string;
  token: string;
  amount: string;
  explorerUrl: string;
  isA2A: boolean;
  parentJobId?: string;
  depth: number;
  rawHeaders?: Record<string, string>;
  metadata?: any;
}

interface FindingLog {
  id: string;
  timestamp: number;
  contractAddress: string;
  vulnType: 'reentrancy' | 'overflow' | 'access-control' | 'logic' | 'flash-loan';
  severity: 'critical' | 'high' | 'medium' | 'low';
  description: string;
  scannerAgent: string;
  validatorAgent?: string;
  confirmed: boolean;
  rewardSTT: number;
  txHash?: string;
}

interface AgentRegistryEntry {
  id: string;
  name: string;
  description: string;
  address: string;
  endpoint: string;
  category: string;
  priceSTT: number;
  reputation: number;
  jobsCompleted: number;
  jobsFailed: number;
  totalEarned: number;
  isActive: boolean;
  efficiency: number;
}

interface PriceConfig {
  sttAmount: number;
  description: string;
  category: string;
}

// ═══════════════════════════════════════════════════════════════════════════
// State — Payment Logs, Finding Logs & Agent Registry
// ═══════════════════════════════════════════════════════════════════════════

const paymentLogs: PaymentLog[] = [];
const findingLogs: FindingLog[] = [];
let paymentIdCounter = 0;
let findingIdCounter = 0;

// All agents submit on-chain via the single platform wallet — reputation is live from SecurityRegistry
const PLATFORM_ADDRESS = '0xDe5df44009FD2E13bBAcfED2b8e3833B5Dc4Bf21';

const agentRegistry: AgentRegistryEntry[] = [
  {
    id: 'scanner-agent',
    name: 'Scanner Agent',
    description: 'Detects reentrancy, overflow, access-control, flash-loan, and logic vulnerabilities in Solidity contracts.',
    address: PLATFORM_ADDRESS,
    endpoint: '/api/scan-contract',
    category: 'security-scanner',
    priceSTT: 0.010,
    reputation: 0,
    jobsCompleted: 0,
    jobsFailed: 0,
    totalEarned: 0,
    isActive: true,
    efficiency: 0,
  },
  {
    id: 'validator-agent',
    name: 'Validator Agent',
    description: 'Adversarially confirms or rejects scanner findings with independent reasoning and confidence scoring.',
    address: PLATFORM_ADDRESS,
    endpoint: '/api/validate-finding',
    category: 'security-validator',
    priceSTT: 0.005,
    reputation: 0,
    jobsCompleted: 0,
    jobsFailed: 0,
    totalEarned: 0,
    isActive: true,
    efficiency: 0,
  },
  {
    id: 'exploit-sim-agent',
    name: 'Exploit Sim Agent',
    description: 'Generates Foundry/Hardhat PoC exploit test code for confirmed vulnerabilities. Estimates potential loss.',
    address: PLATFORM_ADDRESS,
    endpoint: '/api/simulate-exploit',
    category: 'security-exploit',
    priceSTT: 0.020,
    reputation: 0,
    jobsCompleted: 0,
    jobsFailed: 0,
    totalEarned: 0,
    isActive: true,
    efficiency: 0,
  },
];

// Calculate efficiency scores
agentRegistry.forEach(a => {
  a.efficiency = a.priceSTT > 0
    ? Math.round((a.reputation / 100) * (1 / (a.priceSTT + 0.001)) * 100) / 100
    : 0;
});

function findAgentById(idOrName: string): AgentRegistryEntry | undefined {
  if (!idOrName) return undefined;
  const search = idOrName.toLowerCase();
  return agentRegistry.find(a =>
    a.id.toLowerCase() === search ||
    a.name.toLowerCase() === search ||
    a.name.toLowerCase().includes(search) ||
    (search.includes('-') && a.id.startsWith(search.split('-')[0]))
  );
}

function findBestAgentByCategory(category: string): AgentRegistryEntry | undefined {
  return agentRegistry
    .filter(a => a.isActive && a.category === category)
    .sort((a, b) => b.efficiency - a.efficiency)[0];
}

// ═══════════════════════════════════════════════════════════════════════════
// STT Payment Middleware (x402 pattern — Somnia Testnet)
// ═══════════════════════════════════════════════════════════════════════════

function getExplorerURL(txHash: string): string {
  if (!txHash) return `${EXPLORER_BASE}/tx/0x${'0'.repeat(64)}`;
  return `${EXPLORER_BASE}/tx/${txHash}`;
}

function createSTTPaymentChallenge(config: PriceConfig): object {
  return {
    x402Version: '1.0',
    network: NETWORK,
    chainId: parseInt(CHAIN_ID),
    payTo: SERVER_ADDRESS,
    amount: config.sttAmount.toString(),
    token: 'STT',
    description: config.description,
    rpcUrl: RPC_URL,
    explorer: EXPLORER_BASE,
  };
}

function createPaidRoute(config: PriceConfig) {
  return async (req: Request, res: Response, next: NextFunction) => {
    const paymentHeader = req.headers['x-payment-response'] || req.headers['payment-response'];

    if (!paymentHeader) {
      res.status(402).json({
        error: 'Payment Required',
        x402: createSTTPaymentChallenge(config),
        message: `This endpoint requires ${config.sttAmount} STT on Somnia Testnet (chain ${CHAIN_ID}).`,
      });
      return;
    }

    console.log(`[PAYMENT] STT payment header received for ${req.path}`);
    next();
  };
}

// ═══════════════════════════════════════════════════════════════════════════
// Payment Logging
// ═══════════════════════════════════════════════════════════════════════════

function logPayment(
  req: Request,
  endpoint: string,
  priceConfig: PriceConfig,
  opts: { isA2A?: boolean; depth?: number; parentJobId?: string; workerName?: string } = {}
): PaymentLog | null {
  const txId = (req.headers['x-payment-response'] as string) ||
    `pay_${(++paymentIdCounter).toString(16).padStart(8, '0')}`;

  const rawHeaders: Record<string, string> = {};
  ['x-payment-response', 'payment-response', 'x-402-version', 'www-authenticate'].forEach(h => {
    const val = req.headers[h] as string;
    if (val) rawHeaders[h] = val;
  });

  const entry: PaymentLog = {
    id: `pay_${(++paymentIdCounter).toString(36)}`,
    timestamp: new Date().toISOString(),
    endpoint,
    payer: opts.isA2A ? 'Manager Agent' : 'User',
    worker: opts.workerName || endpoint.split('/').pop() || 'unknown',
    transaction: txId,
    token: 'STT',
    amount: `${priceConfig.sttAmount} STT`,
    explorerUrl: getExplorerURL(txId),
    isA2A: opts.isA2A || false,
    parentJobId: opts.parentJobId,
    depth: opts.depth || 0,
    rawHeaders: Object.keys(rawHeaders).length > 0 ? rawHeaders : undefined,
  };

  paymentLogs.push(entry);
  broadcastSSE('payment', entry);

  console.log(`[PAYMENT] ${opts.isA2A ? 'A2A' : 'H2A'} | STT | ${entry.endpoint} | tx=${entry.transaction}`);

  return entry;
}

// ═══════════════════════════════════════════════════════════════════════════
// Pricing Configuration
// ═══════════════════════════════════════════════════════════════════════════

const PRICES: Record<string, PriceConfig> = {
  scanContract: {
    sttAmount: 0.010,
    description: 'Scanner Agent — detect top-10 Solidity vulnerabilities',
    category: 'security-scanner',
  },
  validateFinding: {
    sttAmount: 0.005,
    description: 'Validator Agent — confirm or deny scanner findings with reasoning',
    category: 'security-validator',
  },
  simulateExploit: {
    sttAmount: 0.020,
    description: 'Exploit Sim Agent — generate Foundry/Hardhat PoC exploit test code',
    category: 'security-exploit',
  },
};

const endpointMap: Record<string, string> = {
  scanContract: '/api/scan-contract',
  validateFinding: '/api/validate-finding',
  simulateExploit: '/api/simulate-exploit',
};

// ═══════════════════════════════════════════════════════════════════════════
// Server-Sent Events (SSE) — Real-time Dashboard
// ═══════════════════════════════════════════════════════════════════════════

const sseClients = new Map<string, Response>();

function broadcastSSE(event: string, data: any) {
  sseClients.forEach((client) => {
    client.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
  });
}

function sendSSETo(clientId: string, event: string, data: any) {
  const client = sseClients.get(clientId);
  if (client) {
    client.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// Routes — Health, Info & Discovery
// ═══════════════════════════════════════════════════════════════════════════

app.get('/health', (_req: Request, res: Response) => {
  res.json({
    status: 'ok',
    uptime: process.uptime(),
    network: NETWORK,
    chainId: CHAIN_ID,
    version: '2.0.0',
    agents: agentRegistry.length,
    totalPayments: paymentLogs.length,
    totalFindings: findingLogs.length,
  });
});

app.get('/', (_req: Request, res: Response) => {
  res.json({
    name: 'Audity — Smart Contract Security Platform',
    version: '2.0.0',
    description: 'Trustless smart contract security. AI agents scan, validate, and simulate exploits against Solidity contracts.',
    network: NETWORK,
    chainId: CHAIN_ID,
    protocol: 'x402 (HTTP 402 Payment Required)',
    tokenSupport: ['STT'],
    features: [
      'Solidity vulnerability scanning (top-10)',
      'Adversarial finding validation',
      'Foundry/Hardhat PoC exploit simulation',
      'STT micropayments on Somnia Testnet',
      'Real-time SSE security feed',
      'Trustless audit-full pipeline',
    ],
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// Route — GET /api/tools
// ═══════════════════════════════════════════════════════════════════════════

app.get('/api/tools', (_req: Request, res: Response) => {
  const tools = [
    {
      id: 'scanContract',
      name: 'Scanner Agent',
      endpoint: '/api/scan-contract',
      method: 'POST',
      price: { STT: PRICES.scanContract.sttAmount },
      category: 'security-scanner',
      description: PRICES.scanContract.description,
      reputation: findBestAgentByCategory('security-scanner')?.reputation || 0,
      jobsCompleted: agentRegistry.filter(a => a.category === 'security-scanner').reduce((s, a) => s + a.jobsCompleted, 0),
      efficiency: findBestAgentByCategory('security-scanner')?.efficiency || 0,
      params: {
        contractSource: 'string (optional — Solidity source code)',
        contractAddress: 'string (optional — 0x address to fetch from chain)',
        chain: 'string (optional — target chain, defaults to somnia-testnet)',
      },
      isExternal: false,
    },
    {
      id: 'validateFinding',
      name: 'Validator Agent',
      endpoint: '/api/validate-finding',
      method: 'POST',
      price: { STT: PRICES.validateFinding.sttAmount },
      category: 'security-validator',
      description: PRICES.validateFinding.description,
      reputation: findBestAgentByCategory('security-validator')?.reputation || 0,
      jobsCompleted: agentRegistry.filter(a => a.category === 'security-validator').reduce((s, a) => s + a.jobsCompleted, 0),
      efficiency: findBestAgentByCategory('security-validator')?.efficiency || 0,
      params: {
        finding: 'object (required — FindingLog from scanner)',
        contractSource: 'string (optional — Solidity source code for context)',
      },
      isExternal: false,
    },
    {
      id: 'simulateExploit',
      name: 'Exploit Sim Agent',
      endpoint: '/api/simulate-exploit',
      method: 'POST',
      price: { STT: PRICES.simulateExploit.sttAmount },
      category: 'security-exploit',
      description: PRICES.simulateExploit.description,
      reputation: findBestAgentByCategory('security-exploit')?.reputation || 0,
      jobsCompleted: agentRegistry.filter(a => a.category === 'security-exploit').reduce((s, a) => s + a.jobsCompleted, 0),
      efficiency: findBestAgentByCategory('security-exploit')?.efficiency || 0,
      params: {
        finding: 'object (required — confirmed FindingLog)',
        contractSource: 'string (optional — Solidity source code for context)',
      },
      isExternal: false,
    },
  ];

  res.json(tools);
});

// ═══════════════════════════════════════════════════════════════════════════
// Route — GET /api/registry
// ═══════════════════════════════════════════════════════════════════════════

app.get('/api/registry', (req: Request, res: Response) => {
  const category = req.query.category as string;
  const sortBy = (req.query.sort as string) || 'efficiency';
  const minReputation = parseInt(req.query.minRep as string) || 0;

  let agents = [...agentRegistry].filter(a => a.isActive && a.reputation >= minReputation);
  if (category) agents = agents.filter(a => a.category === category);

  switch (sortBy) {
    case 'reputation':
      agents.sort((a, b) => b.reputation - a.reputation);
      break;
    case 'price':
      agents.sort((a, b) => a.priceSTT - b.priceSTT);
      break;
    case 'jobs':
      agents.sort((a, b) => b.jobsCompleted - a.jobsCompleted);
      break;
    default:
      agents.sort((a, b) => b.efficiency - a.efficiency);
  }

  res.json({
    agents,
    count: agents.length,
    categories: [...new Set(agentRegistry.map(a => a.category))],
    contractAddress: '0xF5baa3381436e0C8818fB5EA3dA9d40C6c49C70D',
    network: NETWORK,
    chainId: CHAIN_ID,
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// Route — GET /api/payments
// ═══════════════════════════════════════════════════════════════════════════

app.get('/api/payments', (_req: Request, res: Response) => {
  res.json({
    payments: paymentLogs.slice(-50).reverse(),
    count: paymentLogs.length,
    a2aCount: paymentLogs.filter(p => p.isA2A).length,
    totalVolume: paymentLogs.reduce((sum, p) => {
      const amount = parseFloat(p.amount) || 0;
      return sum + amount;
    }, 0).toFixed(4),
    timestamp: new Date().toISOString(),
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// Routes — Contract Watchlist (periodic + scheduled re-scanning)
// ═══════════════════════════════════════════════════════════════════════════

// GET /api/watchlist — list all watched contracts
app.get('/api/watchlist', (_req: Request, res: Response) => {
  res.json({
    watchlist,
    count: watchlist.length,
    handlerContract: WATCHLIST_HANDLER_ADDRESS || null,
    network: NETWORK,
  });
});

// POST /api/watchlist — add a contract for periodic re-scanning (BlockTick)
app.post('/api/watchlist', async (req: Request, res: Response) => {
  const { contractAddress, contractSource, label } = req.body;
  if (!contractAddress) {
    res.status(400).json({ error: 'contractAddress is required' });
    return;
  }

  const already = watchlist.find(e => e.contractAddress.toLowerCase() === contractAddress.toLowerCase());
  if (already) {
    res.status(409).json({ error: 'Contract already in watchlist', entry: already });
    return;
  }

  const entry: WatchlistEntry = {
    contractAddress,
    contractSource,
    label: label || contractAddress,
    addedAt:          Date.now(),
    scanCount:        0,
    subscriptionType: 'periodic',
  };

  const txHash = await createPeriodicRescan(entry);
  entry.subscriptionTxHash = txHash || undefined;

  watchlist.push(entry);
  broadcastSSE('watchlist_added', { contractAddress, label: entry.label, txHash });

  res.json({
    message: 'Contract added to watchlist. BlockTick subscription created.',
    entry,
    reactivity: txHash
      ? { subscriptionTxHash: txHash, handlerContract: WATCHLIST_HANDLER_ADDRESS }
      : { status: 'disabled — set WATCHLIST_HANDLER_ADDRESS to enable' },
  });
});

// POST /api/watchlist/schedule-rescan — one-off rescan at a future timestamp
app.post('/api/watchlist/schedule-rescan', async (req: Request, res: Response) => {
  const { contractAddress, contractSource, label, rescanAt } = req.body;
  if (!contractAddress || !rescanAt) {
    res.status(400).json({ error: 'contractAddress and rescanAt (ms timestamp) are required' });
    return;
  }

  const rescanAtMs = parseInt(rescanAt, 10);
  if (rescanAtMs < Date.now() + 12_000) {
    res.status(400).json({ error: 'rescanAt must be at least 12 seconds in the future' });
    return;
  }

  const entry: WatchlistEntry = {
    contractAddress,
    contractSource,
    label:            label || contractAddress,
    addedAt:          Date.now(),
    scanCount:        0,
    subscriptionType: 'scheduled',
    nextScanAt:       rescanAtMs,
  };

  try {
    const txHash = await scheduleOneOffRescan(entry, rescanAtMs);
    entry.subscriptionTxHash = txHash || undefined;

    // Only add to watchlist if not already present
    if (!watchlist.find(e => e.contractAddress.toLowerCase() === contractAddress.toLowerCase())) {
      watchlist.push(entry);
    }

    broadcastSSE('watchlist_scheduled', {
      contractAddress,
      rescanAt:   new Date(rescanAtMs).toISOString(),
      txHash,
    });

    res.json({
      message: `One-off rescan scheduled for ${new Date(rescanAtMs).toISOString()}`,
      entry,
      reactivity: txHash
        ? { subscriptionTxHash: txHash, handlerContract: WATCHLIST_HANDLER_ADDRESS }
        : { status: 'disabled — set WATCHLIST_HANDLER_ADDRESS to enable' },
    });
  } catch (err: any) {
    res.status(400).json({ error: err.message });
  }
});

// DELETE /api/watchlist/:address — remove a contract from the watchlist
app.delete('/api/watchlist/:address', async (req: Request, res: Response) => {
  const address = req.params['address'] as string;
  const idx = watchlist.findIndex(e => e.contractAddress.toLowerCase() === address.toLowerCase());

  if (idx === -1) {
    res.status(404).json({ error: 'Contract not in watchlist' });
    return;
  }

  const [removed] = watchlist.splice(idx, 1);

  // Remove from on-chain WatchlistHandler if configured
  if (WATCHLIST_HANDLER_ADDRESS && viemWalletClient) {
    try {
      const hash = await viemWalletClient.writeContract({
        address: WATCHLIST_HANDLER_ADDRESS,
        abi: WATCHLIST_HANDLER_ABI,
        functionName: 'removeContract',
        args: [address as Hex],
      });
      console.log(`[WATCHLIST] removeContract on-chain: ${hash}`);
    } catch (err: any) {
      console.error('[WATCHLIST] removeContract failed:', err.message);
    }
  }

  broadcastSSE('watchlist_removed', { contractAddress: address });
  res.json({ message: 'Removed from watchlist', removed });
});

// ═══════════════════════════════════════════════════════════════════════════
// Route — GET /api/findings
// ═══════════════════════════════════════════════════════════════════════════

app.get('/api/findings', async (_req: Request, res: Response) => {
  try {
    // Read all findings directly from Somnia SecurityRegistry — never stale
    const ids = await viemPublicClient.readContract({
      address: SECURITY_REGISTRY_ADDRESS,
      abi: SECURITY_REGISTRY_ABI,
      functionName: 'getFindingIds',
      args: [],
    }) as `0x${string}`[];

    const findings: any[] = [];
    for (const id of (ids || [])) {
      try {
        const f = await viemPublicClient.readContract({
          address: SECURITY_REGISTRY_ADDRESS,
          abi: SECURITY_REGISTRY_ABI,
          functionName: 'getFinding',
          args: [id],
        }) as any;
        findings.push({
          id,
          txHash:          id,
          contractAddress: f.contractAddress === '0x0000000000000000000000000000000000000000' ? 'source-provided' : f.contractAddress,
          vulnType:        f.vulnType,
          severity:        f.severity,
          description:     f.description,
          scannerAgent:    f.scannerAgent,
          confirmed:       Number(f.status) === 1,
          status:          ['Pending', 'Confirmed', 'Rejected'][Number(f.status)] ?? 'Pending',
          rewardSTT:       Number(f.rewardSTT) / 1e18,
          timestamp:       Number(f.submittedAt) * 1000,
          source:          'somnia-chain',
        });
      } catch { /* skip corrupt entry */ }
    }

    const sorted = findings.sort((a, b) => b.timestamp - a.timestamp);
    res.json({
      findings: sorted.slice(0, 50),
      count:          findings.length,
      confirmedCount: findings.filter(f => f.confirmed).length,
      criticalCount:  findings.filter(f => f.severity === 'critical').length,
      highCount:      findings.filter(f => f.severity === 'high').length,
      source:         'somnia-chain',
      timestamp:      new Date().toISOString(),
    });
  } catch (err: any) {
    // Fallback to in-session memory if chain read fails
    res.json({
      findings:       findingLogs.slice(-50).reverse(),
      count:          findingLogs.length,
      confirmedCount: findingLogs.filter(f => f.confirmed).length,
      criticalCount:  findingLogs.filter(f => f.severity === 'critical').length,
      highCount:      findingLogs.filter(f => f.severity === 'high').length,
      source:         'in-memory-fallback',
      error:          err.message,
      timestamp:      new Date().toISOString(),
    });
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// Route — GET /api/stats
// ═══════════════════════════════════════════════════════════════════════════

app.get('/api/stats', async (_req: Request, res: Response) => {
  try {
    // Read permanent stats directly from Somnia SecurityRegistry — survives server restarts
    const [ids, repBP, ...hireCounts] = await Promise.all([
      viemPublicClient.readContract({
        address: SECURITY_REGISTRY_ADDRESS,
        abi: SECURITY_REGISTRY_ABI,
        functionName: 'getFindingIds',
        args: [],
      }) as Promise<`0x${string}`[]>,
      viemPublicClient.readContract({
        address: SECURITY_REGISTRY_ADDRESS,
        abi: SECURITY_REGISTRY_ABI,
        functionName: 'scannerReputation',
        args: [PLATFORM_ADDRESS as Hex],
      }) as Promise<bigint>,
      ...agentRegistry.map(a =>
        viemPublicClient.readContract({
          address: SECURITY_REGISTRY_ADDRESS,
          abi: SECURITY_REGISTRY_ABI,
          functionName: 'agentHireCount',
          args: [a.id],
        }) as Promise<bigint>
      ),
    ]);

    // Fetch individual findings to compute severity + confirmed breakdown
    const findings: any[] = [];
    for (const id of (ids || [])) {
      try {
        const f = await viemPublicClient.readContract({
          address: SECURITY_REGISTRY_ADDRESS,
          abi: SECURITY_REGISTRY_ABI,
          functionName: 'getFinding',
          args: [id],
        }) as any;
        findings.push({ severity: f.severity, status: Number(f.status) });
      } catch { /* skip */ }
    }

    const reputationPct = Number(repBP) / 100;
    const totalHires = hireCounts.reduce((s, c) => s + Number(c), 0);

    // Update local registry with fresh chain values
    agentRegistry.forEach((a, i) => {
      if (hireCounts[i] !== undefined) a.jobsCompleted = Number(hireCounts[i]);
      a.reputation = reputationPct;
      a.efficiency = a.priceSTT > 0 ? Math.round((reputationPct / 100) * (1 / (a.priceSTT + 0.001)) * 100) / 100 : 0;
    });

    res.json({
      economy: {
        totalPayments: paymentLogs.length,           // session-only (payments have no on-chain count)
        a2aPayments:   paymentLogs.filter(p => p.isA2A).length,
        h2aPayments:   paymentLogs.filter(p => !p.isA2A).length,
        totalAgents:   agentRegistry.length,
        activeAgents:  agentRegistry.filter(a => a.isActive).length,
        avgReputation: Math.round(reputationPct),
        totalHires,
      },
      security: {
        totalVulnsFound:   findings.length,
        criticalCount:     findings.filter(f => f.severity === 'critical').length,
        highCount:         findings.filter(f => f.severity === 'high').length,
        mediumCount:       findings.filter(f => f.severity === 'medium').length,
        lowCount:          findings.filter(f => f.severity === 'low').length,
        confirmedFindings: findings.filter(f => f.status === 1).length,
        rejectedFindings:  findings.filter(f => f.status === 2).length,
        pendingFindings:   findings.filter(f => f.status === 0).length,
      },
      topAgents: [...agentRegistry]
        .sort((a, b) => b.reputation - a.reputation)
        .slice(0, 5)
        .map(a => ({ name: a.name, reputation: a.reputation, jobs: a.jobsCompleted })),
      recentPayments: paymentLogs.slice(-10).reverse(),
      source:  'somnia-chain',
      network: NETWORK,
      uptime:  process.uptime(),
    });
  } catch (err: any) {
    // Fallback: return what we have in-session if chain read fails
    res.json({
      economy: {
        totalPayments: paymentLogs.length,
        a2aPayments:   paymentLogs.filter(p => p.isA2A).length,
        h2aPayments:   paymentLogs.filter(p => !p.isA2A).length,
        totalAgents:   agentRegistry.length,
        activeAgents:  agentRegistry.filter(a => a.isActive).length,
        avgReputation: Math.round(agentRegistry.reduce((s, a) => s + a.reputation, 0) / agentRegistry.length),
        totalHires:    agentRegistry.reduce((s, a) => s + a.jobsCompleted, 0),
      },
      security: {
        totalVulnsFound:   findingLogs.length,
        criticalCount:     findingLogs.filter(f => f.severity === 'critical').length,
        highCount:         findingLogs.filter(f => f.severity === 'high').length,
        mediumCount:       findingLogs.filter(f => f.severity === 'medium').length,
        lowCount:          findingLogs.filter(f => f.severity === 'low').length,
        confirmedFindings: findingLogs.filter(f => f.confirmed).length,
      },
      topAgents: [...agentRegistry]
        .sort((a, b) => b.reputation - a.reputation)
        .slice(0, 5)
        .map(a => ({ name: a.name, reputation: a.reputation, jobs: a.jobsCompleted })),
      recentPayments: paymentLogs.slice(-10).reverse(),
      source:  'in-memory-fallback',
      error:   err.message,
      network: NETWORK,
      uptime:  process.uptime(),
    });
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// Paid Routes — Security Agent Endpoints
// ═══════════════════════════════════════════════════════════════════════════

// ── Scanner Agent ──────────────────────────────────────────────────────────

app.post('/api/scan-contract', createPaidRoute(PRICES.scanContract), async (req: Request, res: Response) => {
  const agent = findBestAgentByCategory('security-scanner');
  const paymentEntry = logPayment(req, '/api/scan-contract', PRICES.scanContract, { workerName: agent?.name || 'Scanner Agent' });

  const { contractSource, contractAddress, chain } = req.body;
  if (!contractSource && !contractAddress) {
    res.status(400).json({ error: 'Provide contractSource (Solidity code) or contractAddress (0x...).' });
    return;
  }

  const targetChain = chain || NETWORK;
  const target = contractAddress
    ? `contract at address ${contractAddress} on ${targetChain}`
    : 'the provided Solidity source';

  let rawFindings: any[] = [];
  try {
    const systemPrompt = `You are an expert smart contract security auditor with deep knowledge of Solidity vulnerabilities.
Your task is to scan the provided contract for the top-10 Solidity vulnerability classes:
1. Reentrancy (SWC-107)
2. Integer Overflow/Underflow (SWC-101)
3. Access Control flaws (SWC-105, SWC-106)
4. Logic errors and incorrect state transitions
5. Flash loan attack surfaces
6. Uninitialized storage pointers (SWC-109)
7. Timestamp manipulation (SWC-116)
8. Front-running / tx.origin misuse (SWC-115)
9. Unchecked return values (SWC-104)
10. Denial of service vectors (SWC-113)

Return ONLY valid JSON: { "findings": [ { "vulnType": "reentrancy|overflow|access-control|logic|flash-loan", "severity": "critical|high|medium|low", "line": <number or null>, "description": "<concise description>", "recommendation": "<fix recommendation>" } ] }
If no vulnerabilities found, return { "findings": [] }.`;

    const userPrompt = contractSource
      ? `Scan this Solidity contract for vulnerabilities:\n\n\`\`\`solidity\n${contractSource}\n\`\`\``
      : `Scan ${target} for vulnerabilities. Analyze typical patterns for contracts at this address.`;

    const completion = await groq.chat.completions.create({
      messages: [
        { role: 'system', content: systemPrompt },
        { role: 'user', content: userPrompt },
      ],
      model: 'llama-3.3-70b-versatile',
      temperature: 0.2,
      max_tokens: 1000,
      response_format: { type: 'json_object' },
    });
    const parsed = JSON.parse(completion.choices[0]?.message?.content || '{"findings":[]}');
    rawFindings = parsed.findings || [];
  } catch (err) {
    console.error('[SCAN] LLM error:', err);
    rawFindings = [];
  }

  // Persist findings to log, submit on-chain via Somnia Reactivity, and broadcast
  const persistedFindings: FindingLog[] = [];

  for (const f of rawFindings) {
    const rewardSTT = f.severity === 'critical' ? 0.05 : f.severity === 'high' ? 0.03 : 0.01;
    const vulnType  = (f.vulnType  || 'logic')  as FindingLog['vulnType'];
    const severity  = (f.severity  || 'medium') as FindingLog['severity'];

    // Submit to SecurityRegistry on Somnia — fires FindingSubmitted event
    // Reactivity SDK picks it up and broadcasts to all WebSocket subscribers
    const onChainId = await submitFindingOnChain(
      contractAddress || 'source-provided',
      vulnType,
      severity,
      f.description || '',
      agent?.id || 'scanner-agent-1',
      rewardSTT
    );

    const entry: FindingLog = {
      id: `finding_${(++findingIdCounter).toString(36)}`,
      timestamp: Date.now(),
      contractAddress: contractAddress || 'source-provided',
      vulnType,
      severity,
      description: f.description || '',
      scannerAgent: agent?.id || 'scanner-agent-1',
      confirmed: false,
      rewardSTT,
      txHash: onChainId || paymentEntry?.transaction,
    };

    findingLogs.push(entry);
    // Local SSE broadcast (instant) — Reactivity will also fire when tx confirms
    broadcastSSE('finding', { ...entry, onChainId, line: f.line, recommendation: f.recommendation });
    persistedFindings.push(entry);
  }

  if (agent) { agent.totalEarned += PRICES.scanContract.sttAmount; recordHireOnChain(agent.id); }

  res.json({
    findings: rawFindings,
    findingLogs: persistedFindings,
    contractAddress: contractAddress || null,
    chain: targetChain,
    scannerAgent: agent?.name || 'Scanner Agent',
    source: 'Audity Scanner Agent',
    reactivity: SECURITY_REGISTRY_ADDRESS
      ? { contract: SECURITY_REGISTRY_ADDRESS, network: NETWORK }
      : { status: 'disabled — set SECURITY_REGISTRY_ADDRESS to enable' },
    payment: paymentEntry ? { transaction: paymentEntry.transaction, token: 'STT', amount: paymentEntry.amount, explorerUrl: paymentEntry.explorerUrl } : null,
  });
});

// ── Validator Agent ────────────────────────────────────────────────────────

app.post('/api/validate-finding', createPaidRoute(PRICES.validateFinding), async (req: Request, res: Response) => {
  const agent = findBestAgentByCategory('security-validator');
  const paymentEntry = logPayment(req, '/api/validate-finding', PRICES.validateFinding, { workerName: agent?.name || 'Validator Agent' });

  const { finding, contractSource } = req.body as { finding: FindingLog; contractSource?: string };
  if (!finding) {
    res.status(400).json({ error: 'Missing "finding" field (FindingLog object from scanner).' });
    return;
  }

  let validationResult = { confirmed: false, confidence: 0, notes: '' };
  try {
    const systemPrompt = `You are an adversarial smart contract auditor. Your job is to independently verify or refute vulnerability findings from a scanner agent.
Be skeptical. Confirm only if you can independently reason the vulnerability exists and is exploitable.
Return ONLY valid JSON: { "confirmed": true|false, "confidence": 0-100, "notes": "<your reasoning>" }`;

    const userPrompt = `Verify this finding:
Vulnerability Type: ${finding.vulnType}
Severity: ${finding.severity}
Description: ${finding.description}
${contractSource ? `\nContract Source:\n\`\`\`solidity\n${contractSource}\n\`\`\`` : ''}

Is this finding valid and exploitable? Return your verdict.`;

    const completion = await groq.chat.completions.create({
      messages: [
        { role: 'system', content: systemPrompt },
        { role: 'user', content: userPrompt },
      ],
      model: 'llama-3.3-70b-versatile',
      temperature: 0.1,
      max_tokens: 600,
      response_format: { type: 'json_object' },
    });
    validationResult = JSON.parse(completion.choices[0]?.message?.content || '{"confirmed":false,"confidence":0,"notes":""}');
  } catch (err) {
    console.error('[VALIDATE] LLM error:', err);
    validationResult = { confirmed: false, confidence: 0, notes: 'Validation service temporarily unavailable.' };
  }

  // Update finding log and scanner reputation
  const logEntry = findingLogs.find(f => f.id === finding.id);
  if (logEntry) {
    logEntry.confirmed = validationResult.confirmed;
    logEntry.validatorAgent = agent?.id;
  }

  // Push verdict to SecurityRegistry on Somnia — fires FindingConfirmed or FindingRejected
  // Somnia Reactivity propagates to all on-chain and WebSocket subscribers
  const onChainId = (finding.txHash?.startsWith('0x') ? finding.txHash : null) as Hex | null;
  if (onChainId) {
    if (validationResult.confirmed) {
      await confirmFindingOnChain(onChainId);
    } else {
      await rejectFindingOnChain(onChainId);
    }
  }

  if (agent) { agent.totalEarned += PRICES.validateFinding.sttAmount; recordHireOnChain(agent.id); }

  broadcastSSE('finding_validated', { findingId: finding.id, ...validationResult });

  res.json({
    confirmed: validationResult.confirmed,
    confidence: validationResult.confidence,
    notes: validationResult.notes,
    findingId: finding.id,
    validatorAgent: agent?.name || 'Validator Agent',
    source: 'Audity Validator Agent',
    payment: paymentEntry ? { transaction: paymentEntry.transaction, token: 'STT', amount: paymentEntry.amount, explorerUrl: paymentEntry.explorerUrl } : null,
  });
});

// ── Exploit Sim Agent ──────────────────────────────────────────────────────

app.post('/api/simulate-exploit', createPaidRoute(PRICES.simulateExploit), async (req: Request, res: Response) => {
  const agent = findBestAgentByCategory('security-exploit');
  const paymentEntry = logPayment(req, '/api/simulate-exploit', PRICES.simulateExploit, { workerName: agent?.name || 'Exploit Sim Agent' });

  const { finding, contractSource } = req.body as { finding: FindingLog; contractSource?: string };
  if (!finding) {
    res.status(400).json({ error: 'Missing "finding" field (confirmed FindingLog).' });
    return;
  }

  let exploitResult = { exploitCode: '', attackVector: '', estimatedLoss: '' };
  try {
    const systemPrompt = `You are a smart contract security researcher specializing in Foundry and Hardhat exploit PoC development.
Given a confirmed vulnerability, write a complete, runnable Foundry test that demonstrates the exploit.
Include setup, attack execution, and assertion of stolen funds or state corruption.
Return ONLY valid JSON: { "exploitCode": "<complete Foundry test in Solidity>", "attackVector": "<brief attack vector description>", "estimatedLoss": "<estimated loss in ETH/tokens>" }`;

    const userPrompt = `Write a Foundry PoC exploit for this vulnerability:
Type: ${finding.vulnType}
Severity: ${finding.severity}
Description: ${finding.description}
${contractSource ? `\nVulnerable Contract:\n\`\`\`solidity\n${contractSource}\n\`\`\`` : ''}

Generate a complete Foundry test demonstrating the exploit.`;

    const completion = await groq.chat.completions.create({
      messages: [
        { role: 'system', content: systemPrompt },
        { role: 'user', content: userPrompt },
      ],
      model: 'llama-3.3-70b-versatile',
      temperature: 0.3,
      max_tokens: 1200,
      response_format: { type: 'json_object' },
    });
    exploitResult = JSON.parse(completion.choices[0]?.message?.content || '{"exploitCode":"","attackVector":"","estimatedLoss":""}');
  } catch (err) {
    console.error('[EXPLOIT] LLM error:', err);
    exploitResult = {
      exploitCode: '// Exploit simulation temporarily unavailable. Please try again.',
      attackVector: finding.vulnType,
      estimatedLoss: 'Unknown',
    };
  }

  if (agent) { agent.totalEarned += PRICES.simulateExploit.sttAmount; recordHireOnChain(agent.id); }

  res.json({
    exploitCode: exploitResult.exploitCode,
    attackVector: exploitResult.attackVector,
    estimatedLoss: exploitResult.estimatedLoss,
    findingId: finding.id,
    exploitAgent: agent?.name || 'Exploit Sim Agent',
    source: 'Audity Exploit Sim Agent',
    payment: paymentEntry ? { transaction: paymentEntry.transaction, token: 'STT', amount: paymentEntry.amount, explorerUrl: paymentEntry.explorerUrl } : null,
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// Manager Agent — Autonomous Security Orchestration
// ═══════════════════════════════════════════════════════════════════════════

interface AgentExecutionResult {
  query: string;
  plan: string[];
  hiringDecisions: Array<{
    agent: string;
    reason: string;
    cost: number;
    reputation: number;
    alternative?: string;
    alternativeReason?: string;
  }>;
  results: Array<{
    tool: string;
    result: any;
    payment?: any;
    error?: string;
  }>;
  finalAnswer: string;
  totalCost: { STT: number };
  protocolTrace: Array<{
    step: string;
    httpStatus: number;
    headers: Record<string, string>;
    timestamp: string;
  }>;
}

function autonomousHiringDecision(
  toolId: string,
  allAgents: AgentRegistryEntry[]
): { chosen: AgentRegistryEntry | null; reason: string; alternatives: AgentRegistryEntry[] } {
  const category = PRICES[toolId]?.category;
  if (!category) return { chosen: null, reason: 'Unknown tool', alternatives: [] };

  const candidates = allAgents.filter(a => a.isActive && a.category === category);
  if (candidates.length === 0) return { chosen: null, reason: 'No agents available', alternatives: [] };

  const scored = candidates
    .map(a => ({ agent: a, score: a.efficiency }))
    .sort((a, b) => b.score - a.score);

  const chosen = scored[0].agent;
  const alternatives = scored.slice(1).map(s => s.agent);

  const reason = `Selected ${chosen.name} (Rep: ${chosen.reputation}/100, Cost: ${chosen.priceSTT} STT, Efficiency: ${scored[0].score.toFixed(1)}). ` +
    (alternatives.length > 0
      ? `Rejected ${alternatives[0].name} (Rep: ${alternatives[0].reputation}, Cost: ${alternatives[0].priceSTT} STT) — lower efficiency.`
      : 'No alternatives available.');

  return { chosen, reason, alternatives };
}

async function runManagerAgent(
  query: string,
  clientId?: string,
  options: { budgetLimit?: number } = {}
): Promise<AgentExecutionResult> {
  const { budgetLimit = 0.1 } = options;
  const startTime = Date.now();
  const plan: string[] = [];
  const hiringDecisions: AgentExecutionResult['hiringDecisions'] = [];
  const protocolTrace: AgentExecutionResult['protocolTrace'] = [];
  const results: AgentExecutionResult['results'] = [];
  const totalCost = { STT: 0 };

  plan.push(`[${new Date().toISOString()}] Audity Manager received query: "${query}"`);
  plan.push('Step 1: Analyzing security intent with LLM planner...');

  if (clientId) {
    sendSSETo(clientId, 'step', { label: 'Analyzing intent', detail: 'LLM planner routing to security agents', status: 'active' });
  }

  protocolTrace.push({
    step: 'Intent Analysis',
    httpStatus: 200,
    headers: { 'x-agent': 'Audity Manager', 'x-model': 'llama-3.3-70b-versatile' },
    timestamp: new Date().toISOString(),
  });
  if (clientId) sendSSETo(clientId, 'protocol_trace', protocolTrace[protocolTrace.length - 1]);

  const toolsList = Object.entries(PRICES).map(([id, config]) => {
    const agent = findBestAgentByCategory(config.category);
    return `- "${id}": ${agent?.name || id} | ${config.description} | Cost: ${config.sttAmount} STT | Rep: ${agent?.reputation ?? 0}/100`;
  }).join('\n');

  const plannerPrompt = `You are the AUDITY MANAGER — an AI security orchestrator for smart contract audits.
Your job is to route security queries to the best security agent.

Available Security Agents (x402 STT paid):
${toolsList}

User Query: "${query}"

Intent patterns:
- "scan" / "audit" / "check contract" / "find vulnerabilities" → use scanContract
- "validate" / "confirm finding" / "verify" → use validateFinding
- "simulate" / "exploit" / "poc" / "proof of concept" → use simulateExploit
- "audit-full" / "full audit" / "complete audit" → chain all three

Return ONLY valid JSON:
{
  "reasoning": "Why this agent best serves the security need",
  "intent": "scan|validate|simulate|audit-full",
  "toolCalls": [
    { "toolId": "tool_id", "params": { "param_name": "value" } }
  ]
}`;

  let llmPlan: any;

  try {
    const completion = await groq.chat.completions.create({
      messages: [
        { role: 'system', content: 'You are a JSON-generating security agent router. Always return valid JSON.' },
        { role: 'user', content: plannerPrompt },
      ],
      model: 'llama-3.3-70b-versatile',
      temperature: 0,
      response_format: { type: 'json_object' },
    });
    const content = completion.choices[0]?.message?.content;
    if (content) llmPlan = JSON.parse(content);
  } catch (err) {
    console.warn('[MANAGER] Groq planning failed:', err);
  }

  if (!llmPlan) {
    llmPlan = fallbackSecurityPlan(query);
  }

  if (clientId) {
    sendSSETo(clientId, 'step', { label: 'Analyzing intent', status: 'complete' });
    sendSSETo(clientId, 'step', {
      label: 'Planning delegation',
      detail: `${llmPlan.toolCalls?.length || 0} security agents to hire`,
      status: 'complete',
    });
  }

  plan.push(`LLM Reasoning: ${llmPlan.reasoning}`);

  // Handle audit-full: expand to scan → validate each → simulate criticals
  let toolCalls = llmPlan.toolCalls || [];
  if (llmPlan.intent === 'audit-full' && toolCalls.length === 1 && toolCalls[0].toolId === 'scanContract') {
    // The pipeline will auto-chain after scan completes
    plan.push('Audit-full mode: will chain validate + simulate after scan.');
  }

  // Execute tool calls
  let scannedFindings: FindingLog[] = [];

  for (const tc of toolCalls) {
    const toolId = tc.toolId as string;
    const price = PRICES[toolId];

    if (!price) {
      results.push({ tool: toolId, result: null, error: 'Tool not found in registry' });
      continue;
    }

    if (totalCost.STT + price.sttAmount > budgetLimit) {
      results.push({ tool: toolId, result: null, error: `Budget limit reached (${budgetLimit} STT).` });
      continue;
    }

    const hiring = autonomousHiringDecision(toolId, agentRegistry);
    const agentName = hiring.chosen?.name || toolId;

    hiringDecisions.push({
      agent: agentName,
      reason: hiring.reason,
      cost: price.sttAmount,
      reputation: hiring.chosen?.reputation || 0,
      alternative: hiring.alternatives[0]?.name,
      alternativeReason: hiring.alternatives[0]
        ? `${hiring.alternatives[0].reputation}/100 rep, ${hiring.alternatives[0].priceSTT} STT`
        : undefined,
    });

    if (clientId) {
      broadcastSSE('hiring_decision', {
        tool: toolId,
        selectedAgent: agentName,
        reason: hiring.reason,
        valueScore: hiring.chosen?.efficiency || 0,
        alternatives: hiring.alternatives.map(a => ({ id: a.id, score: a.efficiency })),
        approved: true,
      });
      sendSSETo(clientId, 'step', {
        label: `Hiring ${agentName}`,
        detail: `${price.sttAmount} STT | Rep: ${hiring.chosen?.reputation || 'N/A'}/100`,
        status: 'active',
      });
    }

    totalCost.STT += price.sttAmount;

    const challengeTrace = {
      step: `HTTP 402 Payment Required → ${agentName}`,
      httpStatus: 402,
      headers: { 'x-402-version': '1.0', 'x-pay-to': SERVER_ADDRESS, 'x-amount': `${price.sttAmount} STT`, 'x-chain': CHAIN_ID },
      timestamp: new Date().toISOString(),
    };
    protocolTrace.push(challengeTrace);
    if (clientId) sendSSETo(clientId, 'protocol_trace', challengeTrace);

    // Send real STT payment on-chain
    let txHash: string;
    try {
      txHash = await sendSTTPayment(SERVER_ADDRESS, price.sttAmount);
    } catch (payErr: any) {
      console.error(`[PAYMENT] STT transfer failed: ${payErr.message}`);
      throw new Error(`STT payment failed for ${agentName}: ${payErr.message}`);
    }

    // Run the security agent
    const toolResult = await runSecurityAgent(toolId, tc.params, query, txHash);

    const payment = {
      transaction: txHash,
      token: 'STT',
      amount: `${price.sttAmount} STT`,
      explorerUrl: getExplorerURL(txHash),
    };

    paymentLogs.push({
      id: `pay_${(++paymentIdCounter).toString(36)}`,
      timestamp: new Date().toISOString(),
      endpoint: endpointMap[toolId] || `/api/${toolId}`,
      payer: 'Manager Agent',
      worker: agentName,
      transaction: payment.transaction,
      token: 'STT',
      amount: payment.amount,
      explorerUrl: payment.explorerUrl,
      isA2A: true,
      depth: 0,
    });
    broadcastSSE('payment', paymentLogs[paymentLogs.length - 1]);

    protocolTrace.push({
      step: `x402 STT Payment → ${agentName}`,
      httpStatus: 200,
      headers: { 'x-402-version': '1.0', 'x-payment-mode': 'onchain', 'x-chain': CHAIN_ID, 'x-tx-hash': txHash },
      timestamp: new Date().toISOString(),
    });
    if (clientId) sendSSETo(clientId, 'protocol_trace', protocolTrace[protocolTrace.length - 1]);

    results.push({ tool: agentName, result: toolResult, payment });

    // Track scan findings for audit-full chaining
    if (toolId === 'scanContract' && toolResult?.findings) {
      scannedFindings = toolResult.findingLogs || [];
    }

    if (clientId) {
      sendSSETo(clientId, 'thought', {
        content: `**${agentName}:** ${typeof toolResult === 'string' ? toolResult.slice(0, 300) : JSON.stringify(toolResult).slice(0, 300)}`,
      });
      sendSSETo(clientId, 'step', {
        label: `Hiring ${agentName}`,
        detail: `Paid ${price.sttAmount} STT ✓`,
        status: 'complete',
      });
    }

    const registryAgent = agentRegistry.find(a => a.name === agentName);
    if (registryAgent) {
      registryAgent.totalEarned += price.sttAmount;
      recordHireOnChain(registryAgent.id);
    }
  }

  // audit-full: validate each finding then simulate criticals
  if (llmPlan.intent === 'audit-full' && scannedFindings.length > 0) {
    for (const finding of scannedFindings.slice(0, 5)) {
      if (totalCost.STT + PRICES.validateFinding.sttAmount > budgetLimit) break;

      totalCost.STT += PRICES.validateFinding.sttAmount;
      const validationResult = await runSecurityAgent('validateFinding', { finding, contractSource: toolCalls[0]?.params?.contractSource }, query, '');
      results.push({ tool: 'Validator Agent', result: validationResult });

      if (validationResult?.confirmed && finding.severity === 'critical') {
        if (totalCost.STT + PRICES.simulateExploit.sttAmount <= budgetLimit) {
          totalCost.STT += PRICES.simulateExploit.sttAmount;
          const exploitResult = await runSecurityAgent('simulateExploit', { finding, contractSource: toolCalls[0]?.params?.contractSource }, query, '');
          results.push({ tool: 'Exploit Sim Agent', result: exploitResult });
        }
      }
    }
  }

  // Synthesize final answer
  if (clientId) sendSSETo(clientId, 'step', { label: 'Synthesizing results', status: 'active' });

  let finalAnswer = '';
  const successResults = results.filter(r => r.result);

  if (successResults.length === 0) {
    finalAnswer = "No security agents could complete the requested audit. Provide a contract source (Solidity) or address to scan for vulnerabilities.";
  } else {
    try {
      const synthesisPrompt = `You are Audity, an AI smart contract security platform. Synthesize these agent results into a clear security audit summary for: "${query}".

Agent Results:
${successResults.map(r => `${r.tool}: ${typeof r.result === 'string' ? r.result : JSON.stringify(r.result)}`).join('\n\n')}

Provide a concise security summary: findings count, severity breakdown, top risks, and recommended next steps.`;
      const completion = await groq.chat.completions.create({
        messages: [{ role: 'user', content: synthesisPrompt }],
        model: 'llama-3.3-70b-versatile',
        temperature: 0.4,
        max_tokens: 800,
      });
      finalAnswer = completion.choices[0]?.message?.content || '';
    } catch {
      finalAnswer = successResults.map(r =>
        `${r.tool}: ${typeof r.result === 'string' ? r.result : JSON.stringify(r.result)}`
      ).join('\n\n');
    }
  }

  if (clientId) {
    sendSSETo(clientId, 'step', { label: 'Synthesizing results', status: 'complete' });
    sendSSETo(clientId, 'done', { duration: Date.now() - startTime });
  }

  plan.push(`Total cost: ${totalCost.STT.toFixed(4)} STT`);
  plan.push(`Duration: ${Date.now() - startTime}ms`);

  return {
    query,
    plan,
    hiringDecisions,
    results,
    finalAnswer,
    totalCost: { STT: Math.round(totalCost.STT * 10000) / 10000 },
    protocolTrace,
  };
}

function fallbackSecurityPlan(query: string): any {
  const q = query.toLowerCase();
  let reasoning = 'Rule-based routing: ';

  if (q.match(/validate|confirm|verify|check finding/)) {
    reasoning += 'Detected finding validation request.';
    return { reasoning, intent: 'validate', toolCalls: [{ toolId: 'validateFinding', params: {} }] };
  }
  if (q.match(/exploit|simulate|poc|proof.of.concept|attack/)) {
    reasoning += 'Detected exploit simulation request.';
    return { reasoning, intent: 'simulate', toolCalls: [{ toolId: 'simulateExploit', params: {} }] };
  }
  if (q.match(/full.audit|audit.full|complete.audit|audit.all/)) {
    reasoning += 'Detected full audit request — chaining scan → validate → simulate.';
    return { reasoning, intent: 'audit-full', toolCalls: [{ toolId: 'scanContract', params: { contractSource: query } }] };
  }

  // Default: scan
  reasoning += 'Defaulting to contract scan.';
  return { reasoning, intent: 'scan', toolCalls: [{ toolId: 'scanContract', params: { contractSource: query } }] };
}

async function runSecurityAgent(toolId: string, params: any, query: string, txHash: string): Promise<any> {
  // scanContract returns structured JSON so findings can be submitted on-chain
  if (toolId === 'scanContract') {
    const contractSource = params.contractSource || params.contractAddress || query;
    try {
      const completion = await groq.chat.completions.create({
        messages: [
          {
            role: 'system',
            content: `You are an expert smart contract security auditor with deep knowledge of Solidity vulnerabilities.
Scan the provided contract for the top-10 Solidity vulnerability classes:
1. Reentrancy (SWC-107)
2. Integer Overflow/Underflow (SWC-101)
3. Access Control flaws (SWC-105, SWC-106)
4. Logic errors and incorrect state transitions
5. Flash loan attack surfaces
6. Uninitialized storage pointers (SWC-109)
7. Timestamp manipulation (SWC-116)
8. Front-running / tx.origin misuse (SWC-115)
9. Unchecked return values (SWC-104)
10. Denial of service vectors (SWC-113)

Return ONLY valid JSON: { "findings": [ { "vulnType": "reentrancy|overflow|access-control|logic|flash-loan", "severity": "critical|high|medium|low", "line": <number or null>, "description": "<concise description>", "recommendation": "<fix>" } ] }
If no vulnerabilities found, return { "findings": [] }.`,
          },
          { role: 'user', content: `Scan this Solidity contract:\n\n\`\`\`solidity\n${contractSource}\n\`\`\`` },
        ],
        model: 'llama-3.3-70b-versatile',
        temperature: 0.2,
        max_tokens: 1000,
        response_format: { type: 'json_object' },
      });

      const raw = completion.choices[0]?.message?.content || '{"findings":[]}';
      const parsed = JSON.parse(raw);
      const rawFindings: any[] = Array.isArray(parsed.findings) ? parsed.findings : [];

      // Submit each finding to SecurityRegistry on Somnia → initialises/updates reputation
      const agent = findBestAgentByCategory('security-scanner');
      const contractAddress = params.contractAddress || null;
      const persistedFindings: FindingLog[] = [];

      for (const f of rawFindings) {
        const vulnType  = (f.vulnType  || 'logic').toLowerCase();
        const severity  = (f.severity  || 'medium').toLowerCase() as FindingLog['severity'];
        const rewardSTT = severity === 'critical' ? 0.05 : severity === 'high' ? 0.02 : 0.01;

        const onChainId = await submitFindingOnChain(
          contractAddress || 'source-provided',
          vulnType,
          severity,
          f.description || '',
          agent?.id || 'scanner-agent',
          rewardSTT
        );

        const entry: FindingLog = {
          id: onChainId || `finding_${(++findingIdCounter).toString(36)}`,
          timestamp: Date.now(),
          contractAddress: contractAddress || 'source-provided',
          vulnType,
          severity,
          description: f.description || '',
          scannerAgent: agent?.id || 'scanner-agent',
          confirmed: false,
          rewardSTT,
          txHash: onChainId || txHash || undefined,
        };

        findingLogs.push(entry);
        broadcastSSE('finding', { ...entry, onChainId, line: f.line, recommendation: f.recommendation });
        persistedFindings.push(entry);
      }

      if (agent) {
        agent.totalEarned += PRICES.scanContract.sttAmount;
        // Sync reputation from chain now that findings were submitted
        await syncReputationFromChain(agent.address);
      }

      return { findings: rawFindings, findingLogs: persistedFindings, summary: `Found ${rawFindings.length} vulnerabilities` };
    } catch (err: any) {
      console.error('[runSecurityAgent:scanContract]', err.message);
      return { findings: [], findingLogs: [], summary: 'Scan failed' };
    }
  }

  const systemPrompts: Record<string, string> = {
    validateFinding: 'You are an adversarial smart contract auditor. Independently verify or refute the given vulnerability finding. Be skeptical and evidence-based. Return JSON: { "confirmed": true|false, "confidence": 0-100, "notes": "..." }',
    simulateExploit: 'You are a smart contract exploit developer. Write a complete Foundry PoC test for the given vulnerability. Include setup, attack, and assertion.',
  };

  const userPrompts: Record<string, (p: any, q: string) => string> = {
    validateFinding: (p, _q) => `Validate this finding:\nType: ${p.finding?.vulnType}\nSeverity: ${p.finding?.severity}\nDescription: ${p.finding?.description}`,
    simulateExploit: (p, _q) => `Generate Foundry exploit PoC for:\nType: ${p.finding?.vulnType}\nSeverity: ${p.finding?.severity}\nDescription: ${p.finding?.description}`,
  };

  const systemPrompt = systemPrompts[toolId] || 'You are a smart contract security expert.';
  const userPrompt = userPrompts[toolId] ? userPrompts[toolId](params, query) : `Analyze: ${query}`;

  try {
    const completion = await groq.chat.completions.create({
      messages: [
        { role: 'system', content: systemPrompt },
        { role: 'user', content: userPrompt },
      ],
      model: 'llama-3.3-70b-versatile',
      temperature: 0.3,
      max_tokens: 800,
    });
    return completion.choices[0]?.message?.content || `[${toolId}] Result for: ${query}`;
  } catch {
    return `[${toolId}] Result for: ${query}`;
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// SSE Endpoint
// ═══════════════════════════════════════════════════════════════════════════

app.get('/api/agent/events', (req: Request, res: Response) => {
  const clientId = req.query.clientId as string;
  if (!clientId) { res.status(400).send('Missing clientId'); return; }

  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders();

  sseClients.set(clientId, res);

  const keepAlive = setInterval(() => { res.write(': keep-alive\n\n'); }, 15000);

  req.on('close', () => {
    clearInterval(keepAlive);
    sseClients.delete(clientId);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// Main Agent Query Endpoint
// ═══════════════════════════════════════════════════════════════════════════

app.post('/api/agent/query', async (req: Request, res: Response) => {
  try {
    const { query, clientId, options } = req.body;
    if (!query) {
      res.status(400).json({ error: 'Missing query in request body' });
      return;
    }

    const result = await runManagerAgent(query, clientId, options);
    res.json(result);
  } catch (err) {
    console.error('[AGENT QUERY ERROR]', err);
    res.status(500).json({
      error: 'Agent execution failed',
      message: err instanceof Error ? err.message : String(err),
    });
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// Server Start
// ═══════════════════════════════════════════════════════════════════════════

app.listen(PORT, HOST, async () => {
  console.log(`
╔══════════════════════════════════════════════════════════════╗
║             AUDITY — Smart Contract Security Platform        ║
║                                                              ║
║  Trustless audits. AI agents scan, validate & exploit.      ║
║  Powered by x402 STT payments on Somnia Testnet.            ║
╚══════════════════════════════════════════════════════════════╝

  Server:   http://${HOST}:${PORT}
  Network:  ${NETWORK} (chain ${CHAIN_ID})
  RPC:      ${RPC_HTTP}
  WSS:      ${RPC_WSS}
  Agents:   ${agentRegistry.length} security agents ready
  LLM:      Groq (llama-3.3-70b)
  Registry: ${SECURITY_REGISTRY_ADDRESS  || 'not configured (set SECURITY_REGISTRY_ADDRESS)'}
  Watchlist: ${WATCHLIST_HANDLER_ADDRESS || 'not configured (set WATCHLIST_HANDLER_ADDRESS)'}
`);

  // Start Somnia Reactivity WebSocket subscriptions
  await initReactivitySubscription();   // SecurityRegistry events
  await initWatchlistSubscription();    // WatchlistHandler RescanRequested events

  // Seed all persistent state from Somnia chain (survives server restarts)
  await syncFindingsFromChain();                                          // re-hydrate findingLogs
  await syncReputationFromChain(PLATFORM_ADDRESS);                        // agent reputation scores
  await Promise.all(agentRegistry.map(a => syncHireCountFromChain(a.id))); // hire counts
});
