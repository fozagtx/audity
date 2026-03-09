# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**Audity** is a trustless smart contract security platform — a full-stack monorepo where AI agents scan, validate, and simulate exploits against Solidity contracts. Uses the **x402 HTTP 402 micropayment protocol** on the **Somnia Testnet** (STT).

## Commands

### Root (runs all workspaces)
```bash
bun run install:all     # Install all workspace dependencies
bun run dev             # Run backend + frontend concurrently
bun run dev:backend     # Backend only (port 4002)
bun run dev:frontend    # Frontend only (port 3000)
```

### Backend (`cd backend`)
```bash
bun run dev     # tsx watch with hot reload
bun run build   # tsc compilation
bun start       # Run compiled dist
```

### Frontend (`cd frontend`)
```bash
bun run dev     # Next.js dev server
bun run build   # Production build
bun run lint    # ESLint
```

## Architecture

### Monorepo Structure
- `backend/` — Express.js server (port 4002), TypeScript
- `frontend/` — Next.js + React dashboard (port 3000)
- `contracts/` — Solidity smart contracts (`AgentRegistry.sol`, `SecurityRegistry.sol`)

### Request Flow
1. User pastes contract source or address via `AgentChat.tsx` (frontend)
2. `POST /api/agent/query` → Backend Manager Agent
3. Manager LLM (Groq) routes to the best security agent
4. Backend wraps worker calls with x402 payment middleware (HTTP 402 → STT payment → 200)
5. Results stream back to frontend via SSE (`GET /api/agent/events`)
6. `EconomyGraph.tsx` visualizes payment topology via Canvas API in real-time
7. `VulnerabilityFeed.tsx` streams live finding events

### Backend (`backend/src/index.ts`)
Single file containing:
- Express app + middleware setup
- Custom STT x402 payment middleware (HTTP 402 challenge, STT verification)
- Manager Agent orchestration logic with Groq LLM integration
- 3 paid security agent endpoints (see table below)
- FindingLog in-memory store (mirrors paymentLogs pattern)
- Free endpoints: `/api/tools`, `/api/registry`, `/api/payments`, `/api/findings`, `/api/stats`, `/api/agent/events` (SSE)
- `universal-adapter.ts` provides chain RPC adapters for contract bytecode fetching

### Security Agents

| Agent | Endpoint | Price (STT) | Description |
|-------|----------|-------------|-------------|
| Scanner Agent | POST /api/scan-contract | 0.010 STT | Detect top-10 Solidity vulnerabilities |
| Validator Agent | POST /api/validate-finding | 0.005 STT | Adversarial finding confirmation |
| Exploit Sim Agent | POST /api/simulate-exploit | 0.020 STT | Foundry/Hardhat PoC exploit generation |

### Manager Intent Routing
- `scan` / `audit` / `check contract` → `scanContract`
- `validate` / `confirm finding` / `verify` → `validateFinding`
- `simulate` / `exploit` / `poc` → `simulateExploit`
- `audit-full` / `full audit` → chains scan → validate each finding → simulate criticals

### Smart Contracts (`contracts/`)
- `AgentRegistry.sol` — Agent registration, job lifecycle, reputation scoring, STT escrow
- `SecurityRegistry.sol` (Phase 2) — Finding submission, on-chain confirmation, $BUG reward

### Frontend (`frontend/src/`)
- App Router pages: `/` (dashboard), `/agents`, `/tools`, `/docs`
- Key components: `AgentChat.tsx` (SSE streaming), `EconomyGraph.tsx` (Canvas topology), `ProtocolTrace.tsx` (raw 402 headers), `TransactionLog.tsx`, `VulnerabilityFeed.tsx`
- EVM wallet connect via `ConnectWalletButton.tsx` (MetaMask + Somnia testnet)

## Environment Variables

**Backend** (copy `backend/.env.example`):
- `PORT=4002`, `HOST=0.0.0.0`
- `NETWORK=somnia-testnet`, `CHAIN_ID=50312`
- `RPC_URL=https://dream-rpc.somnia.network`
- `SERVER_ADDRESS` — EVM address receiving payments (0x... format)
- `GROQ_API_KEY`

**Frontend**:
- `NEXT_PUBLIC_API_URL` — Backend URL
- `NEXT_PUBLIC_SERVER_ADDRESS` — EVM address for WalletInfo display

## Somnia Testnet Config
- Chain ID: `50312`
- RPC: `https://dream-rpc.somnia.network`
- Explorer: `https://shannon-explorer.somnia.network`
- Native token: STT
- Wallet: MetaMask (any EVM-compatible wallet)

## Key Patterns

- **x402 Protocol**: HTTP 402 payment-required gates all paid endpoints; middleware returns STT payment challenge, then forwards to handler
- **LLM**: Groq (`llama-3.3-70b`) for all planning and agent calls
- **Security Focus**: All agents are specialized for Solidity vulnerability detection — scanner → validator → exploit sim pipeline
- **FindingLog**: In-memory store of all discovered vulnerabilities, broadcast via SSE `finding` event
- **localStorage key**: `audity_client_id`
- **Simulation mode**: Set `SIMULATION_MODE=true` to bypass STT payment requirement
