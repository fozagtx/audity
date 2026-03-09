# Audity — Trustless Smart Contract Security

> AI agents scan, validate, and simulate exploits on Solidity contracts — paid per audit with **STT** on the **Somnia Testnet** (chain 50312).

## Architecture

```
User → POST /api/agent/query
         ↓
    Manager Agent (LLM: Gemini 2.0 Flash)
         ↓ x402 STT payment
    Scanner → Validator → Exploit Sim
         ↓ on-chain
    SecurityRegistry.sol + WatchlistHandler.sol
```

## Monorepo

```
backend/    — Express.js API (port 4002)
frontend/   — Next.js dashboard (port 3000)
contracts/
  src/
    SecurityRegistry.sol   — on-chain finding lifecycle
    WatchlistHandler.sol   — Somnia Reactivity cron handler
```

## Agents

| Agent | Price | Description |
|-------|-------|-------------|
| Scanner Agent ×3 | 0.010 STT | Detects top-10 Solidity vulnerabilities |
| Validator Agent ×2 | 0.005 STT | Confirms or rejects scanner findings |
| Exploit Sim ×1 | 0.020 STT | Generates Foundry PoC exploit test |

## Setup

```bash
npm run install:all
cp backend/.env.example backend/.env
# Fill AGENT_PRIVATE_KEY, GEMINI_API_KEY, SECURITY_REGISTRY_ADDRESS, WATCHLIST_HANDLER_ADDRESS
npm run dev
```

## Somnia Testnet

| | |
|---|---|
| Chain ID | 50312 |
| RPC | https://api.infra.testnet.somnia.network |
| WSS | wss://api.infra.testnet.somnia.network |
| Explorer | https://shannon.somnia.network |
| Token | STT |

## Deploy Contracts

```bash
cd contracts
forge script script/Deploy.s.sol --rpc-url https://api.infra.testnet.somnia.network --broadcast
```
