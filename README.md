# Audity — Trustless Smart Contract Security

> AI agents scan, validate, and simulate exploits on Solidity contracts — paid per audit with **STT** on the **Somnia Testnet** (chain 50312).

## Deployed Contracts (Somnia Testnet)

| Contract | Address | Explorer |
|----------|---------|----------|
| SecurityRegistry | `0x542A1352b7a62f1D2EF320DC1353f6ECbB1Be4dB` | [View](https://shannon-explorer.somnia.network/address/0x542A1352b7a62f1D2EF320DC1353f6ECbB1Be4dB) |
| WatchlistHandler | `0x32A69a587488EB9664A7F7E6f6a6a2B33657446A` | [View](https://shannon-explorer.somnia.network/address/0x32A69a587488EB9664A7F7E6f6a6a2B33657446A) |

## Architecture

```
User → POST /api/agent/query
         ↓
    Manager Agent (LLM: Groq llama-3.3-70b)
         ↓ x402 STT payment
    Scanner → Validator → Exploit Sim
         ↓ on-chain (Somnia Reactivity)
    SecurityRegistry.sol + WatchlistHandler.sol
```

## Monorepo

```
backend/    — Express.js API (port 4002)
frontend/   — Next.js dashboard (port 3000)
contracts/
  src/
    SecurityRegistry.sol   — findings lifecycle, hire counts, reputation
    WatchlistHandler.sol   — Somnia Reactivity cron handler
```

## Agents

| Agent | Price | Description |
|-------|-------|-------------|
| Scanner Agent | 0.010 STT | Detects top-10 Solidity vulnerabilities |
| Validator Agent | 0.005 STT | Confirms or rejects scanner findings |
| Exploit Sim Agent | 0.020 STT | Generates Foundry PoC exploit test |

## Setup

```bash
bun run install:all
# Create backend/.env with:
#   AGENT_PRIVATE_KEY=<your_private_key>
#   GROQ_API_KEY=<your_groq_key>
bun run dev
```

## Somnia Testnet

| | |
|---|---|
| Chain ID | 50312 |
| RPC | https://api.infra.testnet.somnia.network |
| WSS | wss://api.infra.testnet.somnia.network |
| Explorer | https://shannon-explorer.somnia.network |
| Token | STT |
