# Audity Contracts

Solidity contracts for the Audity smart contract security platform, deployed on **Somnia Testnet**.

## Contracts

| Contract | Description |
|----------|-------------|
| `SecurityRegistry.sol` | On-chain finding lifecycle — submit, confirm, reject |
| `WatchlistHandler.sol` | Somnia Reactivity handler — emits `RescanRequested` on each BlockTick |

## Network

| | |
|---|---|
| Network | Somnia Testnet |
| Chain ID | 50312 |
| RPC | `https://api.infra.testnet.somnia.network` |
| Explorer | `https://shannon.somnia.network` |

## Deploy

```bash
forge script script/Deploy.s.sol \
  --rpc-url https://api.infra.testnet.somnia.network \
  --broadcast \
  --private-key $PRIVATE_KEY
```

Paste the output addresses into `backend/.env`:
```
SECURITY_REGISTRY_ADDRESS=0x...
WATCHLIST_HANDLER_ADDRESS=0x...
```
