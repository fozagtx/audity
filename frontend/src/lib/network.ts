// Somnia Testnet — public network config (not a secret, hardcoded intentionally)

export const SOMNIA = {
  chainId:        50312,
  chainIdHex:     '0xC478',
  chainName:      'Somnia Testnet',
  rpc:            'https://api.infra.testnet.somnia.network',
  wss:            'wss://api.infra.testnet.somnia.network',
  explorer:       'https://shannon.somnia.network',
  nativeCurrency: { name: 'STT', symbol: 'STT', decimals: 18 },
} as const;

/** MetaMask wallet_addEthereumChain params shape */
export const SOMNIA_WALLET_CHAIN = {
  chainId:             SOMNIA.chainIdHex,
  chainName:           SOMNIA.chainName,
  nativeCurrency:      SOMNIA.nativeCurrency,
  rpcUrls:             [SOMNIA.rpc],
  blockExplorerUrls:   [SOMNIA.explorer],
} as const;

export const explorerTx  = (hash: string)    => `${SOMNIA.explorer}/tx/${hash}`;
export const explorerAddr = (address: string) => `${SOMNIA.explorer}/address/${address}`;
