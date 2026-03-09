// Somnia Testnet — public network config (not a secret, hardcoded intentionally)

export const SOMNIA = {
  chainId:    50312,
  chainName:  'Somnia Testnet',
  rpcHttp:    'https://api.infra.testnet.somnia.network',
  rpcWss:     'wss://api.infra.testnet.somnia.network',
  explorer:   'https://shannon.somnia.network',
  symbol:     'STT',
} as const;

export const explorerTx   = (hash: string)    => `${SOMNIA.explorer}/tx/${hash}`;
export const explorerAddr  = (address: string) => `${SOMNIA.explorer}/address/${address}`;
