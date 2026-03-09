// EVM wallet session utilities for Audity (Somnia Testnet)
import { SOMNIA_WALLET_CHAIN } from './network';

export { SOMNIA_WALLET_CHAIN as SOMNIA_TESTNET };

export function isMetaMaskAvailable(): boolean {
  return typeof window !== 'undefined' && typeof (window as any).ethereum !== 'undefined';
}

export async function connectMetaMask(): Promise<string | null> {
  if (!isMetaMaskAvailable()) return null;
  try {
    const accounts = await (window as any).ethereum.request({ method: 'eth_requestAccounts' });
    return accounts[0] || null;
  } catch {
    return null;
  }
}

export async function addSomniaTestnet(): Promise<void> {
  if (!isMetaMaskAvailable()) return;
  try {
    await (window as any).ethereum.request({
      method: 'wallet_addEthereumChain',
      params: [SOMNIA_WALLET_CHAIN],
    });
  } catch {
    // Already added or user rejected
  }
}

export async function getConnectedAccount(): Promise<string | null> {
  if (!isMetaMaskAvailable()) return null;
  try {
    const accounts = await (window as any).ethereum.request({ method: 'eth_accounts' });
    return accounts[0] || null;
  } catch {
    return null;
  }
}

export async function disconnectWallet(): Promise<void> {
  // MetaMask doesn't support programmatic disconnect — just clear local state
}
