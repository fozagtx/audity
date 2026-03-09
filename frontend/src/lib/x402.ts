// x402 Payment Interceptor for Audity — Somnia Testnet (STT)
// When the backend returns HTTP 402, this reads the payment challenge,
// fires MetaMask eth_sendTransaction to pay STT, then retries the original
// request with the tx hash in the x-payment-response header.
import { SOMNIA, SOMNIA_WALLET_CHAIN } from './network';

export interface X402Challenge {
  amount: string;       // e.g. "0.010"
  token: string;        // "STT"
  recipient: string;    // 0x... server address
  chainId: number;      // 50312
  endpoint: string;
}

/**
 * Fetch wrapper that transparently handles HTTP 402 x402 payments.
 * On a 402 response, prompts MetaMask to pay STT, then retries.
 */
export async function fetchWithX402(
  url: string,
  options: RequestInit = {}
): Promise<Response> {
  const firstResponse = await fetch(url, options);

  if (firstResponse.status !== 402) {
    return firstResponse;
  }

  let challenge: X402Challenge;
  try {
    challenge = await firstResponse.json() as X402Challenge;
  } catch {
    throw new Error('x402: Could not parse payment challenge from 402 response');
  }

  if (typeof window === 'undefined' || !(window as any).ethereum) {
    throw new Error('x402: MetaMask not available — cannot pay');
  }

  const ethereum = (window as any).ethereum;

  // Ensure we're on Somnia Testnet
  const currentChain = await ethereum.request({ method: 'eth_chainId' });
  if (currentChain.toLowerCase() !== SOMNIA.chainIdHex.toLowerCase()) {
    try {
      await ethereum.request({
        method: 'wallet_switchEthereumChain',
        params: [{ chainId: SOMNIA.chainIdHex }],
      });
    } catch {
      await ethereum.request({
        method: 'wallet_addEthereumChain',
        params: [SOMNIA_WALLET_CHAIN],
      });
    }
  }

  // Convert STT amount to wei (hex)
  const amountFloat = parseFloat(challenge.amount || '0');
  const amountWei = BigInt(Math.round(amountFloat * 1e18));
  const valueHex = '0x' + amountWei.toString(16);

  const txHash: string = await ethereum.request({
    method: 'eth_sendTransaction',
    params: [{
      to: challenge.recipient,
      value: valueHex,
      chainId: SOMNIA.chainIdHex,
    }],
  });

  if (!txHash) {
    throw new Error('x402: MetaMask returned no tx hash — payment may have been rejected');
  }

  return fetch(url, {
    ...options,
    headers: {
      ...(options.headers || {}),
      'x-payment-response': txHash,
    },
  });
}
