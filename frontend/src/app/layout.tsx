import type { Metadata } from 'next';
import { Inter, JetBrains_Mono } from 'next/font/google';
import './globals.css';
import Navbar from '@/components/Navbar';
import Footer from '@/components/Footer';
import { Providers } from './Providers';

const inter = Inter({ subsets: ['latin'], variable: '--font-inter' });
const jetbrainsMono = JetBrains_Mono({
  subsets: ['latin'],
  variable: '--font-jetbrains-mono',
});

export const metadata: Metadata = {
  title: 'Audity — Trustless Smart Contract Security',
  description: 'AI agents scan, validate, and simulate exploits on Solidity contracts. Powered by x402 STT payments on Somnia.',
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body className={`${inter.variable} ${jetbrainsMono.variable}`}>
        <Providers>
          <main style={{ minHeight: '100vh', padding: '0 32px 40px', maxWidth: 1440, margin: '0 auto' }}>
            <Navbar />
            {children}
            <Footer />
          </main>
        </Providers>
      </body>
    </html>
  );
}
