export type Language = 'en';

export const translations = {
  en: {
    // Navbar
    dashboard: 'Dashboard',
    agents: 'Agents',
    tools: 'Tools',
    // AgentChat
    managerAgent: 'Security Agent',
    placeholder: 'Paste contract source or enter 0x address...',
    thinking: 'Scanning...',
    // TransactionLog
    transactions: 'Payments',
    total: 'total',
    a2a: 'A2A',
    emptyTransactions: 'No payments yet. Submit a contract to get started.',
    depth: 'depth',
    flashSwap: 'Flash Swap',
    swapAmount: 'Swap amount',
    reason: 'Reason',
    viewExplorer: 'View on Explorer →',
    // ToolCatalog
    loadingAgents: 'Loading agents...',
    availableAgents: 'Available Agents',
    globalNetwork: 'Global Network',
    // Dashboard
    monitorTitle: 'SECURITY',
    monitorLabel: 'MONITOR',
    // Agents page
    marketplaceTitle: 'Agent Marketplace',
    marketplaceSubtitle: 'Discover and hire specialized AI security agents. Pay per scan with STT micropayments on the Somnia network.',
    sortBy: 'Sort by',
    rep: 'Reputation',
    efficiency: 'Efficiency',
    price: 'Price',
    totalAgents: 'Total Agents',
    networkActive: 'Network Active',
    avgReputation: 'Avg Reputation',
    totalJobs: 'Total Jobs',
    online: 'ONLINE',
    offline: 'OFFLINE',
    jobsCompleted: 'Jobs completed',
    reliability: 'Reliability',
    hireAgent: 'Hire Agent',
    connectionError: 'Unable to connect to Agent Registry',
    // ProtocolTrace
    techTrace: 'TECH TRACE',
    hiringLog: 'HIRING LOG',
    emptyProtocol: 'No protocol traces yet. Submit a contract to see the x402 payment flow.',
    emptyHiring: 'No hiring decisions yet. The security manager will log selections here.',
    // VulnerabilityFeed
    findings: 'Findings',
    emptyFindings: 'No findings yet. Submit a contract to scan for vulnerabilities.',
    confirmed: 'CONFIRMED',
    unconfirmed: 'UNCONFIRMED',
    critical: 'CRITICAL',
    high: 'HIGH',
    medium: 'MEDIUM',
    low: 'LOW',
  },
};

export type Translations = typeof translations.en;
