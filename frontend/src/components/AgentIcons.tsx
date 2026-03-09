import { Shield, CheckCircle, Swords, Cpu, Zap, type LucideIcon } from 'lucide-react';

export const AgentIconMap: Record<string, LucideIcon> = {
  // kebab-case agent IDs
  'scanner-agent':          Shield,
  'validator-agent':        CheckCircle,
  'exploit-sim-agent':      Swords,
  manager:                  Cpu,
  // category names
  'security-scanner':       Shield,
  'security-validator':     CheckCircle,
  'security-exploit':       Swords,
  // camelCase tool IDs (from /api/tools)
  scanContract:             Shield,
  validateFinding:          CheckCircle,
  simulateExploit:          Swords,
};

export const getAgentIcon = (id: string): LucideIcon => {
  const baseId = id.toLowerCase();
  return AgentIconMap[baseId] || Zap;
};

export const AgentColors: Record<string, string> = {
  // kebab-case
  'scanner-agent':          '#6EE7B7',
  'validator-agent':        '#60A5FA',
  'exploit-sim-agent':      '#F87171',
  manager:                  '#6EE7B7',
  // category
  'security-scanner':       '#6EE7B7',
  'security-validator':     '#60A5FA',
  'security-exploit':       '#F87171',
  // camelCase
  scanContract:             '#6EE7B7',
  validateFinding:          '#60A5FA',
  simulateExploit:          '#F87171',
};

export const getAgentColor = (id: string) => {
  const baseId = id.toLowerCase();
  return AgentColors[baseId] || '#64748b';
};
