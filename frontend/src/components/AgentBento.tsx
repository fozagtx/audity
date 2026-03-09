'use client';

import React, { useState, useRef, useMemo, useEffect } from 'react';
import { Shield, CheckCircle, Swords, Rocket, Activity } from 'lucide-react';
import { SOMNIA } from '@/lib/network';

const API = (process.env.NEXT_PUBLIC_API_URL || 'http://localhost:4002').replace(/\/$/, '');

// ─── Category → visual mapping ────────────────────────────────────────────────

const CATEGORY_META: Record<string, { icon: React.ElementType; color: string; label: string }> = {
  'security-scanner':   { icon: Shield,       color: '#6EE7B7', label: 'SCANNER'   },
  'security-validator': { icon: CheckCircle,  color: '#60A5FA', label: 'VALIDATOR' },
  'security-exploit':   { icon: Swords,       color: '#F87171', label: 'EXPLOIT'   },
};

// ─── Main activity chart ──────────────────────────────────────────────────────

const WEEK = ['MON', 'TUE', 'WED', 'THU', 'FRI', 'SAT', 'SUN'];
// day index: 0=Sun,1=Mon,...,6=Sat → remap to MON=0..SUN=6
const JS_DAY_TO_WEEK_IDX = [6, 0, 1, 2, 3, 4, 5];

function buildWaveY(payments: { timestamp: string | number }[]): number[] {
  const counts = [0, 0, 0, 0, 0, 0, 0];
  for (const p of payments) {
    const ts = typeof p.timestamp === 'number' ? p.timestamp : Date.parse(p.timestamp as string);
    if (!isNaN(ts)) {
      const day = new Date(ts).getDay(); // 0=Sun
      counts[JS_DAY_TO_WEEK_IDX[day]]++;
    }
  }
  const max = Math.max(...counts, 1);
  // Map counts → y pixel range [20, 80] (lower y = higher on SVG)
  return counts.map(c => 80 - Math.round((c / max) * 60));
}

function ActivityChart({
  onDeploy,
  connecting,
  waveY,
  agentCount,
}: {
  onDeploy: () => void;
  connecting: boolean;
  waveY: number[];
  agentCount: number;
}) {
  const [hovered, setHovered] = useState<number | null>(null);
  const svgRef = useRef<SVGSVGElement>(null);

  const W = 320, H = 100;
  const PAD = { top: 12, bottom: 20, left: 4, right: 4 };

  const getX = (i: number) => PAD.left + (i / (WEEK.length - 1)) * (W - PAD.left - PAD.right);
  const points = WEEK.map((_, i) => ({ x: getX(i), y: waveY[i] ?? 60 }));

  const linePath = points.reduce((acc, pt, i) => {
    if (i === 0) return `M${pt.x},${pt.y}`;
    const p = points[i - 1];
    const cpx = (p.x + pt.x) / 2;
    return `${acc} C${cpx},${p.y} ${cpx},${pt.y} ${pt.x},${pt.y}`;
  }, '');

  const areaPath = `${linePath} L${getX(WEEK.length - 1)},${H - PAD.bottom} L${getX(0)},${H - PAD.bottom} Z`;

  // Scatter dots seeded from points so they don't randomize on every render
  const scatterDots = useMemo(() => points.flatMap((pt, i) => [
    { x: pt.x - 8,  y: pt.y - 6,  r: 1.2, o: 0.18 },
    { x: pt.x + 10, y: pt.y + 5,  r: 1.0, o: 0.14 },
    { x: pt.x + 4,  y: pt.y - 10, r: 1.5, o: 0.20 },
  ].map(d => ({ ...d, key: `${i}-${d.x}` }))), []);

  const onMouseMove = (e: React.MouseEvent<SVGSVGElement>) => {
    if (!svgRef.current) return;
    const rect = svgRef.current.getBoundingClientRect();
    const relX = ((e.clientX - rect.left) / rect.width) * W;
    let closest = 0, minD = Infinity;
    WEEK.forEach((_, i) => { const d = Math.abs(getX(i) - relX); if (d < minD) { minD = d; closest = i; } });
    setHovered(closest);
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      {/* Top row */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 12 }}>
        <div>
          <div className="mono" style={{ fontSize: '0.65rem', color: '#6B7280', letterSpacing: '0.1em', marginBottom: 6 }}>YOUR AI SECURITY TEAM</div>
          <div className="mono" style={{ fontSize: '1.5rem', fontWeight: 900, color: '#FFFFFF', letterSpacing: '-0.04em', lineHeight: 1 }}>
            {agentCount} Agent{agentCount !== 1 ? 's' : ''} Ready
          </div>
          <div className="mono" style={{ fontSize: '0.65rem', color: '#9CA3AF', marginTop: 6 }}>
            Connect wallet to deploy
          </div>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '4px 10px', border: '1px solid rgba(110,231,183,0.25)', background: 'rgba(110,231,183,0.06)' }}>
          <div style={{ width: 6, height: 6, borderRadius: '50%', background: '#6EE7B7', animation: 'bentoPulse 1.5s infinite' }} />
          <span className="mono" style={{ fontSize: '0.6rem', color: '#6EE7B7', fontWeight: 700 }}>STANDBY</span>
        </div>
      </div>

      {/* Activity chart — sourced from real payment timestamps */}
      <div style={{ flex: 1 }}>
        <svg
          ref={svgRef}
          viewBox={`0 0 ${W} ${H}`}
          style={{ width: '100%', cursor: 'crosshair' }}
          onMouseMove={onMouseMove}
          onMouseLeave={() => setHovered(null)}
        >
          <defs>
            <linearGradient id="bentoArea" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#6EE7B7" stopOpacity="0.2" />
              <stop offset="100%" stopColor="#6EE7B7" stopOpacity="0.01" />
            </linearGradient>
          </defs>

          {WEEK.map((_, i) => (
            <line key={i} x1={getX(i)} y1={PAD.top} x2={getX(i)} y2={H - PAD.bottom}
              stroke="rgba(110,231,183,0.07)" strokeWidth="1" strokeDasharray="3 4"
              opacity={hovered === i ? 0.6 : 0.3} />
          ))}

          {scatterDots.map(d => (
            <circle key={d.key} cx={d.x} cy={d.y} r={d.r} fill="#6EE7B7" opacity={d.o} />
          ))}

          <path d={areaPath} fill="url(#bentoArea)" />
          <path d={linePath} fill="none" stroke="#6EE7B7" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" opacity="0.7" />

          {hovered !== null && (
            <g>
              <circle cx={points[hovered].x} cy={points[hovered].y} r={7} fill="rgba(110,231,183,0.12)" />
              <circle cx={points[hovered].x} cy={points[hovered].y} r={3.5} fill="#0A0A0A" stroke="#6EE7B7" strokeWidth="2" />
            </g>
          )}

          {WEEK.map((d, i) => (
            <text key={i} x={getX(i)} y={H - 4} textAnchor="middle"
              style={{ fontSize: 8, fill: hovered === i ? '#6EE7B7' : '#374151', fontFamily: 'var(--font-mono)', fontWeight: 700 }}>
              {d}
            </text>
          ))}
        </svg>
      </div>

      {/* CTA */}
      <button
        onClick={onDeploy}
        disabled={connecting}
        style={{ width: '100%', padding: '11px', background: '#6EE7B7', color: '#0A0A0A', border: 'none', cursor: connecting ? 'wait' : 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8, fontFamily: 'var(--font-mono)', fontWeight: 800, fontSize: '0.85rem', letterSpacing: '0.06em', transition: 'all 0.2s', opacity: connecting ? 0.7 : 1, marginTop: 12 }}
        onMouseEnter={e => { if (!connecting) (e.currentTarget as HTMLElement).style.filter = 'brightness(1.1)'; }}
        onMouseLeave={e => { (e.currentTarget as HTMLElement).style.filter = 'brightness(1)'; }}
      >
        <Rocket size={14} />
        {connecting ? 'CONNECTING...' : 'START AUDIT'}
      </button>
    </div>
  );
}

// ─── Agent Card ───────────────────────────────────────────────────────────────

interface LiveAgent {
  id: string;
  name: string;
  category: string;
  priceSTT: number;
  reputation: number;
}

function AgentCard({ agent }: { agent: LiveAgent }) {
  const [hovered, setHovered] = useState(false);
  const meta = CATEGORY_META[agent.category] ?? { icon: Shield, color: '#9CA3AF', label: agent.category.toUpperCase() };
  const Icon = meta.icon;

  return (
    <div
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      style={{
        background: hovered ? '#161616' : '#111111',
        border: `1px solid ${hovered ? meta.color + '40' : 'rgba(255,255,255,0.06)'}`,
        padding: '18px',
        display: 'flex',
        flexDirection: 'column',
        justifyContent: 'space-between',
        gap: 16,
        transition: 'all 0.2s ease',
        cursor: 'default',
        boxShadow: hovered ? `0 0 20px ${meta.color}0D` : 'none',
      }}
    >
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <div style={{ width: 32, height: 32, background: `${meta.color}14`, border: `1px solid ${meta.color}30`, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
          <Icon size={15} color={hovered ? meta.color : '#6B7280'} />
        </div>
        <span className="mono" style={{ fontSize: '0.55rem', color: hovered ? meta.color : '#4B5563', fontWeight: 700, letterSpacing: '0.08em', transition: 'color 0.2s' }}>
          {meta.label}
        </span>
      </div>

      <div>
        <div className="mono" style={{ fontSize: '0.72rem', fontWeight: 800, color: hovered ? '#FFFFFF' : '#9CA3AF', textTransform: 'uppercase', lineHeight: 1.3, transition: 'color 0.2s', marginBottom: 4 }}>
          {agent.name}
        </div>
        <div className="mono" style={{ fontSize: '0.6rem', color: '#4B5563', fontWeight: 700, marginBottom: 2 }}>
          {agent.priceSTT} STT / scan
        </div>
        <div className="mono" style={{ fontSize: '0.55rem', color: hovered ? meta.color : '#374151', transition: 'color 0.2s' }}>
          REP {agent.reputation}/100
        </div>
      </div>
    </div>
  );
}

// ─── Bento Grid ───────────────────────────────────────────────────────────────

export default function AgentBento({ onDeploy, connecting }: { onDeploy: () => void; connecting: boolean }) {
  const [agents, setAgents] = useState<LiveAgent[]>([]);
  const [waveY, setWaveY] = useState<number[]>([60, 60, 60, 60, 60, 60, 60]);

  // Fetch registry + payments on mount
  useEffect(() => {
    fetch(`${API}/api/registry`)
      .then(r => r.json())
      .then(data => { if (Array.isArray(data.agents)) setAgents(data.agents); })
      .catch(() => {});

    fetch(`${API}/api/payments`)
      .then(r => r.json())
      .then(data => { if (Array.isArray(data.payments)) setWaveY(buildWaveY(data.payments)); })
      .catch(() => {});
  }, []);

  // SSE: live reputation + payment updates
  useEffect(() => {
    const sse = new EventSource(`${API}/api/agent/events`);

    sse.addEventListener('agent_reputation_update', (e) => {
      try {
        const { scannerAddress, reputation } = JSON.parse((e as MessageEvent).data);
        setAgents(prev => prev.map(a =>
          a.id?.toLowerCase() === scannerAddress?.toLowerCase() ||
          (a as any).address?.toLowerCase() === scannerAddress?.toLowerCase()
            ? { ...a, reputation }
            : a
        ));
      } catch {}
    });

    sse.addEventListener('payment', (e) => {
      // Re-fetch payments to recompute activity chart
      fetch(`${API}/api/payments`)
        .then(r => r.json())
        .then(data => { if (Array.isArray(data.payments)) setWaveY(buildWaveY(data.payments)); })
        .catch(() => {});
    });

    return () => sse.close();
  }, []);

  // Show up to 6 agent cards (grid layout is fixed to 6 slots)
  const displayed = agents.slice(0, 6);
  // Pad with nulls if fewer than 6 so grid doesn't collapse
  const slots: (LiveAgent | null)[] = [...displayed, ...Array(Math.max(0, 6 - displayed.length)).fill(null)];

  return (
    <div style={{ width: '100%', maxWidth: 760 }}>
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(3, 1fr)',
        gridTemplateRows: 'auto auto auto',
        gap: 8,
      }}>
        {/* Hero chart card — spans 2 cols, 2 rows */}
        <div style={{
          gridColumn: 'span 2',
          gridRow: 'span 2',
          background: '#0D0D0D',
          border: '1px solid rgba(110,231,183,0.2)',
          padding: '24px',
          boxShadow: '0 0 40px rgba(110,231,183,0.05)',
        }}>
          <ActivityChart onDeploy={onDeploy} connecting={connecting} waveY={waveY} agentCount={agents.length} />
        </div>

        {/* Agents 0 and 1 go in right col */}
        {slots[0] && <AgentCard agent={slots[0]} />}
        {slots[1] && <AgentCard agent={slots[1]} />}

        {/* Row 2: 3 agent cards */}
        {slots[2] && <AgentCard agent={slots[2]} />}
        {slots[3] && <AgentCard agent={slots[3]} />}
        {slots[4] && <AgentCard agent={slots[4]} />}

        {/* Row 3: last agent + stat blocks */}
        {slots[5] && <AgentCard agent={slots[5]} />}

        {/* Exploit warning */}
        <div style={{ background: '#0D0D0D', border: '1px solid rgba(248,113,113,0.15)', padding: '18px', display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
          <div className="mono" style={{ fontSize: '0.6rem', color: '#4B5563', letterSpacing: '0.1em' }}>CAPABILITY</div>
          <div>
            <div className="mono" style={{ fontSize: '0.75rem', fontWeight: 800, color: '#F87171' }}>POC EXPLOIT</div>
            <div className="mono" style={{ fontSize: '0.65rem', color: '#374151', marginTop: 2 }}>Foundry test gen</div>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <Activity size={10} color="#F87171" />
            <span className="mono" style={{ fontSize: '0.6rem', color: '#F87171', fontWeight: 700 }}>HIGH RISK SIM</span>
          </div>
        </div>

        {/* Network info */}
        <div style={{ background: '#0D0D0D', border: '1px solid rgba(255,255,255,0.04)', padding: '18px', display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
          <div className="mono" style={{ fontSize: '0.6rem', color: '#4B5563', letterSpacing: '0.1em' }}>NETWORK</div>
          <div>
            <div className="mono" style={{ fontSize: '0.75rem', fontWeight: 800, color: '#6B7280' }}>{SOMNIA.chainName.toUpperCase()}</div>
            <div className="mono" style={{ fontSize: '0.65rem', color: '#374151', marginTop: 2 }}>CHAIN {SOMNIA.chainId}</div>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <div style={{ width: 5, height: 5, borderRadius: '50%', background: '#6EE7B7', animation: 'bentoPulse 2s infinite' }} />
            <span className="mono" style={{ fontSize: '0.6rem', color: '#6EE7B7', fontWeight: 700 }}>TESTNET LIVE</span>
          </div>
        </div>
      </div>

      <style jsx>{`
        @keyframes bentoPulse {
          0%, 100% { opacity: 1; transform: scale(1); }
          50% { opacity: 0.5; transform: scale(1.2); }
        }
      `}</style>
    </div>
  );
}
