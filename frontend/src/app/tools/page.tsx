'use client';

import React, { useState, useEffect } from 'react';
import { useRequireWallet } from '@/lib/useRequireWallet';

const API = (process.env.NEXT_PUBLIC_API_URL || 'http://localhost:4002').replace(/\/$/, '');

interface Tool {
  id: string;
  name: string;
  category: string;
  description: string;
  price: { STT?: number };
  endpoint: string;
  jobsCompleted: number;
  reputation: number;
  isExternal?: boolean;
}

export default function ToolsPage() {
  useRequireWallet();
  const [selectedCategory, setSelectedCategory] = useState('All');
  const [tools, setTools] = useState<Tool[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch(`${API}/api/tools`)
      .then(res => res.json())
      .then(data => { setTools(data); setLoading(false); })
      .catch(() => setLoading(false));
  }, []);

  // Live SSE updates — re-fetch tools when Somnia chain emits reputation/hire events
  useEffect(() => {
    const refetch = () => {
      fetch(`${API}/api/tools`)
        .then(res => res.json())
        .then(data => setTools(data))
        .catch(() => {});
    };

    const sse = new EventSource(`${API}/api/agent/events`);
    sse.addEventListener('agent_reputation_update', refetch);
    sse.addEventListener('agent_hired_update', refetch);

    return () => sse.close();
  }, []);

  const categories = ['All', ...Array.from(new Set(tools.map(t => t.category.charAt(0).toUpperCase() + t.category.slice(1))))];

  const filteredTools = selectedCategory === 'All'
    ? tools
    : tools.filter(t => t.category.toLowerCase() === selectedCategory.toLowerCase());

  return (
    <div style={{ padding: '40px 0' }}>
      <div style={{ marginBottom: 40 }}>
        <h1 className="mono" style={{ fontSize: '2.5rem', fontWeight: 800, marginBottom: 12, color: '#FFFFFF' }}>
          Tool Catalog
        </h1>
        <p style={{ fontSize: '1.1rem', color: '#9CA3AF', maxWidth: 700 }}>
          AI-powered security tools for auditing Solidity contracts — pay per scan with STT micropayments on Somnia.
        </p>
      </div>

      {/* Category Filter */}
      <div style={{ display: 'flex', gap: 12, marginBottom: 40, flexWrap: 'wrap' }}>
        {categories.map((category) => (
          <button
            key={category}
            className="mono"
            onClick={() => setSelectedCategory(category)}
            style={{
              padding: '10px 20px',
              borderRadius: 'var(--radius-sm)',
              border: selectedCategory === category
                ? '1px solid rgba(110, 231, 183, 0.4)'
                : '1px solid rgba(110, 231, 183, 0.15)',
              backgroundColor: selectedCategory === category ? '#6EE7B7' : 'transparent',
              color: selectedCategory === category ? '#0A0A0A' : '#9CA3AF',
              fontSize: '0.85rem',
              fontWeight: 600,
              cursor: 'pointer',
              transition: 'all 0.2s ease',
              boxShadow: selectedCategory === category ? '0 0 20px rgba(110, 231, 183, 0.15)' : 'none',
            }}
            onMouseEnter={(e) => {
              if (selectedCategory !== category) {
                e.currentTarget.style.borderColor = 'rgba(110, 231, 183, 0.4)';
                e.currentTarget.style.color = '#6EE7B7';
              }
            }}
            onMouseLeave={(e) => {
              if (selectedCategory !== category) {
                e.currentTarget.style.borderColor = 'rgba(110, 231, 183, 0.15)';
                e.currentTarget.style.color = '#9CA3AF';
              }
            }}
          >
            {category}
          </button>
        ))}
      </div>

      {loading && (
        <div className="mono" style={{ color: '#9CA3AF', padding: '60px 0', textAlign: 'center' }}>
          Loading tools...
        </div>
      )}

      {/* Tools List */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
        {filteredTools.map((tool) => (
          <div
            key={tool.id}
            className="glass-panel"
            style={{
              padding: 24,
              display: 'grid',
              gridTemplateColumns: '1fr auto',
              gap: 24,
              alignItems: 'center',
              transition: 'all 0.2s ease',
            }}
            onMouseEnter={(e) => { e.currentTarget.style.borderColor = 'rgba(110, 231, 183, 0.4)'; }}
            onMouseLeave={(e) => { e.currentTarget.style.borderColor = 'rgba(110, 231, 183, 0.15)'; }}
          >
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 8 }}>
                <h3 className="mono" style={{ fontSize: '1.3rem', fontWeight: 700, color: '#FFFFFF' }}>
                  {tool.name}
                </h3>
                <span className="badge" style={{
                  backgroundColor: 'rgba(34, 211, 238, 0.1)',
                  color: '#22d3ee',
                  border: '1px solid rgba(34, 211, 238, 0.3)',
                }}>
                  {tool.category}
                </span>
                {tool.isExternal && (
                  <span className="badge" style={{
                    backgroundColor: 'rgba(168, 85, 247, 0.1)',
                    color: '#a855f7',
                    border: '1px solid rgba(168, 85, 247, 0.3)',
                  }}>
                    EXTERNAL
                  </span>
                )}
              </div>
              <p style={{ fontSize: '0.95rem', color: '#9CA3AF', marginBottom: 12 }}>
                {tool.description}
              </p>
              <div style={{ display: 'flex', gap: 24, alignItems: 'center' }}>
                <div>
                  <span style={{ fontSize: '0.75rem', color: '#71717a' }}>Endpoint: </span>
                  <code className="mono" style={{
                    fontSize: '0.85rem',
                    color: '#6EE7B7',
                    backgroundColor: 'rgba(110, 231, 183, 0.08)',
                    padding: '2px 8px',
                    borderRadius: 2,
                  }}>
                    {tool.endpoint}
                  </code>
                </div>
                <div>
                  <span style={{ fontSize: '0.75rem', color: '#71717a' }}>Jobs completed: </span>
                  <span className="mono" style={{ fontSize: '0.85rem', color: '#FFFFFF', fontWeight: 600 }}>
                    {tool.jobsCompleted.toLocaleString()}
                  </span>
                </div>
                <div>
                  <span style={{ fontSize: '0.75rem', color: '#71717a' }}>Reputation: </span>
                  <span className="mono" style={{ fontSize: '0.85rem', color: tool.reputation >= 90 ? '#34D399' : '#F59E0B', fontWeight: 600 }}>
                    {tool.reputation}%
                  </span>
                </div>
              </div>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: 12 }}>
              <div style={{ textAlign: 'right' }}>
                <div style={{ fontSize: '0.75rem', color: '#71717a', marginBottom: 4 }}>Price per scan</div>
                <div className="mono" style={{ fontSize: '1.3rem', fontWeight: 800, color: '#6EE7B7' }}>
                  {tool.price?.STT} STT
                </div>
              </div>
              <button className="btn btn-primary" style={{ minWidth: 140 }}>
                Use Tool
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
