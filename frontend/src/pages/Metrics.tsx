import React, { useState, useEffect } from 'react';
import {
  BarChart3,
  Cpu,
  Layers,
  Activity,
  HardDrive,
  Clock,
  Shield,
  Zap,
} from 'lucide-react';
import { SystemMetrics } from '../types';
import { api } from '../services/api';

export const Metrics: React.FC = () => {
  const [metrics, setMetrics] = useState<SystemMetrics | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  const loadMetrics = async () => {
    setIsLoading(true);
    try {
      const res = await api.getMetrics();
      setMetrics(res);
    } catch (err) {
      console.error('Failed to load metrics:', err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadMetrics();
  }, []);

  if (isLoading && !metrics) {
    return (
      <div className="p-8 flex items-center justify-center min-h-[60vh]">
        <div className="flex flex-col items-center space-y-3 text-slate-400">
          <div className="w-8 h-8 border-2 border-sky-500 border-t-transparent rounded-full animate-spin" />
          <span className="text-xs font-mono">Gathering engine telemetry...</span>
        </div>
      </div>
    );
  }

  if (!metrics) return null;

  const suspiciousRatio =
    metrics.events_ingested > 0
      ? ((metrics.events_suspicious / metrics.events_ingested) * 100).toFixed(1)
      : '0.0';

  return (
    <div className="p-8 space-y-8 max-w-7xl mx-auto">
      {/* Header */}
      <div>
        <h2 className="text-xl font-bold text-white tracking-wide">Operational Metrics & Telemetry</h2>
        <p className="text-xs text-slate-400 mt-0.5">
          Real-time performance indicators, in-memory bucket allocations, and ingestion counters
        </p>
      </div>

      {/* Grid: 4 Metric Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-5 font-mono">
        <div className="bg-[#0F172A] border border-slate-800 rounded-xl p-5 shadow-sm space-y-2">
          <span className="text-xs text-slate-500 uppercase">Suspicious Ratio</span>
          <div className="text-2xl font-bold text-amber-400">{suspiciousRatio}%</div>
          <div className="text-[11px] text-slate-400">
            {metrics.events_suspicious} of {metrics.events_ingested} logs flagged
          </div>
        </div>

        <div className="bg-[#0F172A] border border-slate-800 rounded-xl p-5 shadow-sm space-y-2">
          <span className="text-xs text-slate-500 uppercase">Alert Conversion</span>
          <div className="text-2xl font-bold text-rose-400">{metrics.alerts_triggered}</div>
          <div className="text-[11px] text-slate-400">Bucket overflows triggered</div>
        </div>

        <div className="bg-[#0F172A] border border-slate-800 rounded-xl p-5 shadow-sm space-y-2">
          <span className="text-xs text-slate-500 uppercase">Live Bucket Instances</span>
          <div className="text-2xl font-bold text-sky-400">{metrics.live_buckets_count}</div>
          <div className="text-[11px] text-slate-400">In-memory active state machines</div>
        </div>

        <div className="bg-[#0F172A] border border-slate-800 rounded-xl p-5 shadow-sm space-y-2">
          <span className="text-xs text-slate-500 uppercase">Uptime Counter</span>
          <div className="text-2xl font-bold text-emerald-400">
            {Math.floor(metrics.uptime_seconds)}s
          </div>
          <div className="text-[11px] text-slate-400">Continuous runtime</div>
        </div>
      </div>

      {/* Scenario Breakdown Table */}
      <div className="bg-[#0F172A] border border-slate-800 rounded-xl p-6 shadow-sm space-y-4">
        <h3 className="text-base font-bold text-white tracking-wide">Detection Scenarios Activity</h3>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400 bg-slate-900/50">
                <th className="py-3 px-4 font-semibold">Scenario Identifier</th>
                <th className="py-3 px-4 font-semibold">Bucket Architecture</th>
                <th className="py-3 px-4 font-semibold">Capacity / Leak</th>
                <th className="py-3 px-4 font-semibold">Poured Events</th>
                <th className="py-3 px-4 font-semibold">Overflows Emitted</th>
                <th className="py-3 px-4 font-semibold">Active Buckets</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {metrics.scenarios.map((sc) => (
                <tr key={sc.name} className="hover:bg-slate-800/40">
                  <td className="py-3 px-4 font-semibold text-slate-200">{sc.name}</td>
                  <td className="py-3 px-4 uppercase text-sky-400">{sc.type} Bucket</td>
                  <td className="py-3 px-4 text-slate-400">
                    {sc.capacity} events / {sc.leakspeed}
                  </td>
                  <td className="py-3 px-4 text-slate-300">{sc.poured_events}</td>
                  <td className="py-3 px-4 text-rose-400 font-bold">{sc.overflow_count}</td>
                  <td className="py-3 px-4 text-emerald-400 font-bold">{sc.active_buckets}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Architecture & Host Specs */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-5 font-mono text-xs">
        <div className="bg-[#0F172A] border border-slate-800 rounded-xl p-6 space-y-3">
          <h4 className="text-slate-200 font-bold uppercase tracking-wider text-xs">
            Backend Technology Stack
          </h4>
          <div className="space-y-2 text-slate-400">
            <div className="flex justify-between py-1 border-b border-slate-800">
              <span>Backend Core:</span>
              <span className="text-sky-400 font-semibold">Python 3.9 (FastAPI)</span>
            </div>
            <div className="flex justify-between py-1 border-b border-slate-800">
              <span>Database Persistence:</span>
              <span className="text-slate-200">SQLite 3 via SQLAlchemy ORM</span>
            </div>
            <div className="flex justify-between py-1 border-b border-slate-800">
              <span>Detection Implementation:</span>
              <span className="text-emerald-400">Native Python Leaky Bucket</span>
            </div>
            <div className="flex justify-between py-1 border-b border-slate-800">
              <span>Async Server:</span>
              <span className="text-slate-200">Uvicorn ASGI</span>
            </div>
          </div>
        </div>

        <div className="bg-[#0F172A] border border-slate-800 rounded-xl p-6 space-y-3">
          <h4 className="text-slate-200 font-bold uppercase tracking-wider text-xs">
            CrowdSec Compatibility Profile
          </h4>
          <div className="space-y-2 text-slate-400">
            <div className="flex justify-between py-1 border-b border-slate-800">
              <span>Reference Specification:</span>
              <span className="text-sky-400">CrowdSec Engine v1.6+</span>
            </div>
            <div className="flex justify-between py-1 border-b border-slate-800">
              <span>Local API (LAPI) Protocol:</span>
              <span className="text-slate-200">LAPI REST v1.0.0</span>
            </div>
            <div className="flex justify-between py-1 border-b border-slate-800">
              <span>External Engine Requirement:</span>
              <span className="text-emerald-400 font-semibold">None (Self-Contained)</span>
            </div>
            <div className="flex justify-between py-1 border-b border-slate-800">
              <span>Remediation Compatibility:</span>
              <span className="text-slate-200">Bouncers (IP bans, captcha)</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
