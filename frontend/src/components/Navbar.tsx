import React from 'react';
import { RefreshCw, Play, ShieldAlert, Sparkles, CheckCircle2 } from 'lucide-react';
import { HealthStatus } from '../types';

interface NavbarProps {
  currentPageTitle: string;
  health: HealthStatus | null;
  onRefresh: () => void;
  isRefreshing: boolean;
  onSimulateAttack: () => void;
}

export const Navbar: React.FC<NavbarProps> = ({
  currentPageTitle,
  health,
  onRefresh,
  isRefreshing,
  onSimulateAttack,
}) => {
  return (
    <header className="h-16 bg-[#0F172A]/80 backdrop-blur-md border-b border-slate-800/80 px-6 flex items-center justify-between sticky top-0 z-20">
      {/* Page Title & Breadcrumb */}
      <div className="flex items-center space-x-3">
        <h1 className="text-lg font-bold text-white tracking-wide">{currentPageTitle}</h1>
        <span className="text-xs text-slate-500 font-mono">/ Spork-IDS Console</span>
      </div>

      {/* Right Controls */}
      <div className="flex items-center space-x-4">
        {/* Quick Attack Simulator Trigger */}
        <button
          onClick={onSimulateAttack}
          className="flex items-center space-x-2 px-3 py-1.5 rounded-lg bg-gradient-to-r from-rose-500/20 to-amber-500/20 border border-rose-500/30 text-rose-300 hover:text-white hover:border-rose-400/50 text-xs font-semibold transition-all shadow-sm"
          title="Inject realistic attack scenario (SSH brute force / SQL injection) to demonstrate detection in action"
        >
          <Play className="w-3.5 h-3.5 text-rose-400 fill-rose-400/20" />
          <span>Simulate Attack</span>
        </button>

        {/* Live System Uptime */}
        <div className="hidden md:flex items-center space-x-2 px-3 py-1 rounded-full bg-slate-900 border border-slate-800 text-xs font-mono text-slate-300">
          <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
          <span>UP: {health ? Math.floor(health.uptime_seconds) : 0}s</span>
        </div>

        {/* Refresh Button */}
        <button
          onClick={onRefresh}
          disabled={isRefreshing}
          className={`p-2 rounded-lg bg-slate-800/80 hover:bg-slate-700 border border-slate-700/60 text-slate-300 transition-all ${
            isRefreshing ? 'opacity-70 cursor-not-allowed' : ''
          }`}
          title="Refresh Data"
        >
          <RefreshCw className={`w-4 h-4 ${isRefreshing ? 'animate-spin text-sky-400' : ''}`} />
        </button>
      </div>
    </header>
  );
};
