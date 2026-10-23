import React from 'react';
import {
  LayoutDashboard,
  AlertTriangle,
  ScrollText,
  ShieldAlert,
  Ban,
  BarChart3,
  Settings,
  Shield,
  Activity,
  Cpu,
} from 'lucide-react';
import { HealthStatus } from '../types';

interface SidebarProps {
  currentPage: string;
  onNavigate: (page: string) => void;
  health: HealthStatus | null;
}

export const Sidebar: React.FC<SidebarProps> = ({
  currentPage,
  onNavigate,
  health,
}) => {
  const menuItems = [
    { id: 'overview', label: 'Overview', icon: LayoutDashboard },
    { id: 'alerts', label: 'Alerts', icon: AlertTriangle, badge: health?.total_alerts },
    { id: 'events', label: 'Events & Logs', icon: ScrollText },
    { id: 'detection', label: 'Detection Rules', icon: ShieldAlert },
    { id: 'decisions', label: 'Decisions', icon: Ban, badge: health?.active_decisions },
    { id: 'metrics', label: 'Metrics', icon: BarChart3 },
    { id: 'settings', label: 'Settings', icon: Settings },
  ];

  return (
    <aside className="w-64 bg-[#0B1120] border-r border-slate-800 flex flex-col justify-between shrink-0 select-none">
      {/* Brand Header */}
      <div>
        <div className="p-6 border-b border-slate-800/80 flex items-center space-x-3">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-sky-500 to-blue-600 flex items-center justify-center shadow-lg shadow-sky-500/20 ring-1 ring-white/20">
            <Shield className="w-6 h-6 text-white" />
          </div>
          <div>
            <div className="font-bold text-lg tracking-wider text-white flex items-center gap-1.5">
              SPORK<span className="text-sky-400 font-extrabold">IDS</span>
            </div>
            <div className="text-[10px] tracking-widest text-slate-400 uppercase font-mono">
              Adaptive Security
            </div>
          </div>
        </div>

        {/* Navigation Menu */}
        <nav className="p-4 space-y-1.5">
          {menuItems.map((item) => {
            const Icon = item.icon;
            const isActive = currentPage === item.id;
            return (
              <button
                key={item.id}
                onClick={() => onNavigate(item.id)}
                className={`w-full flex items-center justify-between px-3.5 py-2.5 rounded-lg text-sm font-medium transition-all duration-150 ${
                  isActive
                    ? 'bg-sky-500/15 text-sky-400 border border-sky-500/30 shadow-sm shadow-sky-500/10'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60 border border-transparent'
                }`}
              >
                <div className="flex items-center space-x-3">
                  <Icon className={`w-4 h-4 ${isActive ? 'text-sky-400' : 'text-slate-400'}`} />
                  <span>{item.label}</span>
                </div>
                {item.badge !== undefined && item.badge > 0 && (
                  <span
                    className={`px-2 py-0.5 text-xs rounded-full font-mono font-semibold ${
                      item.id === 'alerts'
                        ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30'
                        : 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                    }`}
                  >
                    {item.badge}
                  </span>
                )}
              </button>
            );
          })}
        </nav>
      </div>

      {/* Engine & Status Footer */}
      <div className="p-4 m-4 rounded-xl bg-slate-900/80 border border-slate-800 space-y-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-2 text-xs font-semibold text-slate-300">
            <Cpu className="w-3.5 h-3.5 text-sky-400" />
            <span>Engine Mode</span>
          </div>
          <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-sky-500/10 text-sky-400 border border-sky-500/20">
            Python 3.9
          </span>
        </div>

        <div className="space-y-1.5 text-[11px] font-mono text-slate-400">
          <div className="flex items-center justify-between">
            <span className="flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
              Detection Core
            </span>
            <span className="text-emerald-400 font-semibold">Active</span>
          </div>

          <div className="flex items-center justify-between">
            <span className="flex items-center gap-1.5 text-slate-400">
              <span className={`w-2 h-2 rounded-full ${health?.crowdsec_integration === 'hybrid' ? 'bg-emerald-400' : 'bg-slate-500'}`}></span>
              CrowdSec LAPI
            </span>
            <span className={health?.crowdsec_integration === 'hybrid' ? 'text-emerald-400 font-semibold' : 'text-slate-400'}>
              {health?.crowdsec_integration === 'hybrid' ? 'Connected' : 'Standalone'}
            </span>
          </div>
        </div>
      </div>
    </aside>
  );
};
