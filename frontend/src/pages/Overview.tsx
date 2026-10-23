import React from 'react';
import {
  ShieldAlert,
  AlertTriangle,
  Ban,
  Activity,
  ArrowUpRight,
  Globe,
  Clock,
  Layers,
  CheckCircle2,
} from 'lucide-react';
import { DashboardSummary, Alert } from '../types';

interface OverviewProps {
  summary: DashboardSummary | null;
  isLoading: boolean;
  onNavigate: (page: string) => void;
  onSelectAlert: (alert: Alert) => void;
}

export const Overview: React.FC<OverviewProps> = ({
  summary,
  isLoading,
  onNavigate,
  onSelectAlert,
}) => {
  if (isLoading && !summary) {
    return (
      <div className="p-8 flex items-center justify-center min-h-[60vh]">
        <div className="flex flex-col items-center space-y-3 text-slate-400">
          <div className="w-10 h-10 border-2 border-sky-500 border-t-transparent rounded-full animate-spin" />
          <p className="text-sm font-mono">Loading telemetry...</p>
        </div>
      </div>
    );
  }

  if (!summary) {
    return (
      <div className="p-8 text-center text-slate-400">
        <p>No dashboard data available. Verify backend is running.</p>
      </div>
    );
  }

  const maxEventCount = Math.max(...summary.hourly_trend.map((h) => h.events), 1);

  return (
    <div className="p-8 space-y-8 max-w-7xl mx-auto">
      {/* 4 Stat Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-5">
        {/* Total Events */}
        <div className="bg-[#0F172A] border border-slate-800 rounded-xl p-5 shadow-sm relative overflow-hidden group hover:border-slate-700 transition-all">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider font-mono">
              Events Processed
            </span>
            <div className="p-2 rounded-lg bg-sky-500/10 text-sky-400 border border-sky-500/20">
              <Activity className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-4 flex items-baseline justify-between">
            <div className="text-3xl font-extrabold text-white font-mono">
              {summary.total_events.toLocaleString()}
            </div>
            <div className="text-xs text-sky-400 font-mono flex items-center">
              <span>{summary.events_last_24h} in 24h</span>
            </div>
          </div>
          <div className="mt-2 text-xs text-slate-500">Normal & suspicious log lines</div>
          <div className="absolute inset-x-0 bottom-0 h-0.5 bg-gradient-to-r from-sky-500 to-blue-600 opacity-60" />
        </div>

        {/* Total Alerts */}
        <div className="bg-[#0F172A] border border-slate-800 rounded-xl p-5 shadow-sm relative overflow-hidden group hover:border-slate-700 transition-all">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider font-mono">
              Alerts Triggered
            </span>
            <div className="p-2 rounded-lg bg-rose-500/10 text-rose-400 border border-rose-500/20">
              <AlertTriangle className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-4 flex items-baseline justify-between">
            <div className="text-3xl font-extrabold text-white font-mono">
              {summary.total_alerts.toLocaleString()}
            </div>
            <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-500/15 text-rose-400 border border-rose-500/30">
              High Severity
            </span>
          </div>
          <div className="mt-2 text-xs text-slate-500">Scenario bucket overflows</div>
          <div className="absolute inset-x-0 bottom-0 h-0.5 bg-gradient-to-r from-rose-500 to-amber-500 opacity-60" />
        </div>

        {/* Active Decisions */}
        <div className="bg-[#0F172A] border border-slate-800 rounded-xl p-5 shadow-sm relative overflow-hidden group hover:border-slate-700 transition-all">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider font-mono">
              Active Bans
            </span>
            <div className="p-2 rounded-lg bg-amber-500/10 text-amber-400 border border-amber-500/20">
              <Ban className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-4 flex items-baseline justify-between">
            <div className="text-3xl font-extrabold text-white font-mono">
              {summary.active_decisions.toLocaleString()}
            </div>
            <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-500/15 text-amber-400 border border-amber-500/30">
              Enforced
            </span>
          </div>
          <div className="mt-2 text-xs text-slate-500">Blocked malicious IP targets</div>
          <div className="absolute inset-x-0 bottom-0 h-0.5 bg-gradient-to-r from-amber-500 to-yellow-500 opacity-60" />
        </div>

        {/* Active Rules */}
        <div className="bg-[#0F172A] border border-slate-800 rounded-xl p-5 shadow-sm relative overflow-hidden group hover:border-slate-700 transition-all">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider font-mono">
              Detection Rules
            </span>
            <div className="p-2 rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
              <ShieldAlert className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-4 flex items-baseline justify-between">
            <div className="text-3xl font-extrabold text-white font-mono">
              {summary.scenarios_active}
            </div>
            <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">
              Python Core
            </span>
          </div>
          <div className="mt-2 text-xs text-slate-500">Leaky, Trigger & Uniq scenarios</div>
          <div className="absolute inset-x-0 bottom-0 h-0.5 bg-gradient-to-r from-emerald-500 to-teal-500 opacity-60" />
        </div>
      </div>

      {/* Hourly Threat Trend Chart */}
      <div className="bg-[#0F172A] border border-slate-800 rounded-xl p-6 shadow-sm">
        <div className="flex items-center justify-between mb-6">
          <div>
            <h2 className="text-base font-bold text-white tracking-wide">Threat & Ingestion Activity</h2>
            <p className="text-xs text-slate-400 mt-0.5">Event volume and detection alerts across recent hours</p>
          </div>
          <div className="flex items-center space-x-4 text-xs font-mono">
            <div className="flex items-center space-x-1.5">
              <span className="w-3 h-3 rounded bg-sky-500" />
              <span className="text-slate-300">Events</span>
            </div>
            <div className="flex items-center space-x-1.5">
              <span className="w-3 h-3 rounded bg-rose-500" />
              <span className="text-slate-300">Alerts</span>
            </div>
          </div>
        </div>

        {/* SVG-based Bar Chart */}
        <div className="h-44 w-full flex items-end space-x-2 pt-6">
          {summary.hourly_trend.map((point, index) => {
            const eventHeight = Math.max((point.events / maxEventCount) * 100, 6);
            const alertHeight = point.alerts > 0 ? Math.min(point.alerts * 25, 100) : 0;
            return (
              <div key={index} className="flex-1 flex flex-col items-center h-full justify-end group">
                <div className="w-full flex items-end justify-center space-x-1 h-32">
                  <div
                    style={{ height: `${eventHeight}%` }}
                    className="w-full max-w-[20px] bg-sky-500/70 hover:bg-sky-400 rounded-t transition-all group-hover:shadow-lg group-hover:shadow-sky-500/30 relative"
                    title={`${point.hour}: ${point.events} events`}
                  />
                  {point.alerts > 0 && (
                    <div
                      style={{ height: `${alertHeight}%` }}
                      className="w-full max-w-[14px] bg-rose-500 hover:bg-rose-400 rounded-t transition-all group-hover:shadow-lg group-hover:shadow-rose-500/30"
                      title={`${point.hour}: ${point.alerts} alerts`}
                    />
                  )}
                </div>
                <span className="text-[10px] font-mono text-slate-500 mt-2 truncate w-full text-center">
                  {point.hour}
                </span>
              </div>
            );
          })}
        </div>
      </div>

      {/* Two Column Grid: Recent Alerts & Top Attacking IPs */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Recent Alerts (2 Cols) */}
        <div className="lg:col-span-2 bg-[#0F172A] border border-slate-800 rounded-xl p-6 shadow-sm">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h2 className="text-base font-bold text-white tracking-wide">Recent Threat Alerts</h2>
              <p className="text-xs text-slate-400 mt-0.5">Latest scenario overflows and remediation triggers</p>
            </div>
            <button
              onClick={() => onNavigate('alerts')}
              className="text-xs text-sky-400 hover:text-sky-300 font-semibold flex items-center gap-1 transition-colors"
            >
              <span>View All</span>
              <ArrowUpRight className="w-3.5 h-3.5" />
            </button>
          </div>

          {summary.recent_alerts.length === 0 ? (
            <div className="py-12 text-center text-slate-500 text-sm">
              No recent alerts detected. System is clean.
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="border-b border-slate-800 text-slate-400 font-mono">
                    <th className="pb-3 font-semibold">Severity</th>
                    <th className="pb-3 font-semibold">Scenario</th>
                    <th className="pb-3 font-semibold">Attacker IP</th>
                    <th className="pb-3 font-semibold">Count</th>
                    <th className="pb-3 font-semibold">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 font-mono">
                  {summary.recent_alerts.map((alert) => (
                    <tr
                      key={alert.id}
                      onClick={() => onSelectAlert(alert)}
                      className="hover:bg-slate-800/40 cursor-pointer transition-colors"
                    >
                      <td className="py-3">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                            alert.severity === 'critical'
                              ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30'
                              : alert.severity === 'high'
                              ? 'bg-orange-500/20 text-orange-400 border border-orange-500/30'
                              : 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                          }`}
                        >
                          {alert.severity}
                        </span>
                      </td>
                      <td className="py-3 text-slate-200 font-medium">{alert.scenario}</td>
                      <td className="py-3 text-sky-400">{alert.source_ip}</td>
                      <td className="py-3 text-slate-300">{alert.events_count} events</td>
                      <td className="py-3">
                        <span className="px-2 py-0.5 rounded text-[10px] bg-slate-800 text-slate-300 border border-slate-700">
                          {alert.decisions?.[0]?.type || 'ban'}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* Top Attacking IPs & Architecture Status (1 Col) */}
        <div className="space-y-6">
          {/* Top Attacking IPs */}
          <div className="bg-[#0F172A] border border-slate-800 rounded-xl p-6 shadow-sm">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-base font-bold text-white tracking-wide">Top Attacking IPs</h2>
              <Globe className="w-4 h-4 text-slate-400" />
            </div>
            {summary.top_attacking_ips.length === 0 ? (
              <p className="text-xs text-slate-500 py-4 text-center">No attacking IPs recorded yet.</p>
            ) : (
              <div className="space-y-3 font-mono text-xs">
                {summary.top_attacking_ips.map((item, idx) => (
                  <div
                    key={idx}
                    className="flex items-center justify-between p-2.5 rounded-lg bg-slate-900/60 border border-slate-800/80"
                  >
                    <span className="text-slate-200 font-semibold">{item.ip}</span>
                    <span className="px-2 py-0.5 rounded bg-rose-500/10 text-rose-400 border border-rose-500/20 font-bold">
                      {item.event_count} hits
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Architecture Status */}
          <div className="bg-[#0F172A] border border-slate-800 rounded-xl p-6 shadow-sm">
            <h2 className="text-base font-bold text-white tracking-wide mb-2">Engine Architecture</h2>
            <p className="text-xs text-slate-400 leading-relaxed">
              Spork-IDS runs a <strong>100% Python-native Security Engine</strong> reproducing CrowdSec's leaky-bucket algorithm, parsing, and decisions without requiring external Go binaries.
            </p>
            <div className="mt-4 pt-4 border-t border-slate-800 flex items-center justify-between text-xs">
              <span className="text-slate-400">CrowdSec LAPI Mode:</span>
              <span className="font-mono text-sky-400 font-semibold">
                {summary.crowdsec_status.mode.toUpperCase()}
              </span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
