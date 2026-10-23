import React, { useState, useEffect } from 'react';
import {
  AlertTriangle,
  Search,
  Filter,
  CheckCircle,
  XCircle,
  Trash2,
  ExternalLink,
  Shield,
  Clock,
  MapPin,
  X,
} from 'lucide-react';
import { Alert } from '../types';
import { api } from '../services/api';

interface AlertsProps {
  initialSelectedAlert?: Alert | null;
  onClearSelectedAlert?: () => void;
}

export const Alerts: React.FC<AlertsProps> = ({
  initialSelectedAlert,
  onClearSelectedAlert,
}) => {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [pageSize] = useState(15);
  const [severity, setSeverity] = useState<string>('');
  const [search, setSearch] = useState<string>('');
  const [statusFilter, setStatusFilter] = useState<string>('');
  const [simulatedOnly, setSimulatedOnly] = useState(false);
  const [isLoading, setIsLoading] = useState(true);
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(initialSelectedAlert || null);
  const [actionMessage, setActionMessage] = useState<string | null>(null);

  useEffect(() => {
    if (initialSelectedAlert) {
      setSelectedAlert(initialSelectedAlert);
    }
  }, [initialSelectedAlert]);

  const loadAlerts = async () => {
    setIsLoading(true);
    try {
      const res = await api.getAlerts({
        severity: severity || undefined,
        ip: search || undefined,
        status: statusFilter || undefined,
        is_simulated: simulatedOnly ? true : undefined,
        page,
        page_size: pageSize,
      });
      setAlerts(res.items);
      setTotal(res.total);
    } catch (err: any) {
      console.error('Failed to load alerts:', err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadAlerts();
  }, [page, severity, statusFilter, simulatedOnly]);

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setPage(1);
    loadAlerts();
  };

  const handleUpdateStatus = async (alertId: number, newStatus: string) => {
    try {
      const updated = await api.updateAlertStatus(alertId, newStatus);
      setAlerts((prev) => prev.map((a) => (a.id === alertId ? updated : a)));
      if (selectedAlert && selectedAlert.id === alertId) {
        setSelectedAlert(updated);
      }
      setActionMessage(`Alert #${alertId} marked as ${newStatus}`);
      setTimeout(() => setActionMessage(null), 3000);
    } catch (err: any) {
      alert(`Failed to update alert: ${err.message}`);
    }
  };

  const handleDeleteAlert = async (alertId: number) => {
    if (!confirm(`Are you sure you want to delete Alert #${alertId}?`)) return;
    try {
      await api.deleteAlert(alertId);
      setAlerts((prev) => prev.filter((a) => a.id !== alertId));
      if (selectedAlert && selectedAlert.id === alertId) {
        setSelectedAlert(null);
        if (onClearSelectedAlert) onClearSelectedAlert();
      }
      setActionMessage(`Alert #${alertId} deleted successfully.`);
      setTimeout(() => setActionMessage(null), 3000);
    } catch (err: any) {
      alert(`Failed to delete alert: ${err.message}`);
    }
  };

  const getSeverityBadge = (sev: string) => {
    const s = sev.toLowerCase();
    if (s === 'critical') {
      return 'bg-rose-500/20 text-rose-400 border-rose-500/30';
    } else if (s === 'high') {
      return 'bg-orange-500/20 text-orange-400 border-orange-500/30';
    } else if (s === 'medium') {
      return 'bg-amber-500/20 text-amber-400 border-amber-500/30';
    }
    return 'bg-sky-500/20 text-sky-400 border-sky-500/30';
  };

  return (
    <div className="p-8 space-y-6 max-w-7xl mx-auto">
      {/* Header and Filter Controls */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-white tracking-wide">Threat & Detection Alerts</h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Real-time security alerts emitted by the Spork-IDS scenario engine ({total} total)
          </p>
        </div>

        {/* Action Flash Notification */}
        {actionMessage && (
          <div className="px-3 py-1.5 rounded-lg bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 text-xs font-mono animate-fade-in">
            {actionMessage}
          </div>
        )}
      </div>

      {/* Filter Toolbar */}
      <div className="bg-[#0F172A] border border-slate-800 rounded-xl p-4 flex flex-wrap items-center justify-between gap-4">
        <form onSubmit={handleSearchSubmit} className="flex-1 min-w-[260px] flex items-center relative">
          <Search className="w-4 h-4 text-slate-400 absolute left-3" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search by IP address or keyword..."
            className="w-full pl-9 pr-4 py-2 rounded-lg bg-slate-900 border border-slate-800 text-slate-200 text-xs font-mono focus:outline-none focus:border-sky-500 transition-colors"
          />
        </form>

        <div className="flex items-center space-x-3">
          {/* Severity Filter */}
          <select
            value={severity}
            onChange={(e) => {
              setSeverity(e.target.value);
              setPage(1);
            }}
            className="px-3 py-2 rounded-lg bg-slate-900 border border-slate-800 text-slate-300 text-xs font-mono focus:outline-none focus:border-sky-500"
          >
            <option value="">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>

          {/* Status Filter */}
          <select
            value={statusFilter}
            onChange={(e) => {
              setStatusFilter(e.target.value);
              setPage(1);
            }}
            className="px-3 py-2 rounded-lg bg-slate-900 border border-slate-800 text-slate-300 text-xs font-mono focus:outline-none focus:border-sky-500"
          >
            <option value="">All Statuses</option>
            <option value="active">Active</option>
            <option value="resolved">Resolved</option>
            <option value="dismissed">Dismissed</option>
          </select>

          <label className="flex items-center space-x-2 text-xs font-mono text-purple-300 cursor-pointer select-none">
            <input
              type="checkbox"
              checked={simulatedOnly}
              onChange={(e) => {
                setSimulatedOnly(e.target.checked);
                setPage(1);
              }}
              className="rounded bg-slate-900 border-slate-800 text-purple-500 focus:ring-0 focus:outline-none"
            />
            <span>Simulated only</span>
          </label>
        </div>
      </div>

      {/* Alerts Table */}
      <div className="bg-[#0F172A] border border-slate-800 rounded-xl overflow-hidden shadow-sm">
        {isLoading ? (
          <div className="py-20 flex flex-col items-center justify-center space-y-3 text-slate-400">
            <div className="w-8 h-8 border-2 border-sky-500 border-t-transparent rounded-full animate-spin" />
            <span className="text-xs font-mono">Fetching alerts...</span>
          </div>
        ) : alerts.length === 0 ? (
          <div className="py-20 text-center text-slate-500 space-y-2">
            <AlertTriangle className="w-8 h-8 mx-auto text-slate-600" />
            <p className="text-sm font-semibold">No alerts found matching your criteria</p>
            <p className="text-xs text-slate-500">Try clearing filters or simulate an attack from the top bar.</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400 font-mono bg-slate-900/50">
                  <th className="py-3.5 px-4 font-semibold">ID</th>
                  <th className="py-3.5 px-4 font-semibold">Severity</th>
                  <th className="py-3.5 px-4 font-semibold">Scenario</th>
                  <th className="py-3.5 px-4 font-semibold">Attacker IP</th>
                  <th className="py-3.5 px-4 font-semibold">Events</th>
                  <th className="py-3.5 px-4 font-semibold">Status</th>
                  <th className="py-3.5 px-4 font-semibold">Timestamp</th>
                  <th className="py-3.5 px-4 font-semibold text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-mono">
                {alerts.map((alert) => (
                  <tr
                    key={alert.id}
                    className="hover:bg-slate-800/40 transition-colors cursor-pointer"
                    onClick={() => setSelectedAlert(alert)}
                  >
                    <td className="py-3 px-4 text-slate-500">#{alert.id}</td>
                    <td className="py-3 px-4">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase border ${getSeverityBadge(alert.severity)}`}>
                        {alert.severity}
                      </span>
                    </td>
                    <td className="py-3 px-4 font-medium text-slate-200">
                      <div className="flex items-center space-x-1.5">
                        <span>{alert.scenario}</span>
                        {alert.is_simulated && (
                          <span className="px-1.5 py-0.2 rounded text-[9px] font-mono font-bold bg-purple-500/20 text-purple-300 border border-purple-500/40">
                            SIMULATED
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="py-3 px-4 text-sky-400 font-semibold">{alert.source_ip}</td>
                    <td className="py-3 px-4 text-slate-300">{alert.events_count} hits</td>
                    <td className="py-3 px-4">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-semibold uppercase ${
                          alert.status === 'active'
                            ? 'bg-rose-500/15 text-rose-400'
                            : alert.status === 'resolved'
                            ? 'bg-emerald-500/15 text-emerald-400'
                            : 'bg-slate-700 text-slate-400'
                        }`}
                      >
                        {alert.status}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-slate-400 text-[11px]">
                      {new Date(alert.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                    </td>
                    <td className="py-3 px-4 text-right space-x-2" onClick={(e) => e.stopPropagation()}>
                      {alert.status === 'active' && (
                        <button
                          onClick={() => handleUpdateStatus(alert.id, 'resolved')}
                          className="px-2 py-1 rounded bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-400 text-[11px] font-semibold transition-colors"
                          title="Mark Resolved"
                        >
                          Resolve
                        </button>
                      )}
                      <button
                        onClick={() => handleDeleteAlert(alert.id)}
                        className="p-1 rounded hover:bg-rose-500/20 text-slate-500 hover:text-rose-400 transition-colors"
                        title="Delete Alert"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Alert Detail Modal */}
      {selectedAlert && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-[#0F172A] border border-slate-800 rounded-2xl w-full max-w-2xl max-h-[90vh] overflow-y-auto shadow-2xl p-6 space-y-6">
            {/* Modal Header */}
            <div className="flex items-start justify-between border-b border-slate-800 pb-4">
              <div>
                <div className="flex items-center space-x-3">
                  <span className={`px-2.5 py-0.5 rounded text-xs font-bold uppercase border ${getSeverityBadge(selectedAlert.severity)}`}>
                    {selectedAlert.severity}
                  </span>
                  <h3 className="text-base font-bold text-white font-mono">{selectedAlert.scenario}</h3>
                  {selectedAlert.is_simulated && (
                    <span className="px-1.5 py-0.5 rounded text-[10px] font-mono font-bold bg-purple-500/20 text-purple-300 border border-purple-500/40">
                      SIMULATED
                    </span>
                  )}
                </div>
                <p className="text-xs text-slate-400 mt-1">{selectedAlert.message}</p>
              </div>
              <button
                onClick={() => {
                  setSelectedAlert(null);
                  if (onClearSelectedAlert) onClearSelectedAlert();
                }}
                className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Target Information Grid */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 bg-slate-900/60 border border-slate-800/80 p-4 rounded-xl font-mono text-xs">
              <div>
                <span className="text-slate-500 block">Attacker IP</span>
                <span className="text-sky-400 font-bold">{selectedAlert.source_ip}</span>
              </div>
              <div>
                <span className="text-slate-500 block">Scope</span>
                <span className="text-slate-200">{selectedAlert.source_scope}</span>
              </div>
              <div>
                <span className="text-slate-500 block">Bucket Capacity</span>
                <span className="text-slate-200">{selectedAlert.capacity} events</span>
              </div>
              <div>
                <span className="text-slate-500 block">Leak Speed</span>
                <span className="text-slate-200">{selectedAlert.leakspeed}</span>
              </div>
            </div>

            {/* Decisions Enforced */}
            <div>
              <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider font-mono mb-2">
                Enforced Decisions
              </h4>
              {selectedAlert.decisions && selectedAlert.decisions.length > 0 ? (
                <div className="space-y-2">
                  {selectedAlert.decisions.map((dec) => (
                    <div
                      key={dec.id}
                      className="p-3 rounded-lg bg-rose-500/10 border border-rose-500/20 flex items-center justify-between font-mono text-xs"
                    >
                      <div className="flex items-center space-x-2">
                        <span className="px-2 py-0.5 rounded bg-rose-500 text-white font-bold uppercase text-[10px]">
                          {dec.type}
                        </span>
                        <span className="text-slate-200">{dec.value}</span>
                        <span className="text-slate-500">for {dec.duration}</span>
                      </div>
                      <span className="text-[11px] text-rose-300">
                        Expires: {new Date(dec.until).toLocaleTimeString()}
                      </span>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-xs text-slate-500 font-mono">No active decision attached.</p>
              )}
            </div>

            {/* Contributing Events */}
            <div>
              <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider font-mono mb-2">
                Contributing Log Events ({selectedAlert.events_count})
              </h4>
              <div className="bg-slate-950 border border-slate-800 rounded-xl p-3 font-mono text-[11px] space-y-2 max-h-48 overflow-y-auto">
                {selectedAlert.meta_data?.contributing_events?.map((ev, i) => (
                  <div key={i} className="text-slate-300 border-b border-slate-900 pb-1.5 last:border-none">
                    <span className="text-sky-400">[{ev.service || 'log'}]</span> {ev.raw_log}
                  </div>
                )) || <div className="text-slate-500">No raw log details available.</div>}
              </div>
            </div>

            {/* Modal Footer Controls */}
            <div className="flex items-center justify-between pt-4 border-t border-slate-800">
              <div className="flex space-x-2">
                {selectedAlert.status !== 'resolved' && (
                  <button
                    onClick={() => handleUpdateStatus(selectedAlert.id, 'resolved')}
                    className="px-3 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold font-mono transition-colors"
                  >
                    Resolve Alert
                  </button>
                )}
                {selectedAlert.status !== 'dismissed' && (
                  <button
                    onClick={() => handleUpdateStatus(selectedAlert.id, 'dismissed')}
                    className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold font-mono transition-colors"
                  >
                    Dismiss
                  </button>
                )}
              </div>
              <button
                onClick={() => handleDeleteAlert(selectedAlert.id)}
                className="px-3 py-1.5 rounded-lg bg-rose-500/10 hover:bg-rose-500/20 text-rose-400 border border-rose-500/30 text-xs font-semibold font-mono transition-colors flex items-center gap-1.5"
              >
                <Trash2 className="w-3.5 h-3.5" />
                <span>Delete</span>
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
