import React, { useState, useEffect } from 'react';
import {
  Ban,
  PlusCircle,
  Search,
  CheckCircle,
  XCircle,
  Shield,
  Clock,
  Trash2,
  X,
} from 'lucide-react';
import { Decision } from '../types';
import { api } from '../services/api';

export const Decisions: React.FC = () => {
  const [decisions, setDecisions] = useState<Decision[]>([]);
  const [activeOnly, setActiveOnly] = useState(true);
  const [search, setSearch] = useState('');
  const [isLoading, setIsLoading] = useState(true);

  // Manual Decision Modal State
  const [showAddModal, setShowAddModal] = useState(false);
  const [targetValue, setTargetValue] = useState('');
  const [targetScope, setTargetScope] = useState('Ip');
  const [decisionType, setDecisionType] = useState('ban');
  const [duration, setDuration] = useState('4h');
  const [scenarioReason, setScenarioReason] = useState('manual/admin-ban');
  const [actionNotice, setActionNotice] = useState<string | null>(null);

  const loadDecisions = async () => {
    setIsLoading(true);
    try {
      const res = await api.getDecisions(activeOnly);
      setDecisions(res.items);
    } catch (err) {
      console.error('Failed to load decisions:', err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadDecisions();
  }, [activeOnly]);

  const handleCreateDecision = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!targetValue.trim()) return;

    try {
      await api.createDecision({
        value: targetValue.trim(),
        scope: targetScope,
        type: decisionType,
        duration: duration,
        scenario: scenarioReason.trim(),
      });
      setShowAddModal(false);
      setTargetValue('');
      setActionNotice(`Created ${decisionType} decision on ${targetValue}`);
      loadDecisions();
      setTimeout(() => setActionNotice(null), 4000);
    } catch (err: any) {
      alert(`Error creating decision: ${err.message}`);
    }
  };

  const handleRevoke = async (id: number, value: string) => {
    if (!confirm(`Are you sure you want to revoke decision for ${value}?`)) return;

    try {
      await api.revokeDecision(id);
      setDecisions((prev) => prev.filter((d) => d.id !== id));
      setActionNotice(`Revoked remediation decision for ${value}`);
      setTimeout(() => setActionNotice(null), 3000);
    } catch (err: any) {
      alert(`Error revoking decision: ${err.message}`);
    }
  };

  const filteredDecisions = decisions.filter(
    (d) =>
      d.value.toLowerCase().includes(search.toLowerCase()) ||
      d.scenario.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div className="p-8 space-y-6 max-w-7xl mx-auto">
      {/* Header and Add Button */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-white tracking-wide">Remediation Decisions (Bans)</h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Active and historical IP blocklists, throttles, and security enforcement policies
          </p>
        </div>

        <div className="flex items-center space-x-3">
          {actionNotice && (
            <div className="px-3 py-1.5 rounded-lg bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 text-xs font-mono">
              {actionNotice}
            </div>
          )}

          <button
            onClick={() => setShowAddModal(true)}
            className="flex items-center space-x-2 px-3.5 py-2 rounded-lg bg-rose-600 hover:bg-rose-500 text-white text-xs font-semibold font-mono transition-colors shadow-sm"
          >
            <PlusCircle className="w-4 h-4" />
            <span>Add Manual Ban</span>
          </button>
        </div>
      </div>

      {/* Filter Toolbar */}
      <div className="bg-[#0F172A] border border-slate-800 rounded-xl p-4 flex flex-wrap items-center justify-between gap-4">
        <div className="flex-1 min-w-[260px] flex items-center relative">
          <Search className="w-4 h-4 text-slate-400 absolute left-3" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search decisions by IP or scenario..."
            className="w-full pl-9 pr-4 py-2 rounded-lg bg-slate-900 border border-slate-800 text-slate-200 text-xs font-mono focus:outline-none focus:border-sky-500 transition-colors"
          />
        </div>

        <div className="flex items-center space-x-3 font-mono text-xs">
          <label className="flex items-center space-x-2 text-slate-300 cursor-pointer select-none">
            <input
              type="checkbox"
              checked={activeOnly}
              onChange={(e) => setActiveOnly(e.target.checked)}
              className="rounded bg-slate-900 border-slate-800 text-sky-500 focus:ring-0"
            />
            <span>Active only</span>
          </label>
        </div>
      </div>

      {/* Decisions Table */}
      <div className="bg-[#0F172A] border border-slate-800 rounded-xl overflow-hidden shadow-sm">
        {isLoading ? (
          <div className="py-20 flex flex-col items-center justify-center space-y-3 text-slate-400">
            <div className="w-8 h-8 border-2 border-sky-500 border-t-transparent rounded-full animate-spin" />
            <span className="text-xs font-mono">Loading decisions...</span>
          </div>
        ) : filteredDecisions.length === 0 ? (
          <div className="py-20 text-center text-slate-500 space-y-2">
            <Ban className="w-8 h-8 mx-auto text-slate-600" />
            <p className="text-sm font-semibold">No remediation decisions found</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400 font-mono bg-slate-900/50">
                  <th className="py-3.5 px-4 font-semibold">Type</th>
                  <th className="py-3.5 px-4 font-semibold">Target Value (IP / Scope)</th>
                  <th className="py-3.5 px-4 font-semibold">Scenario Trigger</th>
                  <th className="py-3.5 px-4 font-semibold">Duration</th>
                  <th className="py-3.5 px-4 font-semibold">Expires At</th>
                  <th className="py-3.5 px-4 font-semibold">Origin</th>
                  <th className="py-3.5 px-4 font-semibold text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-mono">
                {filteredDecisions.map((dec) => (
                  <tr key={dec.id} className="hover:bg-slate-800/40 transition-colors">
                    <td className="py-3 px-4">
                      <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-rose-500/20 text-rose-400 border border-rose-500/30">
                        {dec.type}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-sky-400 font-semibold">
                      {dec.value}{' '}
                      <span className="text-[10px] text-slate-500">({dec.scope})</span>
                    </td>
                    <td className="py-3 px-4 text-slate-300">{dec.scenario}</td>
                    <td className="py-3 px-4 text-slate-400">{dec.duration}</td>
                    <td className="py-3 px-4 text-slate-400 text-[11px]">
                      {new Date(dec.until).toLocaleString()}
                    </td>
                    <td className="py-3 px-4">
                      <span className="px-2 py-0.5 rounded text-[10px] bg-slate-800 text-slate-300">
                        {dec.origin}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-right">
                      {dec.is_active && (
                        <button
                          onClick={() => handleRevoke(dec.id, dec.value)}
                          className="px-2.5 py-1 rounded bg-slate-800 hover:bg-rose-500/20 text-slate-300 hover:text-rose-400 border border-slate-700 text-[11px] font-semibold transition-colors"
                        >
                          Revoke / Unban
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Add Decision Modal */}
      {showAddModal && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-[#0F172A] border border-slate-800 rounded-2xl w-full max-w-md shadow-2xl p-6 space-y-5">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-base font-bold text-white font-mono flex items-center gap-2">
                <Ban className="w-4 h-4 text-rose-400" />
                <span>Create Remediation Decision</span>
              </h3>
              <button
                onClick={() => setShowAddModal(false)}
                className="p-1 rounded text-slate-400 hover:text-white"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <form onSubmit={handleCreateDecision} className="space-y-4 font-mono text-xs">
              <div>
                <label className="text-slate-300 block mb-1">Target Value (IP address / subnet / username):</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. 192.168.1.105 or 10.0.0.0/24"
                  value={targetValue}
                  onChange={(e) => setTargetValue(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-800 text-slate-200 focus:outline-none focus:border-rose-500"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-slate-300 block mb-1">Remediation Type:</label>
                  <select
                    value={decisionType}
                    onChange={(e) => setDecisionType(e.target.value)}
                    className="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-800 text-slate-200 focus:outline-none focus:border-rose-500"
                  >
                    <option value="ban">Ban (Block Traffic)</option>
                    <option value="captcha">Captcha</option>
                    <option value="throttle">Throttle</option>
                  </select>
                </div>

                <div>
                  <label className="text-slate-300 block mb-1">Duration:</label>
                  <select
                    value={duration}
                    onChange={(e) => setDuration(e.target.value)}
                    className="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-800 text-slate-200 focus:outline-none focus:border-rose-500"
                  >
                    <option value="1h">1 Hour</option>
                    <option value="4h">4 Hours</option>
                    <option value="24h">24 Hours</option>
                    <option value="7d">7 Days</option>
                    <option value="30d">30 Days</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="text-slate-300 block mb-1">Reason / Scenario Note:</label>
                <input
                  type="text"
                  value={scenarioReason}
                  onChange={(e) => setScenarioReason(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-800 text-slate-200 focus:outline-none focus:border-rose-500"
                />
              </div>

              <div className="flex justify-end space-x-2 pt-3 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowAddModal(false)}
                  className="px-3 py-1.5 rounded-lg bg-slate-800 text-slate-300 hover:bg-slate-700"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-1.5 rounded-lg bg-rose-600 hover:bg-rose-500 text-white font-bold"
                >
                  Enforce Decision
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
