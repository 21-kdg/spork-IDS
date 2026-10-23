import React, { useState, useEffect } from 'react';
import {
  ShieldAlert,
  Flame,
  Radio,
  RotateCcw,
  Play,
  Square,
  AlertTriangle,
  Ban,
  CheckCircle2,
  Terminal,
  Activity,
  Zap,
} from 'lucide-react';
import { SimulationScenario, SimulationLaunchResult, SimulationStatus } from '../types';
import { api } from '../services/api';

interface AttackSimulatorWidgetProps {
  onRefresh?: () => void;
  compact?: boolean;
}

export const AttackSimulatorWidget: React.FC<AttackSimulatorWidgetProps> = ({
  onRefresh,
  compact = false,
}) => {
  const [scenarios, setScenarios] = useState<SimulationScenario[]>([]);
  const [selectedScenario, setSelectedScenario] = useState<string>('spork/ssh-bf');
  const [customIp, setCustomIp] = useState<string>('185.220.101.5');
  const [isLaunching, setIsLaunching] = useState(false);
  const [launchResult, setLaunchResult] = useState<SimulationLaunchResult | null>(null);

  // Background stream status
  const [streamStatus, setStreamStatus] = useState<SimulationStatus>({
    is_running: false,
    interval_seconds: 3.0,
    total_simulated_events: 0,
    total_simulated_alerts: 0,
  });
  const [isTogglingStream, setIsTogglingStream] = useState(false);
  const [isResetting, setIsResetting] = useState(false);

  useEffect(() => {
    loadScenariosAndStatus();
  }, []);

  // Poll status periodically if stream is running
  useEffect(() => {
    let timer: any = null;
    if (streamStatus.is_running) {
      timer = setInterval(() => {
        pollStatusAndRefresh();
      }, 3000);
    }
    return () => {
      if (timer) clearInterval(timer);
    };
  }, [streamStatus.is_running]);

  const loadScenariosAndStatus = async () => {
    try {
      const [scList, status] = await Promise.all([
        api.getSimulationScenarios(),
        api.getSimulationStatus(),
      ]);
      setScenarios(scList);
      setStreamStatus(status);
    } catch (e) {
      console.error('Failed to load simulator data:', e);
    }
  };

  const pollStatusAndRefresh = async () => {
    try {
      const status = await api.getSimulationStatus();
      setStreamStatus(status);
      if (onRefresh) onRefresh();
    } catch (_) {}
  };

  const handleScenarioSelect = (sc: SimulationScenario) => {
    setSelectedScenario(sc.id);
    setCustomIp(sc.default_ip);
    setLaunchResult(null);
  };

  const handleLaunchAttack = async () => {
    setIsLaunching(true);
    setLaunchResult(null);
    try {
      const res = await api.launchSimulation({
        scenario: selectedScenario,
        source_ip: customIp.trim() || undefined,
      });
      setLaunchResult(res);
      if (onRefresh) onRefresh();
    } catch (err: any) {
      alert(`Simulation error: ${err.message}`);
    } finally {
      setIsLaunching(false);
    }
  };

  const handleToggleStream = async () => {
    setIsTogglingStream(true);
    try {
      if (streamStatus.is_running) {
        const res = await api.stopSimulation();
        setStreamStatus(res);
      } else {
        const res = await api.startSimulation({ interval_seconds: 3.0, include_attacks: true });
        setStreamStatus(res);
      }
      if (onRefresh) onRefresh();
    } catch (err: any) {
      alert(`Stream toggle error: ${err.message}`);
    } finally {
      setIsTogglingStream(false);
    }
  };

  const handleResetData = async () => {
    if (!confirm('Purge all simulated events, alerts, and decisions from the system?')) return;
    setIsResetting(true);
    try {
      await api.resetSimulation();
      setLaunchResult(null);
      await loadScenariosAndStatus();
      if (onRefresh) onRefresh();
    } catch (err: any) {
      alert(`Reset error: ${err.message}`);
    } finally {
      setIsResetting(false);
    }
  };

  const currentMeta = scenarios.find((s) => s.id === selectedScenario);

  return (
    <div className="bg-[#0B132B] border border-sky-900/60 rounded-2xl p-6 shadow-xl relative overflow-hidden space-y-6">
      {/* Top Banner & Mode */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-5">
        <div className="flex items-start space-x-3">
          <div className="p-2.5 rounded-xl bg-rose-500/15 text-rose-400 border border-rose-500/30 shadow-inner">
            <Flame className="w-6 h-6 animate-pulse" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <h2 className="text-base font-bold text-white tracking-wide">
                Live Attack Simulation & Anomaly Generator
              </h2>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-purple-500/20 text-purple-300 border border-purple-500/40">
                [SIMULATED]
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-1">
              Trigger real-time intrusion scenarios against the Python Leaky-Bucket engine and observe automatic remediation.
            </p>
          </div>
        </div>

        {/* Action Controls */}
        <div className="flex items-center space-x-2">
          {/* Continuous stream button */}
          <button
            onClick={handleToggleStream}
            disabled={isTogglingStream}
            className={`px-3 py-2 rounded-lg text-xs font-mono font-semibold flex items-center space-x-2 border transition-all ${
              streamStatus.is_running
                ? 'bg-rose-500/20 text-rose-300 border-rose-500/40 hover:bg-rose-500/30 animate-pulse'
                : 'bg-slate-900 text-slate-300 border-slate-700 hover:bg-slate-800'
            }`}
          >
            {streamStatus.is_running ? (
              <>
                <Square className="w-3.5 h-3.5 fill-rose-400" />
                <span>Stop Stream</span>
              </>
            ) : (
              <>
                <Radio className="w-3.5 h-3.5 text-sky-400" />
                <span>Continuous Stream</span>
              </>
            )}
          </button>

          {/* Reset button */}
          <button
            onClick={handleResetData}
            disabled={isResetting}
            title="Purge all simulated events, alerts, and decisions"
            className="p-2 rounded-lg bg-slate-900 text-slate-400 border border-slate-800 hover:text-slate-200 hover:border-slate-700 transition-colors"
          >
            <RotateCcw className={`w-4 h-4 ${isResetting ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* Stream Active Indicator Bar */}
      {streamStatus.is_running && (
        <div className="px-4 py-2.5 rounded-xl bg-purple-950/40 border border-purple-500/30 flex items-center justify-between text-xs font-mono text-purple-300 animate-fade-in">
          <div className="flex items-center space-x-2">
            <span className="w-2.5 h-2.5 rounded-full bg-purple-400 animate-ping" />
            <span className="font-bold">BACKGROUND STREAM ACTIVE:</span>
            <span>Injecting traffic & attack bursts every {streamStatus.interval_seconds}s</span>
          </div>
          <span className="text-slate-400">
            Total Injected: {streamStatus.total_simulated_events} events | {streamStatus.total_simulated_alerts} alerts
          </span>
        </div>
      )}

      {/* Scenario Selection Grid */}
      <div className="space-y-3">
        <label className="text-xs font-semibold text-slate-300 block font-mono uppercase tracking-wider">
          Select Intrusion Attack Scenario:
        </label>
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-2.5">
          {scenarios.map((sc) => {
            const isSelected = sc.id === selectedScenario;
            return (
              <button
                key={sc.id}
                onClick={() => handleScenarioSelect(sc)}
                className={`p-3 rounded-xl border text-left transition-all relative ${
                  isSelected
                    ? 'bg-sky-500/15 border-sky-500/60 shadow-lg shadow-sky-500/10'
                    : 'bg-slate-900/70 border-slate-800 hover:border-slate-700'
                }`}
              >
                <div className="flex items-center justify-between mb-1">
                  <span
                    className={`text-[9px] font-mono font-bold uppercase px-1.5 py-0.5 rounded ${
                      sc.id === 'benign'
                        ? 'bg-emerald-500/20 text-emerald-300'
                        : sc.bucket_type === 'trigger'
                        ? 'bg-rose-500/20 text-rose-300'
                        : 'bg-sky-500/20 text-sky-300'
                    }`}
                  >
                    {sc.category}
                  </span>
                  <span className="text-[10px] font-mono text-slate-500">{sc.burst_count} reqs</span>
                </div>
                <h4 className="text-xs font-bold text-white truncate">{sc.name}</h4>
                <p className="text-[11px] text-slate-400 font-mono mt-0.5 truncate">{sc.default_ip}</p>
              </button>
            );
          })}
        </div>
      </div>

      {/* Attacker IP & Fire Controls */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-2">
        <div className="md:col-span-2">
          <label className="text-xs font-semibold text-slate-300 block mb-1 font-mono">
            Simulated Attacker Source IP:
          </label>
          <div className="flex items-center space-x-2">
            <input
              type="text"
              value={customIp}
              onChange={(e) => setCustomIp(e.target.value)}
              placeholder="e.g. 185.220.101.5"
              className="flex-1 px-3.5 py-2.5 rounded-xl bg-slate-950 border border-slate-800 text-white font-mono text-xs focus:outline-none focus:border-sky-500 shadow-inner"
            />
            <button
              onClick={() => {
                const octet = Math.floor(Math.random() * 250) + 2;
                setCustomIp(`198.51.100.${octet}`);
              }}
              className="px-3 py-2.5 rounded-xl bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-800 text-xs font-mono transition-colors"
            >
              Random IP
            </button>
          </div>
          {currentMeta && (
            <p className="text-[11px] text-slate-400 mt-1 font-mono truncate">
              Sample log: {currentMeta.sample_payload}
            </p>
          )}
        </div>

        <div className="flex items-end">
          <button
            onClick={handleLaunchAttack}
            disabled={isLaunching}
            className="w-full py-2.5 px-5 rounded-xl bg-gradient-to-r from-rose-600 to-amber-600 hover:from-rose-500 hover:to-amber-500 text-white font-mono font-bold text-xs shadow-lg shadow-rose-600/20 flex items-center justify-center space-x-2 transition-all disabled:opacity-50"
          >
            {isLaunching ? (
              <>
                <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
                <span>Simulating Intrusion...</span>
              </>
            ) : (
              <>
                <Flame className="w-4 h-4 fill-white" />
                <span>Launch Attack Simulation</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Simulation Result Box */}
      {launchResult && (
        <div className="mt-4 p-4 rounded-xl bg-slate-950 border border-slate-800 font-mono text-xs space-y-3 animate-fade-in">
          <div className="flex items-center justify-between border-b border-slate-800 pb-2">
            <div className="flex items-center space-x-2">
              <span className="w-2.5 h-2.5 rounded-full bg-emerald-400 animate-pulse" />
              <span className="text-white font-bold">Detection Outcome:</span>
              <span className="text-slate-400">{launchResult.scenario}</span>
            </div>
            <span
              className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                launchResult.overflow_triggered
                  ? 'bg-rose-500/20 text-rose-400 border border-rose-500/40'
                  : 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/40'
              }`}
            >
              {launchResult.overflow_triggered ? 'BUCKET OVERFLOW TRIGGERED' : 'NORMAL / NO OVERFLOW'}
            </span>
          </div>

          <p className="text-slate-300 text-[11px] leading-relaxed">{launchResult.message}</p>

          <div className="grid grid-cols-2 md:grid-cols-4 gap-2.5 text-[11px]">
            <div className="p-2 rounded-lg bg-slate-900 border border-slate-800">
              <span className="text-slate-500 block text-[10px]">Events Poured</span>
              <span className="text-sky-400 font-bold">{launchResult.events_generated} logs</span>
            </div>
            <div className="p-2 rounded-lg bg-slate-900 border border-slate-800">
              <span className="text-slate-500 block text-[10px]">Attacker IP</span>
              <span className="text-slate-200 font-bold">{launchResult.attacker_ip}</span>
            </div>
            <div className="p-2 rounded-lg bg-slate-900 border border-slate-800">
              <span className="text-slate-500 block text-[10px]">Alerts Created</span>
              <span className="text-rose-400 font-bold">{launchResult.alerts_created.length} alert(s)</span>
            </div>
            <div className="p-2 rounded-lg bg-slate-900 border border-slate-800">
              <span className="text-slate-500 block text-[10px]">Enforced Decision</span>
              <span className="text-amber-400 font-bold">
                {launchResult.decisions_created[0]?.type || 'None'} ({launchResult.decisions_created[0]?.duration || '-'})
              </span>
            </div>
          </div>

          {/* Generated Log Snippets */}
          {launchResult.logs_generated.length > 0 && (
            <div className="mt-2 pt-2 border-t border-slate-800/80">
              <span className="text-slate-500 block text-[10px] mb-1">Generated Raw Logs Poured into Pipeline:</span>
              <div className="p-2.5 rounded-lg bg-black/60 border border-slate-900 text-slate-400 text-[10px] space-y-1 max-h-24 overflow-y-auto">
                {launchResult.logs_generated.map((l, idx) => (
                  <div key={idx} className="truncate">
                    <span className="text-purple-400 mr-2">[SIMULATED]</span>
                    <span>{l}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
