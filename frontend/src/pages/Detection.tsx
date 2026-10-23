import React, { useState, useEffect } from 'react';
import {
  ShieldAlert,
  Play,
  CheckCircle2,
  AlertOctagon,
  Layers,
  Activity,
  Cpu,
  Clock,
  Zap,
} from 'lucide-react';
import { ScenarioInfo } from '../types';
import { api } from '../services/api';
import { AttackSimulatorWidget } from '../components/AttackSimulatorWidget';

export const Detection: React.FC = () => {
  const [scenarios, setScenarios] = useState<ScenarioInfo[]>([]);
  const [isLoading, setIsLoading] = useState(true);

  // Sandbox Evaluator State
  const [selectedScenario, setSelectedScenario] = useState('spork/ssh-bf');
  const [testIp, setTestIp] = useState('192.168.1.199');
  const [testLog, setTestLog] = useState(
    'Failed password for invalid user admin from 192.168.1.199 port 52123 ssh2'
  );
  const [evalResult, setEvalResult] = useState<any | null>(null);
  const [isEvaluating, setIsEvaluating] = useState(false);

  const loadScenarios = async () => {
    setIsLoading(true);
    try {
      const res = await api.getScenarios();
      setScenarios(res.items);
    } catch (err) {
      console.error('Failed to load scenarios:', err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadScenarios();
  }, []);

  const handleScenarioChange = (name: string) => {
    setSelectedScenario(name);
    setEvalResult(null);

    // Provide preset log lines matching each scenario
    if (name === 'spork/ssh-bf') {
      setTestLog('Failed password for invalid user admin from 192.168.1.199 port 52123 ssh2');
    } else if (name === 'spork/http-crawl-bf') {
      setTestLog('192.168.1.199 - - [23/Oct/2026:12:00:00 +0000] "GET /admin/setup.php HTTP/1.1" 404 160');
    } else if (name === 'spork/http-sqli') {
      setTestLog('192.168.1.199 - - [23/Oct/2026:12:00:00 +0000] "GET /items?id=1%20UNION%20SELECT%20*%20FROM%20users HTTP/1.1" 200 450');
    } else if (name === 'spork/http-path-traversal') {
      setTestLog('192.168.1.199 - - [23/Oct/2026:12:00:00 +0000] "GET /../../../../etc/shadow HTTP/1.1" 404 120');
    } else if (name === 'spork/port-scan') {
      setTestLog('iptables DROP: IN=eth0 SRC=192.168.1.199 DST=10.0.0.1 PROTO=TCP DPT=8080');
    } else if (name === 'spork/auth-credential-stuffing') {
      setTestLog('Failed password for root from 192.168.1.199 port 51230 ssh2');
    }
  };

  const handleEvaluate = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsEvaluating(true);
    try {
      const res = await api.evaluateSandbox({
        scenario_name: selectedScenario,
        source_ip: testIp.trim(),
        raw_log: testLog.trim(),
        meta_data: {
          is_sqli: testLog.toLowerCase().includes('union select'),
          is_traversal: testLog.includes('../') || testLog.includes('etc/shadow'),
          action: testLog.includes('Failed password') ? 'failed_login' : 'test_action',
        },
      });
      setEvalResult(res);
    } catch (err: any) {
      alert(`Evaluation error: ${err.message}`);
    } finally {
      setIsEvaluating(false);
    }
  };

  return (
    <div className="p-8 space-y-8 max-w-7xl mx-auto">
      {/* Page Header */}
      <div>
        <h2 className="text-xl font-bold text-white tracking-wide">Detection Scenarios & Rules</h2>
        <p className="text-xs text-slate-400 mt-0.5">
          Native Python scenario engine reproducing CrowdSec's Leaky Bucket, Trigger, and Uniq bucket models
        </p>
      </div>

      {/* Scenario Catalog Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
        {scenarios.map((sc) => (
          <div
            key={sc.name}
            className="bg-[#0F172A] border border-slate-800 rounded-xl p-5 shadow-sm space-y-4 hover:border-slate-700 transition-all flex flex-col justify-between"
          >
            <div>
              <div className="flex items-center justify-between">
                <span
                  className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase font-mono ${
                    sc.type === 'trigger'
                      ? 'bg-rose-500/15 text-rose-400 border border-rose-500/30'
                      : sc.type === 'uniq'
                      ? 'bg-purple-500/15 text-purple-400 border border-purple-500/30'
                      : 'bg-sky-500/15 text-sky-400 border border-sky-500/30'
                  }`}
                >
                  {sc.type} Bucket
                </span>
                <span className="text-[11px] font-mono text-slate-500">
                  {sc.active_buckets} active bucket(s)
                </span>
              </div>

              <h3 className="text-sm font-bold text-white font-mono mt-3">{sc.name}</h3>
              <p className="text-xs text-slate-400 mt-1 leading-relaxed">{sc.description}</p>
            </div>

            <div className="pt-3 border-t border-slate-800/80 grid grid-cols-3 gap-2 text-center font-mono text-[11px]">
              <div className="bg-slate-900/80 p-2 rounded-lg border border-slate-800/60">
                <span className="text-slate-500 block text-[10px]">Capacity</span>
                <span className="text-slate-200 font-bold">{sc.capacity}</span>
              </div>
              <div className="bg-slate-900/80 p-2 rounded-lg border border-slate-800/60">
                <span className="text-slate-500 block text-[10px]">Leak Speed</span>
                <span className="text-slate-200 font-bold">{sc.leakspeed}</span>
              </div>
              <div className="bg-slate-900/80 p-2 rounded-lg border border-slate-800/60">
                <span className="text-slate-500 block text-[10px]">Overflows</span>
                <span className="text-rose-400 font-bold">{sc.overflow_count}</span>
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Live Intrusion Simulation Engine */}
      <AttackSimulatorWidget onRefresh={loadScenarios} />

      {/* Interactive Scenario Sandbox Evaluator */}
      <div className="bg-[#0F172A] border border-slate-800 rounded-2xl p-6 shadow-sm space-y-5">
        <div className="flex items-center space-x-3 border-b border-slate-800 pb-4">
          <div className="p-2 rounded-lg bg-sky-500/10 text-sky-400 border border-sky-500/20">
            <Zap className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-base font-bold text-white">Live Rule Sandbox Evaluator</h3>
            <p className="text-xs text-slate-400">
              Simulate rule matching and bucket math in an isolated test environment without mutating production state.
            </p>
          </div>
        </div>

        <form onSubmit={handleEvaluate} className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div>
              <label className="text-xs font-semibold text-slate-300 block mb-1 font-mono">
                Target Scenario:
              </label>
              <select
                value={selectedScenario}
                onChange={(e) => handleScenarioChange(e.target.value)}
                className="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-800 text-slate-200 text-xs font-mono focus:outline-none focus:border-sky-500"
              >
                {scenarios.map((sc) => (
                  <option key={sc.name} value={sc.name}>
                    {sc.name} ({sc.type})
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label className="text-xs font-semibold text-slate-300 block mb-1 font-mono">
                Attacker IP (Stack Key):
              </label>
              <input
                type="text"
                value={testIp}
                onChange={(e) => setTestIp(e.target.value)}
                className="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-800 text-slate-200 text-xs font-mono focus:outline-none focus:border-sky-500"
              />
            </div>

            <div className="flex items-end">
              <button
                type="submit"
                disabled={isEvaluating}
                className="w-full py-2 px-4 rounded-lg bg-sky-500 hover:bg-sky-400 text-white text-xs font-bold font-mono transition-colors flex items-center justify-center space-x-2 shadow-sm"
              >
                <Play className="w-4 h-4 fill-white" />
                <span>{isEvaluating ? 'Evaluating...' : 'Test Evaluation'}</span>
              </button>
            </div>
          </div>

          <div>
            <label className="text-xs font-semibold text-slate-300 block mb-1 font-mono">
              Raw Log Payload to Test:
            </label>
            <textarea
              rows={2}
              value={testLog}
              onChange={(e) => setTestLog(e.target.value)}
              className="w-full p-3 rounded-lg bg-slate-950 border border-slate-800 text-slate-200 text-xs font-mono focus:outline-none focus:border-sky-500"
            />
          </div>
        </form>

        {/* Evaluation Output Result */}
        {evalResult && (
          <div className="mt-4 p-4 rounded-xl bg-slate-900 border border-slate-800 font-mono text-xs space-y-3 animate-fade-in">
            <div className="flex items-center justify-between border-b border-slate-800 pb-2">
              <span className="text-slate-400 font-bold">Simulation Result:</span>
              <span
                className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                  evalResult.overflow
                    ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30'
                    : evalResult.matched_filter
                    ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                    : 'bg-slate-800 text-slate-400'
                }`}
              >
                {evalResult.overflow
                  ? 'Overflow Triggered'
                  : evalResult.matched_filter
                  ? 'Filter Matched (No Overflow)'
                  : 'Filter Miss'}
              </span>
            </div>

            <p className="text-slate-300">{evalResult.reason}</p>

            <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-[11px]">
              <div className="p-2 rounded bg-slate-950 border border-slate-800">
                <span className="text-slate-500 block">Scenario</span>
                <span className="text-sky-400 font-bold">{evalResult.scenario_name}</span>
              </div>
              <div className="p-2 rounded bg-slate-950 border border-slate-800">
                <span className="text-slate-500 block">Bucket Type</span>
                <span className="text-slate-200 uppercase">{evalResult.bucket_type}</span>
              </div>
              <div className="p-2 rounded bg-slate-950 border border-slate-800">
                <span className="text-slate-500 block">Drops / Capacity</span>
                <span className="text-slate-200 font-bold">
                  {evalResult.current_count} / {evalResult.capacity}
                </span>
              </div>
              <div className="p-2 rounded bg-slate-950 border border-slate-800">
                <span className="text-slate-500 block">Decision Emitted</span>
                <span className="text-rose-400 font-bold">
                  {evalResult.decision ? `${evalResult.decision.type} (${evalResult.decision.duration})` : 'None'}
                </span>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
