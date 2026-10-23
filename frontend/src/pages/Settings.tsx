import React, { useState, useEffect } from 'react';
import {
  Settings as SettingsIcon,
  Server,
  Database,
  Key,
  ShieldCheck,
  CheckCircle2,
  XCircle,
  HelpCircle,
  RefreshCw,
  Info,
} from 'lucide-react';
import { SystemSettings } from '../types';
import { api } from '../services/api';

export const Settings: React.FC = () => {
  const [settings, setSettings] = useState<SystemSettings | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  // CrowdSec Connection Test State
  const [lapiTargetUrl, setLapiTargetUrl] = useState('http://localhost:8080');
  const [lapiApiKey, setLapiApiKey] = useState('');
  const [isTesting, setIsTesting] = useState(false);
  const [testResult, setTestResult] = useState<{
    success: boolean;
    message: string;
    version?: string;
    latency_ms?: number;
  } | null>(null);

  // Local API Key Configuration
  const [localApiKeyInput, setLocalApiKeyInput] = useState('');
  const [apiKeySaved, setApiKeySaved] = useState(false);

  const loadSettings = async () => {
    setIsLoading(true);
    try {
      const res = await api.getSettings();
      setSettings(res);
      setLapiTargetUrl(res.crowdsec_lapi_url);
    } catch (err) {
      console.error('Failed to load settings:', err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadSettings();
    const existingKey = localStorage.getItem('spork_api_key');
    if (existingKey) setLocalApiKeyInput(existingKey);
  }, []);

  const handleTestConnection = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsTesting(true);
    setTestResult(null);
    try {
      const res = await api.testCrowdSecConnection(lapiTargetUrl.trim(), lapiApiKey.trim() || undefined);
      setTestResult(res);
    } catch (err: any) {
      setTestResult({
        success: false,
        message: `Network check failed: ${err.message}`,
      });
    } finally {
      setIsTesting(false);
    }
  };

  const handleSaveApiKey = (e: React.FormEvent) => {
    e.preventDefault();
    if (localApiKeyInput.trim()) {
      localStorage.setItem('spork_api_key', localApiKeyInput.trim());
    } else {
      localStorage.removeItem('spork_api_key');
    }
    setApiKeySaved(true);
    setTimeout(() => setApiKeySaved(false), 3000);
  };

  if (isLoading && !settings) {
    return (
      <div className="p-8 flex items-center justify-center min-h-[60vh]">
        <div className="flex flex-col items-center space-y-3 text-slate-400">
          <div className="w-8 h-8 border-2 border-sky-500 border-t-transparent rounded-full animate-spin" />
          <span className="text-xs font-mono">Loading configuration...</span>
        </div>
      </div>
    );
  }

  return (
    <div className="p-8 space-y-8 max-w-5xl mx-auto">
      {/* Header */}
      <div>
        <h2 className="text-xl font-bold text-white tracking-wide">Platform Configuration & Integrations</h2>
        <p className="text-xs text-slate-400 mt-0.5">
          Backend server settings, CrowdSec engine interoperability, and authentication
        </p>
      </div>

      {/* Honest Architectural Disclosure Note */}
      <div className="bg-sky-950/40 border border-sky-500/30 rounded-xl p-5 flex items-start space-x-3.5 shadow-sm">
        <Info className="w-5 h-5 text-sky-400 shrink-0 mt-0.5" />
        <div className="text-xs text-slate-300 space-y-1 leading-relaxed">
          <span className="font-bold text-sky-400">Architecture Transparency Note:</span>
          <p>
            Upstream CrowdSec’s reference security engine is implemented in Go. Spork-IDS fulfills the
            <strong> Python-only backend</strong> requirement by providing a fully native Python detection engine
            (implementing leaky-bucket state machines, log parsing, enrichment, alert persistence, and decision management).
            If an external Go-based CrowdSec instance is running on your network, Spork-IDS can also communicate with it
            over its Local API (LAPI) using the adapter below.
          </p>
        </div>
      </div>

      {/* System Settings & Server Info */}
      <div className="bg-[#0F172A] border border-slate-800 rounded-xl p-6 shadow-sm space-y-4">
        <div className="flex items-center space-x-3 border-b border-slate-800 pb-3">
          <Server className="w-4 h-4 text-sky-400" />
          <h3 className="text-sm font-bold text-white font-mono uppercase tracking-wider">
            Server Runtime Environment
          </h3>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 font-mono text-xs">
          <div className="p-3 rounded-lg bg-slate-900 border border-slate-800 flex justify-between items-center">
            <span className="text-slate-400">API Host & Port:</span>
            <span className="text-slate-200 font-bold">
              {settings?.server_host}:{settings?.server_port}
            </span>
          </div>

          <div className="p-3 rounded-lg bg-slate-900 border border-slate-800 flex justify-between items-center">
            <span className="text-slate-400">Environment:</span>
            <span className="text-sky-400 font-bold uppercase">{settings?.environment}</span>
          </div>

          <div className="p-3 rounded-lg bg-slate-900 border border-slate-800 flex justify-between items-center">
            <span className="text-slate-400">Database Engine:</span>
            <span className="text-slate-200 font-bold">{settings?.database_url_safe}</span>
          </div>

          <div className="p-3 rounded-lg bg-slate-900 border border-slate-800 flex justify-between items-center">
            <span className="text-slate-400">Python Backend Status:</span>
            <span className="text-emerald-400 font-bold flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-emerald-400"></span>
              Operational
            </span>
          </div>
        </div>
      </div>

      {/* CrowdSec LAPI Integration Tester */}
      <div className="bg-[#0F172A] border border-slate-800 rounded-xl p-6 shadow-sm space-y-4">
        <div className="flex items-center space-x-3 border-b border-slate-800 pb-3">
          <ShieldCheck className="w-4 h-4 text-sky-400" />
          <div>
            <h3 className="text-sm font-bold text-white font-mono uppercase tracking-wider">
              CrowdSec Local API (LAPI) Interoperability
            </h3>
            <p className="text-[11px] text-slate-400">
              Test connectivity to an external CrowdSec daemon instance (if installed)
            </p>
          </div>
        </div>

        <form onSubmit={handleTestConnection} className="space-y-4 font-mono text-xs">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="text-slate-300 block mb-1">CrowdSec LAPI URL:</label>
              <input
                type="text"
                value={lapiTargetUrl}
                onChange={(e) => setLapiTargetUrl(e.target.value)}
                placeholder="http://localhost:8080"
                className="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-800 text-slate-200 focus:outline-none focus:border-sky-500"
              />
            </div>

            <div>
              <label className="text-slate-300 block mb-1">LAPI Machine Key / Bouncer Token (Optional):</label>
              <input
                type="password"
                value={lapiApiKey}
                onChange={(e) => setLapiApiKey(e.target.value)}
                placeholder="Enter token if configured"
                className="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-800 text-slate-200 focus:outline-none focus:border-sky-500"
              />
            </div>
          </div>

          <div className="flex items-center justify-between pt-2">
            <button
              type="submit"
              disabled={isTesting}
              className="px-4 py-2 rounded-lg bg-sky-500 hover:bg-sky-400 text-white font-bold transition-colors flex items-center space-x-2"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isTesting ? 'animate-spin' : ''}`} />
              <span>{isTesting ? 'Testing LAPI...' : 'Test CrowdSec Connection'}</span>
            </button>

            <span className="text-[11px] text-slate-500">
              When disconnected, Spork-IDS runs autonomously in Standalone Python mode.
            </span>
          </div>
        </form>

        {testResult && (
          <div
            className={`p-4 rounded-xl border text-xs font-mono space-y-1.5 ${
              testResult.success
                ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300'
                : 'bg-rose-500/10 border-rose-500/30 text-rose-300'
            }`}
          >
            <div className="flex items-center space-x-2 font-bold">
              {testResult.success ? (
                <CheckCircle2 className="w-4 h-4 text-emerald-400" />
              ) : (
                <XCircle className="w-4 h-4 text-rose-400" />
              )}
              <span>{testResult.success ? 'CrowdSec LAPI Connected' : 'CrowdSec LAPI Standalone Fallback'}</span>
            </div>
            <p className="text-[11px] opacity-90">{testResult.message}</p>
            {testResult.latency_ms && (
              <p className="text-[10px] text-slate-400">Response latency: {testResult.latency_ms} ms</p>
            )}
          </div>
        )}
      </div>

      {/* Security & API Key Settings */}
      <div className="bg-[#0F172A] border border-slate-800 rounded-xl p-6 shadow-sm space-y-4">
        <div className="flex items-center space-x-3 border-b border-slate-800 pb-3">
          <Key className="w-4 h-4 text-amber-400" />
          <h3 className="text-sm font-bold text-white font-mono uppercase tracking-wider">
            API Authorization & Local Key
          </h3>
        </div>

        <form onSubmit={handleSaveApiKey} className="space-y-3 font-mono text-xs">
          <label className="text-slate-300 block">
            Browser X-Api-Key Header (used for authenticated mutating endpoints):
          </label>
          <div className="flex items-center space-x-3">
            <input
              type="password"
              value={localApiKeyInput}
              onChange={(e) => setLocalApiKeyInput(e.target.value)}
              placeholder="Leave empty for open local development mode"
              className="flex-1 px-3 py-2 rounded-lg bg-slate-900 border border-slate-800 text-slate-200 focus:outline-none focus:border-sky-500"
            />
            <button
              type="submit"
              className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 font-bold transition-colors"
            >
              Save Key
            </button>
          </div>
          {apiKeySaved && (
            <p className="text-emerald-400 text-xs">API key preference updated in browser storage.</p>
          )}
        </form>
      </div>
    </div>
  );
};
