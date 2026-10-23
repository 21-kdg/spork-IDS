import React, { useState, useEffect } from 'react';
import {
  ScrollText,
  Search,
  Filter,
  PlusCircle,
  AlertCircle,
  CheckCircle,
  Send,
  Terminal,
  ChevronDown,
  ChevronRight,
} from 'lucide-react';
import { SecurityEvent } from '../types';
import { api } from '../services/api';

export const Events: React.FC = () => {
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [pageSize] = useState(20);
  const [serviceFilter, setServiceFilter] = useState('');
  const [suspiciousOnly, setSuspiciousOnly] = useState(false);
  const [simulatedOnly, setSimulatedOnly] = useState(false);
  const [searchIp, setSearchIp] = useState('');
  const [isLoading, setIsLoading] = useState(true);

  // Ingest manual log box state
  const [showIngestBox, setShowIngestBox] = useState(false);
  const [customLog, setCustomLog] = useState('');
  const [customServiceHint, setCustomServiceHint] = useState('ssh');
  const [ingestStatus, setIngestStatus] = useState<string | null>(null);
  const [expandedEventId, setExpandedEventId] = useState<number | null>(null);

  const loadEvents = async () => {
    setIsLoading(true);
    try {
      const res = await api.getEvents({
        service: serviceFilter || undefined,
        is_suspicious: suspiciousOnly ? true : undefined,
        is_simulated: simulatedOnly ? true : undefined,
        ip: searchIp || undefined,
        page,
        page_size: pageSize,
      });
      setEvents(res.items);
      setTotal(res.total);
    } catch (err) {
      console.error('Failed to load events:', err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadEvents();
  }, [page, serviceFilter, suspiciousOnly, simulatedOnly]);

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setPage(1);
    loadEvents();
  };

  const handleIngestSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!customLog.trim()) return;

    try {
      setIngestStatus('Processing log through pipeline...');
      const res = await api.ingestRawLogs([customLog.trim()], customServiceHint);
      setIngestStatus(
        `Success: Processed 1 log. Alerts triggered: ${res.alerts_triggered}, Decisions created: ${res.decisions_created}`
      );
      setCustomLog('');
      loadEvents();
      setTimeout(() => setIngestStatus(null), 5000);
    } catch (err: any) {
      setIngestStatus(`Error: ${err.message}`);
    }
  };

  const samplePresets = [
    {
      label: 'SSH Failed Auth',
      hint: 'ssh',
      log: 'Failed password for invalid user admin from 198.51.100.44 port 51222 ssh2',
    },
    {
      label: 'SQL Injection Payload',
      hint: 'nginx',
      log: '203.0.113.89 - - [23/Oct/2026:15:00:00 +0000] "GET /api/user?id=1%20UNION%20SELECT%20username,password%20FROM%20users-- HTTP/1.1" 200 450 "-" "sqlmap/1.7"',
    },
    {
      label: 'Directory Traversal',
      hint: 'nginx',
      log: '192.0.2.77 - - [23/Oct/2026:15:00:00 +0000] "GET /static/../../../../etc/passwd HTTP/1.1" 404 150 "-" "curl/7.88"',
    },
    {
      label: 'Firewall Port Drop',
      hint: 'firewall',
      log: 'iptables DROP: IN=eth0 SRC=198.51.100.99 DST=192.168.1.1 PROTO=TCP DPT=3389',
    },
  ];

  return (
    <div className="p-8 space-y-6 max-w-7xl mx-auto">
      {/* Page Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-white tracking-wide">Security Events & Audit Stream</h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Normalized log records ingested across SSH, Web, System, and Firewall sources ({total} records)
          </p>
        </div>

        <button
          onClick={() => setShowIngestBox(!showIngestBox)}
          className="flex items-center space-x-2 px-3.5 py-2 rounded-lg bg-sky-600 hover:bg-sky-500 text-white text-xs font-semibold font-mono transition-colors shadow-sm"
        >
          <PlusCircle className="w-4 h-4" />
          <span>{showIngestBox ? 'Hide Ingest Box' : 'Ingest Custom Log'}</span>
        </button>
      </div>

      {/* Manual Ingest Box */}
      {showIngestBox && (
        <div className="bg-[#0F172A] border border-sky-500/30 rounded-xl p-5 shadow-lg space-y-4 animate-fade-in">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2 text-xs font-bold font-mono text-sky-400">
              <Terminal className="w-4 h-4" />
              <span>Real-Time Security Log Ingestion & Parser Test</span>
            </div>
            <div className="flex items-center space-x-2">
              <span className="text-[11px] text-slate-400 font-mono">Quick Preset:</span>
              {samplePresets.map((preset, idx) => (
                <button
                  key={idx}
                  type="button"
                  onClick={() => {
                    setCustomLog(preset.log);
                    setCustomServiceHint(preset.hint);
                  }}
                  className="px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-[10px] font-mono border border-slate-700 transition-colors"
                >
                  {preset.label}
                </button>
              ))}
            </div>
          </div>

          <form onSubmit={handleIngestSubmit} className="space-y-3">
            <div className="flex items-center gap-3">
              <select
                value={customServiceHint}
                onChange={(e) => setCustomServiceHint(e.target.value)}
                className="px-3 py-2 rounded-lg bg-slate-900 border border-slate-800 text-slate-200 text-xs font-mono focus:outline-none focus:border-sky-500"
              >
                <option value="ssh">Service: SSH</option>
                <option value="nginx">Service: Nginx / HTTP</option>
                <option value="firewall">Service: Firewall</option>
                <option value="windows">Service: Windows Event</option>
                <option value="system">Service: System</option>
              </select>

              <input
                type="text"
                value={customLog}
                onChange={(e) => setCustomLog(e.target.value)}
                placeholder="Enter raw log line text to parse, enrich, and evaluate..."
                className="flex-1 px-4 py-2 rounded-lg bg-slate-900 border border-slate-800 text-slate-200 text-xs font-mono focus:outline-none focus:border-sky-500"
              />

              <button
                type="submit"
                className="px-4 py-2 rounded-lg bg-sky-500 hover:bg-sky-400 text-white text-xs font-bold font-mono flex items-center space-x-1.5 transition-colors shrink-0"
              >
                <Send className="w-3.5 h-3.5" />
                <span>Ingest Log</span>
              </button>
            </div>
          </form>

          {ingestStatus && (
            <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800 text-xs font-mono text-sky-300">
              {ingestStatus}
            </div>
          )}
        </div>
      )}

      {/* Filter Toolbar */}
      <div className="bg-[#0F172A] border border-slate-800 rounded-xl p-4 flex flex-wrap items-center justify-between gap-4">
        <form onSubmit={handleSearchSubmit} className="flex-1 min-w-[260px] flex items-center relative">
          <Search className="w-4 h-4 text-slate-400 absolute left-3" />
          <input
            type="text"
            value={searchIp}
            onChange={(e) => setSearchIp(e.target.value)}
            placeholder="Filter by IP address..."
            className="w-full pl-9 pr-4 py-2 rounded-lg bg-slate-900 border border-slate-800 text-slate-200 text-xs font-mono focus:outline-none focus:border-sky-500 transition-colors"
          />
        </form>

        <div className="flex items-center space-x-4">
          <select
            value={serviceFilter}
            onChange={(e) => {
              setServiceFilter(e.target.value);
              setPage(1);
            }}
            className="px-3 py-2 rounded-lg bg-slate-900 border border-slate-800 text-slate-300 text-xs font-mono focus:outline-none focus:border-sky-500"
          >
            <option value="">All Services</option>
            <option value="ssh">SSH</option>
            <option value="nginx">Nginx</option>
            <option value="firewall">Firewall</option>
            <option value="windows">Windows</option>
            <option value="system">System</option>
          </select>

          <label className="flex items-center space-x-2 text-xs font-mono text-slate-300 cursor-pointer select-none">
            <input
              type="checkbox"
              checked={suspiciousOnly}
              onChange={(e) => {
                setSuspiciousOnly(e.target.checked);
                setPage(1);
              }}
              className="rounded bg-slate-900 border-slate-800 text-sky-500 focus:ring-0 focus:outline-none"
            />
            <span>Suspicious only</span>
          </label>

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

      {/* Events Table */}
      <div className="bg-[#0F172A] border border-slate-800 rounded-xl overflow-hidden shadow-sm">
        {isLoading ? (
          <div className="py-20 flex flex-col items-center justify-center space-y-3 text-slate-400">
            <div className="w-8 h-8 border-2 border-sky-500 border-t-transparent rounded-full animate-spin" />
            <span className="text-xs font-mono">Streaming events...</span>
          </div>
        ) : events.length === 0 ? (
          <div className="py-20 text-center text-slate-500 space-y-2">
            <ScrollText className="w-8 h-8 mx-auto text-slate-600" />
            <p className="text-sm font-semibold">No security events found</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400 font-mono bg-slate-900/50">
                  <th className="py-3.5 px-4 font-semibold w-10"></th>
                  <th className="py-3.5 px-4 font-semibold">Timestamp</th>
                  <th className="py-3.5 px-4 font-semibold">Service</th>
                  <th className="py-3.5 px-4 font-semibold">Action</th>
                  <th className="py-3.5 px-4 font-semibold">Source IP</th>
                  <th className="py-3.5 px-4 font-semibold">Threat</th>
                  <th className="py-3.5 px-4 font-semibold">Raw Log Extract</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-mono">
                {events.map((ev) => {
                  const isExpanded = expandedEventId === ev.id;
                  return (
                    <React.Fragment key={ev.id}>
                      <tr
                        onClick={() => setExpandedEventId(isExpanded ? null : ev.id)}
                        className="hover:bg-slate-800/40 transition-colors cursor-pointer"
                      >
                        <td className="py-3 px-4 text-slate-500">
                          {isExpanded ? (
                            <ChevronDown className="w-3.5 h-3.5 text-sky-400" />
                          ) : (
                            <ChevronRight className="w-3.5 h-3.5 text-slate-600" />
                          )}
                        </td>
                        <td className="py-3 px-4 text-slate-400 text-[11px] whitespace-nowrap">
                          {new Date(ev.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                        </td>
                        <td className="py-3 px-4">
                          <span className="px-2 py-0.5 rounded text-[10px] bg-slate-800 text-slate-300 border border-slate-700 uppercase">
                            {ev.service}
                          </span>
                        </td>
                        <td className="py-3 px-4 font-medium text-slate-200">
                          <div className="flex items-center space-x-1.5">
                            <span>{ev.action}</span>
                            {ev.is_simulated && (
                              <span className="px-1.5 py-0.2 rounded text-[9px] font-mono font-bold bg-purple-500/20 text-purple-300 border border-purple-500/40">
                                SIMULATED
                              </span>
                            )}
                          </div>
                        </td>
                        <td className="py-3 px-4 text-sky-400 font-semibold">{ev.source_ip}</td>
                        <td className="py-3 px-4">
                          {ev.is_suspicious ? (
                            <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-rose-500/15 text-rose-400 border border-rose-500/30">
                              Suspicious
                            </span>
                          ) : (
                            <span className="px-2 py-0.5 rounded text-[10px] bg-slate-800 text-slate-400">
                              Benign
                            </span>
                          )}
                        </td>
                        <td className="py-3 px-4 text-slate-400 truncate max-w-md">{ev.raw_log}</td>
                      </tr>

                      {/* Expanded Event Details */}
                      {isExpanded && (
                        <tr className="bg-slate-900/80 border-b border-slate-800">
                          <td colSpan={7} className="p-4 space-y-3">
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono">
                              <div>
                                <span className="text-slate-400 font-semibold block mb-1">
                                  Parsed Metadata:
                                </span>
                                <pre className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-slate-300 text-[11px] overflow-x-auto">
                                  {JSON.stringify(ev.meta_data, null, 2)}
                                </pre>
                              </div>
                              <div>
                                <span className="text-slate-400 font-semibold block mb-1">
                                  Network & GeoIP Enrichment:
                                </span>
                                <pre className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-slate-300 text-[11px] overflow-x-auto">
                                  {JSON.stringify(ev.enrichment, null, 2)}
                                </pre>
                              </div>
                            </div>
                            <div>
                              <span className="text-slate-400 font-semibold block mb-1">Raw Log:</span>
                              <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 text-slate-200 text-xs font-mono">
                                {ev.raw_log}
                              </div>
                            </div>
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};
