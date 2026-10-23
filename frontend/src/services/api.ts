import {
  HealthStatus,
  DashboardSummary,
  Alert,
  SecurityEvent,
  Decision,
  ScenarioInfo,
  SystemMetrics,
  SystemSettings,
} from '../types';

// Use environment or relative path (/api)
const API_BASE = import.meta.env.VITE_API_URL || '/api';

async function fetchJson<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
  const url = `${API_BASE}${endpoint}`;
  const apiKey = localStorage.getItem('spork_api_key') || '';
  
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(options.headers as Record<string, string>),
  };
  
  if (apiKey) {
    headers['X-Api-Key'] = apiKey;
  }

  const response = await fetch(url, { ...options, headers });
  
  if (!response.ok) {
    let errorMsg = `API Error ${response.status}: ${response.statusText}`;
    try {
      const errData = await response.json();
      if (errData.detail) errorMsg = errData.detail;
    } catch (_) {}
    throw new Error(errorMsg);
  }

  if (response.status === 204) {
    return {} as T;
  }

  return response.json();
}

export const api = {
  // Health
  getHealth: () => fetchJson<HealthStatus>('/health'),

  // Dashboard
  getDashboardSummary: () => fetchJson<DashboardSummary>('/dashboard/summary'),

  // Alerts
  getAlerts: (params: { severity?: string; scenario?: string; ip?: string; status?: string; page?: number; page_size?: number } = {}) => {
    const query = new URLSearchParams();
    if (params.severity) query.append('severity', params.severity);
    if (params.scenario) query.append('scenario', params.scenario);
    if (params.ip) query.append('ip', params.ip);
    if (params.status) query.append('status', params.status);
    if (params.page) query.append('page', params.page.toString());
    if (params.page_size) query.append('page_size', params.page_size.toString());
    return fetchJson<{ total: number; items: Alert[]; page: number; page_size: number }>(`/alerts?${query.toString()}`);
  },
  getAlertDetail: (id: number) => fetchJson<Alert>(`/alerts/${id}`),
  updateAlertStatus: (id: number, status: string) =>
    fetchJson<Alert>(`/alerts/${id}/status`, {
      method: 'PATCH',
      body: JSON.stringify({ status }),
    }),
  deleteAlert: (id: number) => fetchJson<void>(`/alerts/${id}`, { method: 'DELETE' }),

  // Events & Logs
  getEvents: (params: { service?: string; is_suspicious?: boolean; ip?: string; page?: number; page_size?: number } = {}) => {
    const query = new URLSearchParams();
    if (params.service) query.append('service', params.service);
    if (params.is_suspicious !== undefined) query.append('is_suspicious', params.is_suspicious.toString());
    if (params.ip) query.append('ip', params.ip);
    if (params.page) query.append('page', params.page.toString());
    if (params.page_size) query.append('page_size', params.page_size.toString());
    return fetchJson<{ total: number; items: SecurityEvent[]; page: number; page_size: number }>(`/events?${query.toString()}`);
  },
  ingestRawLogs: (logs: string[], serviceHint?: string) =>
    fetchJson<{ processed_count: number; alerts_triggered: number; decisions_created: number; details: any[] }>(
      '/events/raw',
      {
        method: 'POST',
        body: JSON.stringify({ logs, service_hint: serviceHint }),
      }
    ),

  // Decisions
  getDecisions: (activeOnly: boolean = true) =>
    fetchJson<{ total: number; items: Decision[] }>(`/decisions?active_only=${activeOnly}`),
  createDecision: (data: { value: string; scope: string; type: string; duration: string; scenario: string }) =>
    fetchJson<Decision>('/decisions', {
      method: 'POST',
      body: JSON.stringify(data),
    }),
  revokeDecision: (id: number) =>
    fetchJson<{ status: string; id: number }>(`/decisions/${id}`, { method: 'DELETE' }),

  // Detection & Scenarios
  getScenarios: () => fetchJson<{ total: number; items: ScenarioInfo[] }>('/scenarios'),
  evaluateSandbox: (data: { scenario_name: string; source_ip: string; raw_log: string; service?: string; meta_data?: any }) =>
    fetchJson<{
      matched_filter: boolean;
      scenario_name: string;
      bucket_type: string;
      current_count: number;
      capacity: number;
      overflow: boolean;
      alert_generated?: any;
      decision?: any;
      reason: string;
    }>('/scenarios/evaluate', {
      method: 'POST',
      body: JSON.stringify(data),
    }),

  // Metrics
  getMetrics: () => fetchJson<SystemMetrics>('/metrics'),

  // Settings
  getSettings: () => fetchJson<SystemSettings>('/settings'),
  updateSettings: (data: Partial<SystemSettings>) =>
    fetchJson<SystemSettings>('/settings', {
      method: 'POST',
      body: JSON.stringify(data),
    }),
  testCrowdSecConnection: (lapi_url: string, api_key?: string) =>
    fetchJson<{ success: boolean; message: string; version?: string; latency_ms?: number }>(
      '/settings/test-crowdsec',
      {
        method: 'POST',
        body: JSON.stringify({ lapi_url, api_key }),
      }
    ),
};
