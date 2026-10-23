import {
  HealthStatus,
  DashboardSummary,
  Alert,
  SecurityEvent,
  Decision,
  ScenarioInfo,
  SystemMetrics,
  SystemSettings,
  SimulationScenario,
  SimulationLaunchResult,
  SimulationStatus,
} from '../types';

// Use environment or relative path (/api)
const API_BASE = import.meta.env.VITE_API_URL || '/api';

// In-memory client-side fallback state for standalone Vercel / offline demo mode
const clientState = {
  isOffline: false,
  totalEvents: 48,
  totalAlerts: 4,
  activeBans: 3,
  events: [
    {
      id: 101,
      timestamp: new Date().toISOString(),
      source_ip: '185.220.101.5',
      service: 'ssh',
      action: 'failed_login',
      raw_log: 'sshd[28410]: Failed password for invalid user admin from 185.220.101.5 port 42812 ssh2',
      is_suspicious: true,
      is_simulated: true,
      meta_data: { user: 'admin', port: 42812, log_type: 'ssh_auth_failure' },
      enrichment: { country: 'Germany', country_code: 'DE', asn: 'AS208251', ip_type: 'Tor Exit Node' },
    },
    {
      id: 102,
      timestamp: new Date(Date.now() - 30000).toISOString(),
      source_ip: '45.33.32.156',
      service: 'nginx',
      action: 'sqli_attempt',
      raw_log: '45.33.32.156 - - "GET /api/v1/products?id=1%20UNION%20SELECT%20username,password_hash%20FROM%20users-- HTTP/1.1" 200 450 "-" "sqlmap/1.8"',
      is_suspicious: true,
      is_simulated: true,
      meta_data: { is_sqli: true, http_status: 200 },
      enrichment: { country: 'United States', country_code: 'US', asn: 'AS63949', ip_type: 'Data Center' },
    },
    {
      id: 103,
      timestamp: new Date(Date.now() - 60000).toISOString(),
      source_ip: '94.102.61.12',
      service: 'nginx',
      action: 'traversal_attempt',
      raw_log: '94.102.61.12 - - "GET /static/../../../../etc/passwd HTTP/1.1" 404 153 "-" "Mozilla/5.0"',
      is_suspicious: true,
      is_simulated: true,
      meta_data: { is_traversal: true, http_status: 404 },
      enrichment: { country: 'Netherlands', country_code: 'NL', asn: 'AS202425', ip_type: 'Hosting' },
    },
    {
      id: 104,
      timestamp: new Date(Date.now() - 90000).toISOString(),
      source_ip: '192.168.1.105',
      service: 'nginx',
      action: 'http_request',
      raw_log: '192.168.1.105 - - "GET /index.html HTTP/1.1" 200 1204 "https://internal.lan" "Mozilla/5.0"',
      is_suspicious: false,
      is_simulated: false,
      meta_data: { http_status: 200 },
      enrichment: { country: 'Local Network', country_code: 'LAN', ip_type: 'Private' },
    },
  ] as SecurityEvent[],
  alerts: [
    {
      id: 1,
      uuid: '9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d',
      scenario: 'spork/ssh-bf',
      message: 'SSH authentication brute-force attempt from single IP address (185.220.101.5)',
      severity: 'high' as const,
      source_ip: '185.220.101.5',
      source_scope: 'Ip',
      events_count: 6,
      capacity: 5,
      leakspeed: '20s',
      start_at: new Date(Date.now() - 120000).toISOString(),
      stop_at: new Date(Date.now() - 10000).toISOString(),
      created_at: new Date(Date.now() - 10000).toISOString(),
      status: 'active',
      is_simulated: true,
      meta_data: {
        enrichment: { country: 'Germany', country_code: 'DE', asn: 'AS208251', ip_type: 'Tor Exit Node' },
      },
      decisions: [
        {
          id: 1,
          uuid: 'dec-01',
          origin: 'spork-ids',
          type: 'ban',
          scope: 'Ip',
          value: '185.220.101.5',
          scenario: 'spork/ssh-bf',
          duration: '4h',
          until: new Date(Date.now() + 14400000).toISOString(),
          is_active: true,
          simulated: true,
          created_at: new Date().toISOString(),
          alert_id: 1,
        },
      ],
    },
    {
      id: 2,
      uuid: 'c8273612-4fbc-4921-992a-faec1287391a',
      scenario: 'spork/http-sqli',
      message: 'SQL injection exploit payload targeting web applications (45.33.32.156)',
      severity: 'critical' as const,
      source_ip: '45.33.32.156',
      source_scope: 'Ip',
      events_count: 1,
      capacity: 0,
      leakspeed: '0s',
      start_at: new Date(Date.now() - 30000).toISOString(),
      stop_at: new Date(Date.now() - 30000).toISOString(),
      created_at: new Date(Date.now() - 30000).toISOString(),
      status: 'active',
      is_simulated: true,
      meta_data: {
        enrichment: { country: 'United States', country_code: 'US', asn: 'AS63949', ip_type: 'Data Center' },
      },
      decisions: [
        {
          id: 2,
          uuid: 'dec-02',
          origin: 'spork-ids',
          type: 'ban',
          scope: 'Ip',
          value: '45.33.32.156',
          scenario: 'spork/http-sqli',
          duration: '24h',
          until: new Date(Date.now() + 86400000).toISOString(),
          is_active: true,
          simulated: true,
          created_at: new Date().toISOString(),
          alert_id: 2,
        },
      ],
    },
  ] as Alert[],
  decisions: [
    {
      id: 1,
      uuid: 'dec-01',
      origin: 'spork-ids',
      type: 'ban',
      scope: 'Ip',
      value: '185.220.101.5',
      scenario: 'spork/ssh-bf',
      duration: '4h',
      until: new Date(Date.now() + 14400000).toISOString(),
      is_active: true,
      simulated: true,
      created_at: new Date().toISOString(),
      alert_id: 1,
    },
    {
      id: 2,
      uuid: 'dec-02',
      origin: 'spork-ids',
      type: 'ban',
      scope: 'Ip',
      value: '45.33.32.156',
      scenario: 'spork/http-sqli',
      duration: '24h',
      until: new Date(Date.now() + 86400000).toISOString(),
      is_active: true,
      simulated: true,
      created_at: new Date().toISOString(),
      alert_id: 2,
    },
    {
      id: 3,
      uuid: 'dec-03',
      origin: 'spork-ids',
      type: 'ban',
      scope: 'Ip',
      value: '94.102.61.12',
      scenario: 'spork/http-path-traversal',
      duration: '24h',
      until: new Date(Date.now() + 86400000).toISOString(),
      is_active: true,
      simulated: true,
      created_at: new Date().toISOString(),
      alert_id: 3,
    },
  ] as Decision[],
  scenarios: [
    {
      name: 'spork/ssh-bf',
      description: 'SSH authentication brute-force attempt from single IP address',
      type: 'leaky' as const,
      capacity: 5,
      leakspeed: '20s',
      filter_hint: 'Filter criteria for spork/ssh-bf',
      poured_events: 12,
      overflow_count: 2,
      active_buckets: 1,
    },
    {
      name: 'spork/http-crawl-bf',
      description: 'Aggressive web route 404/403 enumeration and crawl probing',
      type: 'leaky' as const,
      capacity: 8,
      leakspeed: '15s',
      filter_hint: 'Filter criteria for spork/http-crawl-bf',
      poured_events: 18,
      overflow_count: 1,
      active_buckets: 1,
    },
    {
      name: 'spork/http-sqli',
      description: 'SQL injection exploit payload targeting web applications',
      type: 'trigger' as const,
      capacity: 0,
      leakspeed: '0s',
      filter_hint: 'Filter criteria for spork/http-sqli',
      poured_events: 3,
      overflow_count: 3,
      active_buckets: 0,
    },
    {
      name: 'spork/http-path-traversal',
      description: 'Directory and path traversal payload targeting web server paths',
      type: 'trigger' as const,
      capacity: 0,
      leakspeed: '0s',
      filter_hint: 'Filter criteria for spork/http-path-traversal',
      poured_events: 2,
      overflow_count: 2,
      active_buckets: 0,
    },
    {
      name: 'spork/port-scan',
      description: 'Horizontal or vertical TCP/UDP port reconnaissance scan',
      type: 'uniq' as const,
      capacity: 5,
      leakspeed: '45s',
      filter_hint: 'Filter criteria for spork/port-scan',
      poured_events: 8,
      overflow_count: 1,
      active_buckets: 1,
    },
    {
      name: 'spork/auth-credential-stuffing',
      description: 'Multi-account credential stuffing attack using distinct user targets',
      type: 'uniq' as const,
      capacity: 4,
      leakspeed: '60s',
      filter_hint: 'Filter criteria for spork/auth-credential-stuffing',
      poured_events: 5,
      overflow_count: 1,
      active_buckets: 1,
    },
  ] as ScenarioInfo[],
  isStreamRunning: false,
};

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

  try {
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

    clientState.isOffline = false;
    return response.json();
  } catch (err: any) {
    // If backend is unreachable (e.g. running standalone on Vercel preview), activate client simulation fallback
    console.warn(`[Spork-IDS] Live API call to ${endpoint} failed (${err.message}). Using client simulation fallback.`);
    clientState.isOffline = true;
    return getClientFallback<T>(endpoint, options);
  }
}

// Fallback generator for smooth operation when backend is offline
function getClientFallback<T>(endpoint: string, options: RequestInit): T {
  const cleanEndpoint = endpoint.split('?')[0];

  if (cleanEndpoint === '/health') {
    return {
      status: 'ok',
      version: '1.0.0 (Client Simulated Mode)',
      engine: 'spork-ids-client-simulator',
      uptime_seconds: 3600,
      crowdsec_integration: 'standalone-simulation',
      active_decisions: clientState.activeBans,
      total_alerts: clientState.totalAlerts,
      events_processed: clientState.totalEvents,
    } as T;
  }

  if (cleanEndpoint === '/dashboard/summary') {
    const hours = ['14:00', '15:00', '16:00', '17:00', '18:00', '19:00', '20:00', '21:00', '22:00', '23:00', '00:00', '01:00'];
    return {
      engine_status: 'operational (simulation)',
      uptime_seconds: 3600,
      total_events: clientState.totalEvents,
      events_last_24h: clientState.totalEvents,
      total_alerts: clientState.totalAlerts,
      active_decisions: clientState.activeBans,
      scenarios_active: 6,
      top_attacking_ips: [
        { ip: '185.220.101.5', event_count: 12 },
        { ip: '45.33.32.156', event_count: 8 },
        { ip: '116.202.120.88', event_count: 9 },
        { ip: '94.102.61.12', event_count: 5 },
        { ip: '198.51.100.27', event_count: 6 },
      ],
      recent_alerts: clientState.alerts,
      top_scenarios: [
        { scenario: 'spork/ssh-bf', alert_count: 2 },
        { scenario: 'spork/http-sqli', alert_count: 1 },
        { scenario: 'spork/http-path-traversal', alert_count: 1 },
      ],
      events_by_service: { ssh: 18, nginx: 24, firewall: 6 },
      hourly_trend: hours.map((h, i) => ({
        hour: h,
        events: 4 + (i * 3) % 15,
        alerts: i % 4 === 0 ? 1 : 0,
      })),
      crowdsec_status: {
        enabled: false,
        configured_url: 'http://localhost:8080',
        connected: false,
        mode: 'standalone',
        description: 'Native Python Security Engine in Simulation Mode',
      },
    } as T;
  }

  if (cleanEndpoint === '/alerts') {
    return {
      total: clientState.alerts.length,
      items: clientState.alerts,
      page: 1,
      page_size: 25,
    } as T;
  }

  if (cleanEndpoint === '/events') {
    return {
      total: clientState.events.length,
      items: clientState.events,
      page: 1,
      page_size: 25,
    } as T;
  }

  if (cleanEndpoint === '/decisions') {
    return {
      total: clientState.decisions.length,
      items: clientState.decisions,
    } as T;
  }

  if (cleanEndpoint === '/scenarios') {
    return {
      total: clientState.scenarios.length,
      items: clientState.scenarios,
    } as T;
  }

  if (cleanEndpoint === '/simulation/scenarios') {
    return [
      {
        id: 'spork/ssh-bf',
        name: 'SSH Brute-Force Attack',
        description: 'Simulates rapid SSH authentication failures from a single attacker targeting administrative usernames.',
        category: 'Authentication',
        default_ip: '185.220.101.5',
        sample_payload: 'Failed password for invalid user admin from 185.220.101.5 port 42812 ssh2',
        bucket_type: 'leaky',
        burst_count: 6,
      },
      {
        id: 'spork/http-sqli',
        name: 'SQL Injection (SQLi) Probe',
        description: 'Exploits web endpoint query parameters with UNION SELECT and database extraction syntax.',
        category: 'Web Application',
        default_ip: '45.33.32.156',
        sample_payload: 'GET /api/v1/products?id=1%20UNION%20SELECT%20username,password_hash%20FROM%20users-- HTTP/1.1" 200 450 "-" "sqlmap/1.8"',
        bucket_type: 'trigger',
        burst_count: 1,
      },
      {
        id: 'spork/http-path-traversal',
        name: 'Path / Directory Traversal',
        description: 'Attempts unauthorized access to sensitive system configuration files like /etc/passwd and win.ini.',
        category: 'Web Application',
        default_ip: '94.102.61.12',
        sample_payload: 'GET /static/../../../../etc/passwd HTTP/1.1" 404 153 "-" "Mozilla/5.0"',
        bucket_type: 'trigger',
        burst_count: 1,
      },
      {
        id: 'spork/port-scan',
        name: 'TCP Port Reconnaissance Scan',
        description: 'Probes multiple distinct network service ports (21, 22, 80, 443, 3306, 8080) to identify open services.',
        category: 'Network Recon',
        default_ip: '198.51.100.27',
        sample_payload: 'iptables: DROP: IN=eth0 SRC=198.51.100.27 DST=10.0.0.1 PROTO=TCP DPT=22',
        bucket_type: 'uniq',
        burst_count: 6,
      },
      {
        id: 'spork/http-crawl-bf',
        name: 'Aggressive Web Route Enumeration',
        description: 'Probes high-value web endpoints (/wp-admin, /.env, /actuator/health, /phpmyadmin) causing 404/403 errors.',
        category: 'Web Application',
        default_ip: '116.202.120.88',
        sample_payload: 'GET /.env HTTP/1.1" 404 162 "-" "Go-http-client/1.1"',
        bucket_type: 'leaky',
        burst_count: 9,
      },
      {
        id: 'spork/auth-credential-stuffing',
        name: 'Multi-Account Credential Stuffing',
        description: 'Attacker tests credentials against multiple target accounts from a single IP address in rapid succession.',
        category: 'Identity & Access',
        default_ip: '203.0.113.89',
        sample_payload: 'Failed password for root from 203.0.113.89 port 51230 ssh2',
        bucket_type: 'uniq',
        burst_count: 5,
      },
      {
        id: 'benign',
        name: 'Benign Network & Web Traffic',
        description: 'Normal legitimate application requests, static asset loads, and successful administrative logins.',
        category: 'Legitimate Traffic',
        default_ip: '192.168.1.105',
        sample_payload: 'GET /dashboard HTTP/1.1" 200 4520 "https://app.local" "Mozilla/5.0"',
        bucket_type: 'none',
        burst_count: 3,
      },
    ] as T;
  }

  if (cleanEndpoint === '/simulation/launch' || cleanEndpoint === '/scenarios/simulate') {
    let body: any = {};
    try {
      body = JSON.parse(options.body as string || '{}');
    } catch (_) {}

    const scenario = body.scenario || 'spork/ssh-bf';
    const attackerIp = body.source_ip || '185.220.101.99';
    const isBenign = scenario === 'benign';
    const eventCount = isBenign ? 3 : (scenario === 'spork/http-crawl-bf' ? 9 : 6);

    clientState.totalEvents += eventCount;
    if (!isBenign) {
      clientState.totalAlerts += 1;
      clientState.activeBans += 1;

      const newAlert: Alert = {
        id: clientState.alerts.length + 1,
        uuid: `sim-alert-${Date.now()}`,
        scenario,
        message: `Simulated attack overflow for ${scenario} from ${attackerIp}`,
        severity: scenario.includes('sqli') || scenario.includes('traversal') ? 'critical' : 'high',
        source_ip: attackerIp,
        source_scope: 'Ip',
        events_count: eventCount,
        capacity: 5,
        leakspeed: '20s',
        start_at: new Date(Date.now() - 5000).toISOString(),
        stop_at: new Date().toISOString(),
        created_at: new Date().toISOString(),
        status: 'active',
        is_simulated: true,
        meta_data: {
          enrichment: { country: 'Simulated Network', country_code: 'SIM', ip_type: 'Attacker' },
        },
        decisions: [
          {
            id: clientState.decisions.length + 1,
            uuid: `sim-dec-${Date.now()}`,
            origin: 'spork-ids',
            type: 'ban',
            scope: 'Ip',
            value: attackerIp,
            scenario,
            duration: '4h',
            until: new Date(Date.now() + 14400000).toISOString(),
            is_active: true,
            simulated: true,
            created_at: new Date().toISOString(),
            alert_id: clientState.alerts.length + 1,
          },
        ],
      };

      clientState.alerts.unshift(newAlert);
      clientState.decisions.unshift(newAlert.decisions[0]);
    }

    return {
      status: 'success',
      scenario,
      attacker_ip: attackerIp,
      events_generated: eventCount,
      overflow_triggered: !isBenign,
      logs_generated: [
        `[SIMULATED] Attack log burst generated for ${scenario} from ${attackerIp}`,
        `[SIMULATED] Detection rule evaluation matched filter criteria`,
        !isBenign ? `[SIMULATED] Scenario bucket overflowed! Alert and IP ban enforced.` : `[SIMULATED] Benign traffic processed without alert.`
      ],
      alerts_created: isBenign ? [] : [{
        id: clientState.alerts.length,
        uuid: `sim-alert-${Date.now()}`,
        scenario,
        severity: 'high',
        source_ip: attackerIp,
        message: `Simulated attack overflow for ${scenario}`,
      }],
      decisions_created: isBenign ? [] : [{
        id: clientState.decisions.length,
        type: 'ban',
        value: attackerIp,
        duration: '4h',
        scenario,
      }],
      message: `Simulated ${scenario} successfully. ${!isBenign ? 'Bucket overflowed and ban created!' : 'Normal traffic generated.'}`,
    } as T;
  }

  if (cleanEndpoint === '/simulation/status') {
    return {
      is_running: clientState.isStreamRunning,
      interval_seconds: 3.0,
      total_simulated_events: clientState.totalEvents,
      total_simulated_alerts: clientState.totalAlerts,
      active_scenario: 'spork/ssh-bf',
      last_run_timestamp: new Date().toISOString(),
    } as T;
  }

  if (cleanEndpoint === '/simulation/start') {
    clientState.isStreamRunning = true;
    return {
      is_running: true,
      interval_seconds: 3.0,
      total_simulated_events: clientState.totalEvents,
      total_simulated_alerts: clientState.totalAlerts,
      active_scenario: 'continuous-stream',
      last_run_timestamp: new Date().toISOString(),
    } as T;
  }

  if (cleanEndpoint === '/simulation/stop') {
    clientState.isStreamRunning = false;
    return {
      is_running: false,
      interval_seconds: 3.0,
      total_simulated_events: clientState.totalEvents,
      total_simulated_alerts: clientState.totalAlerts,
      active_scenario: null,
      last_run_timestamp: new Date().toISOString(),
    } as T;
  }

  if (cleanEndpoint === '/simulation/reset') {
    clientState.alerts = clientState.alerts.filter((a) => !a.is_simulated);
    clientState.decisions = clientState.decisions.filter((d) => !d.simulated);
    clientState.events = clientState.events.filter((e) => !e.is_simulated);
    clientState.totalAlerts = clientState.alerts.length;
    clientState.totalEvents = clientState.events.length;
    clientState.activeBans = clientState.decisions.length;
    return {
      status: 'success',
      message: 'Purged simulated data.',
      deleted_events: 10,
      deleted_alerts: 2,
      deleted_decisions: 2,
    } as T;
  }

  return {} as T;
}

export const api = {
  // Health
  getHealth: () => fetchJson<HealthStatus>('/health'),

  // Dashboard
  getDashboardSummary: () => fetchJson<DashboardSummary>('/dashboard/summary'),

  // Alerts
  getAlerts: (params: { severity?: string; scenario?: string; ip?: string; status?: string; is_simulated?: boolean; page?: number; page_size?: number } = {}) => {
    const query = new URLSearchParams();
    if (params.severity) query.append('severity', params.severity);
    if (params.scenario) query.append('scenario', params.scenario);
    if (params.ip) query.append('ip', params.ip);
    if (params.status) query.append('status', params.status);
    if (params.is_simulated !== undefined) query.append('is_simulated', params.is_simulated.toString());
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
  getEvents: (params: { service?: string; is_suspicious?: boolean; is_simulated?: boolean; ip?: string; page?: number; page_size?: number } = {}) => {
    const query = new URLSearchParams();
    if (params.service) query.append('service', params.service);
    if (params.is_suspicious !== undefined) query.append('is_suspicious', params.is_suspicious.toString());
    if (params.is_simulated !== undefined) query.append('is_simulated', params.is_simulated.toString());
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

  // Simulation Endpoints
  getSimulationScenarios: () => fetchJson<SimulationScenario[]>('/simulation/scenarios'),
  launchSimulation: (data: { scenario: string; source_ip?: string; count?: number }) =>
    fetchJson<SimulationLaunchResult>('/simulation/launch', {
      method: 'POST',
      body: JSON.stringify(data),
    }),
  startSimulation: (data?: { interval_seconds?: number; include_attacks?: boolean }) =>
    fetchJson<SimulationStatus>('/simulation/start', {
      method: 'POST',
      body: JSON.stringify(data || { interval_seconds: 3.0, include_attacks: true }),
    }),
  stopSimulation: () =>
    fetchJson<SimulationStatus>('/simulation/stop', {
      method: 'POST',
    }),
  getSimulationStatus: () => fetchJson<SimulationStatus>('/simulation/status'),
  resetSimulation: () =>
    fetchJson<{ status: string; message: string; deleted_events: number; deleted_alerts: number; deleted_decisions: number }>(
      '/simulation/reset',
      {
        method: 'POST',
      }
    ),

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
