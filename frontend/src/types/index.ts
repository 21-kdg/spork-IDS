export interface HealthStatus {
  status: string;
  version: string;
  engine: string;
  uptime_seconds: number;
  crowdsec_integration: string;
  active_decisions: number;
  total_alerts: number;
  events_processed: number;
}

export interface Decision {
  id: number;
  uuid: string;
  origin: string;
  type: string;
  scope: string;
  value: string;
  scenario: string;
  duration: string;
  until: string;
  is_active: boolean;
  simulated: boolean;
  created_at: string;
  alert_id?: number | null;
}

export interface Alert {
  id: number;
  uuid: string;
  scenario: string;
  message: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  source_ip: string;
  source_scope: string;
  events_count: number;
  capacity: number;
  leakspeed: string;
  start_at: string;
  stop_at: string;
  created_at: string;
  status: string;
  is_simulated?: boolean;
  meta_data: {
    contributing_events?: Array<{
      source_ip?: string;
      service?: string;
      action?: string;
      raw_log?: string;
      timestamp_epoch?: number;
      meta_data?: Record<string, any>;
    }>;
    enrichment?: {
      country?: string;
      country_code?: string;
      asn?: string;
      ip_type?: string;
    };
  };
  decisions: Decision[];
}

export interface SecurityEvent {
  id: number;
  timestamp: string;
  source_ip: string;
  service: string;
  action: string;
  raw_log: string;
  is_suspicious: boolean;
  is_simulated?: boolean;
  meta_data: Record<string, any>;
  enrichment: {
    country?: string;
    country_code?: string;
    asn?: string;
    ip_type?: string;
  };
}

export interface ScenarioInfo {
  name: string;
  description: string;
  type: 'leaky' | 'trigger' | 'uniq';
  capacity: number;
  leakspeed: string;
  filter_hint: string;
  poured_events: number;
  overflow_count: number;
  active_buckets: number;
}

export interface DashboardSummary {
  engine_status: string;
  uptime_seconds: number;
  total_events: number;
  events_last_24h: number;
  total_alerts: number;
  active_decisions: number;
  scenarios_active: number;
  top_attacking_ips: Array<{ ip: string; event_count: number }>;
  recent_alerts: Alert[];
  top_scenarios: Array<{ scenario: string; alert_count: number }>;
  events_by_service: Record<string, number>;
  hourly_trend: Array<{ hour: string; events: number; alerts: number }>;
  crowdsec_status: {
    enabled: boolean;
    configured_url: string;
    connected: boolean;
    last_error?: string | null;
    mode: string;
    description: string;
  };
}

export interface SystemMetrics {
  uptime_seconds: number;
  events_ingested: number;
  events_suspicious: number;
  alerts_triggered: number;
  decisions_active: number;
  decisions_expired: number;
  live_buckets_count: number;
  scenarios: ScenarioInfo[];
}

export interface SystemSettings {
  server_host: string;
  server_port: number;
  environment: string;
  database_url_safe: string;
  api_key_enabled: boolean;
  crowdsec_enabled: boolean;
  crowdsec_lapi_url: string;
  crowdsec_connected: boolean;
}

export interface SimulationScenario {
  id: string;
  name: string;
  description: string;
  category: string;
  default_ip: string;
  sample_payload: string;
  bucket_type: string;
  burst_count: number;
}

export interface SimulationLaunchResult {
  status: string;
  scenario: string;
  attacker_ip: string;
  events_generated: number;
  overflow_triggered: boolean;
  logs_generated: string[];
  alerts_created: Array<{
    id: number;
    uuid: string;
    scenario: string;
    severity: string;
    source_ip: string;
    message: string;
  }>;
  decisions_created: Array<{
    id: number;
    type: string;
    value: string;
    duration: string;
    scenario: string;
  }>;
  message: string;
}

export interface SimulationStatus {
  is_running: boolean;
  interval_seconds: number;
  total_simulated_events: number;
  total_simulated_alerts: number;
  active_scenario?: string | null;
  last_run_timestamp?: string | null;
}

