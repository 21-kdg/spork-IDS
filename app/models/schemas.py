"""Pydantic schemas for Spork-IDS request and response validation."""
from datetime import datetime
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field, ConfigDict


# ---------------------------------------------------------------------------
# Health & Status Schemas
# ---------------------------------------------------------------------------

class HealthResponse(BaseModel):
    status: str = "ok"
    version: str = "1.0.0"
    engine: str = "spork-ids-python"
    uptime_seconds: float
    crowdsec_integration: str = "standalone"
    active_decisions: int = 0
    total_alerts: int = 0
    events_processed: int = 0


# ---------------------------------------------------------------------------
# Event Schemas
# ---------------------------------------------------------------------------

class EventCreate(BaseModel):
    source_ip: str = Field(..., description="IPv4 or IPv6 address")
    service: str = Field("unknown", description="Log service type: ssh, nginx, syslog, windows, etc.")
    action: str = Field("log", description="Action name, e.g. failed_login, 404_not_found, sqli_attempt")
    raw_log: str = Field(..., description="Raw log line text")
    timestamp: Optional[datetime] = None
    meta_data: Optional[Dict[str, Any]] = None


class EventResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    timestamp: datetime
    source_ip: str
    service: str
    action: str
    raw_log: str
    is_suspicious: bool
    meta_data: Dict[str, Any] = {}
    enrichment: Dict[str, Any] = {}


class EventListResponse(BaseModel):
    total: int
    items: List[EventResponse]
    page: int
    page_size: int


class RawLogIngestRequest(BaseModel):
    logs: List[str] = Field(..., description="List of raw log strings to parse and process")
    service_hint: Optional[str] = Field(None, description="Optional parser hint: ssh, nginx, syslog, windows")


class RawLogIngestResponse(BaseModel):
    processed_count: int
    alerts_triggered: int
    decisions_created: int
    details: List[Dict[str, Any]] = []


# ---------------------------------------------------------------------------
# Decision Schemas
# ---------------------------------------------------------------------------

class DecisionCreate(BaseModel):
    value: str = Field(..., description="IP, IP range, or username")
    scope: str = Field("Ip", description="Scope: Ip, Range, User")
    type: str = Field("ban", description="Remediation type: ban, captcha, throttle")
    duration: str = Field("4h", description="Duration string: e.g. 1h, 4h, 24h, 7d")
    scenario: str = Field("manual/admin-ban", description="Scenario or reason")
    simulated: bool = False


class DecisionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    uuid: str
    origin: str
    type: str
    scope: str
    value: str
    scenario: str
    duration: str
    until: datetime
    is_active: bool
    simulated: bool
    created_at: datetime
    alert_id: Optional[int] = None


class DecisionListResponse(BaseModel):
    total: int
    items: List[DecisionResponse]


# ---------------------------------------------------------------------------
# Alert Schemas
# ---------------------------------------------------------------------------

class AlertResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    uuid: str
    scenario: str
    message: str
    severity: str
    source_ip: str
    source_scope: str
    events_count: int
    capacity: int
    leakspeed: str
    start_at: datetime
    stop_at: datetime
    created_at: datetime
    status: str
    meta_data: Dict[str, Any] = {}
    decisions: List[DecisionResponse] = []


class AlertListResponse(BaseModel):
    total: int
    items: List[AlertResponse]
    page: int
    page_size: int


class AlertResolveRequest(BaseModel):
    status: str = Field("resolved", description="Status: resolved, dismissed, active")


# ---------------------------------------------------------------------------
# Scenario & Detection Schemas
# ---------------------------------------------------------------------------

class ScenarioInfo(BaseModel):
    name: str
    description: str
    type: str  # leaky, trigger, uniq
    capacity: int
    leakspeed: str
    filter_hint: str
    poured_events: int = 0
    overflow_count: int = 0
    active_buckets: int = 0


class ScenarioListResponse(BaseModel):
    total: int
    items: List[ScenarioInfo]


class ScenarioEvaluateRequest(BaseModel):
    scenario_name: str
    source_ip: str
    raw_log: str
    service: Optional[str] = None
    meta_data: Optional[Dict[str, Any]] = None


class ScenarioEvaluateResponse(BaseModel):
    matched_filter: bool
    scenario_name: str
    bucket_type: str
    current_count: int
    capacity: int
    overflow: bool
    alert_generated: Optional[Dict[str, Any]] = None
    decision: Optional[Dict[str, Any]] = None
    reason: str


# ---------------------------------------------------------------------------
# Dashboard & Metrics Schemas
# ---------------------------------------------------------------------------

class DashboardSummaryResponse(BaseModel):
    engine_status: str
    uptime_seconds: float
    total_events: int
    events_last_24h: int
    total_alerts: int
    active_decisions: int
    scenarios_active: int
    top_attacking_ips: List[Dict[str, Any]]
    recent_alerts: List[AlertResponse]
    top_scenarios: List[Dict[str, Any]]
    events_by_service: Dict[str, int]
    hourly_trend: List[Dict[str, Any]]
    crowdsec_status: Dict[str, Any]


class MetricsResponse(BaseModel):
    uptime_seconds: float
    events_ingested: int
    events_suspicious: int
    alerts_triggered: int
    decisions_active: int
    decisions_expired: int
    live_buckets_count: int
    scenarios: List[Dict[str, Any]]


# ---------------------------------------------------------------------------
# Settings Schemas
# ---------------------------------------------------------------------------

class SettingsResponse(BaseModel):
    server_host: str
    server_port: int
    environment: str
    database_url_safe: str
    api_key_enabled: bool
    crowdsec_enabled: bool
    crowdsec_lapi_url: str
    crowdsec_connected: bool


class SettingsUpdateRequest(BaseModel):
    crowdsec_enabled: Optional[bool] = None
    crowdsec_lapi_url: Optional[str] = None
    crowdsec_api_key: Optional[str] = None


class CrowdSecTestRequest(BaseModel):
    lapi_url: str
    api_key: Optional[str] = None


class CrowdSecTestResponse(BaseModel):
    success: bool
    message: str
    version: Optional[str] = None
    latency_ms: Optional[float] = None
