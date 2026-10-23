"""SQLAlchemy Database Models for Spork-IDS."""
import json
from datetime import datetime
from sqlalchemy import (
    Column,
    Integer,
    String,
    Text,
    DateTime,
    Boolean,
    ForeignKey,
    Index,
)
from sqlalchemy.orm import relationship
from app.db.session import Base


class EventModel(Base):
    """Normalized security log event."""

    __tablename__ = "events"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    source_ip = Column(String(64), index=True, nullable=False)
    service = Column(String(64), index=True, default="unknown")
    action = Column(String(64), index=True, default="log")
    raw_log = Column(Text, nullable=False)
    is_suspicious = Column(Boolean, default=False, index=True)
    meta_json = Column(Text, default="{}")
    enrichment_json = Column(Text, default="{}")

    @property
    def meta_data(self) -> dict:
        try:
            return json.loads(self.meta_json) if self.meta_json else {}
        except Exception:
            return {}

    @meta_data.setter
    def meta_data(self, val: dict):
        self.meta_json = json.dumps(val or {})

    @property
    def enrichment(self) -> dict:
        try:
            return json.loads(self.enrichment_json) if self.enrichment_json else {}
        except Exception:
            return {}

    @enrichment.setter
    def enrichment(self, val: dict):
        self.enrichment_json = json.dumps(val or {})


class AlertModel(Base):
    """Detection alert emitted on scenario bucket overflow."""

    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    uuid = Column(String(64), unique=True, index=True, nullable=False)
    scenario = Column(String(128), index=True, nullable=False)
    message = Column(String(256), nullable=False)
    severity = Column(String(32), default="medium", index=True)  # low, medium, high, critical
    source_ip = Column(String(64), index=True, nullable=False)
    source_scope = Column(String(32), default="Ip")
    events_count = Column(Integer, default=1)
    capacity = Column(Integer, default=0)
    leakspeed = Column(String(32), default="0s")
    start_at = Column(DateTime, default=datetime.utcnow)
    stop_at = Column(DateTime, default=datetime.utcnow)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    status = Column(String(32), default="active", index=True)  # active, resolved, dismissed
    meta_json = Column(Text, default="{}")

    decisions = relationship("DecisionModel", back_populates="alert", cascade="all, delete-orphan")

    @property
    def meta_data(self) -> dict:
        try:
            return json.loads(self.meta_json) if self.meta_json else {}
        except Exception:
            return {}

    @meta_data.setter
    def meta_data(self, val: dict):
        self.meta_json = json.dumps(val or {})


class DecisionModel(Base):
    """Active or historical remediation decision (ban, captcha, throttle)."""

    __tablename__ = "decisions"

    id = Column(Integer, primary_key=True, index=True)
    uuid = Column(String(64), unique=True, index=True, nullable=False)
    alert_id = Column(Integer, ForeignKey("alerts.id", ondelete="SET NULL"), nullable=True)
    origin = Column(String(64), default="spork-ids", index=True)  # spork-ids, crowdsec, manual
    type = Column(String(32), default="ban", index=True)  # ban, captcha, throttle
    scope = Column(String(32), default="Ip", index=True)
    value = Column(String(128), index=True, nullable=False)
    scenario = Column(String(128), index=True, nullable=False)
    duration = Column(String(32), default="4h")
    until = Column(DateTime, index=True, nullable=False)
    is_active = Column(Boolean, default=True, index=True)
    simulated = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)

    alert = relationship("AlertModel", back_populates="decisions")


class ScenarioStatModel(Base):
    """Live statistics for supported detection scenarios."""

    __tablename__ = "scenario_stats"

    id = Column(Integer, primary_key=True, index=True)
    scenario_name = Column(String(128), unique=True, index=True, nullable=False)
    description = Column(String(256), default="")
    scenario_type = Column(String(32), default="leaky")  # leaky, trigger, uniq
    capacity = Column(Integer, default=5)
    leakspeed = Column(String(32), default="10s")
    poured_events = Column(Integer, default=0)
    overflow_count = Column(Integer, default=0)
    last_overflow = Column(DateTime, nullable=True)


Index("idx_alert_created_status", AlertModel.created_at, AlertModel.status)
Index("idx_decision_value_active", DecisionModel.value, DecisionModel.is_active)
Index("idx_event_ip_time", EventModel.source_ip, EventModel.timestamp)
