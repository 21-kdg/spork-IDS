"""Metrics and telemetry calculation service for Spork-IDS."""
import time
from datetime import datetime, timedelta
from typing import Dict, Any, List
from sqlalchemy import func
from sqlalchemy.orm import Session
from app.models.db_models import EventModel, AlertModel, DecisionModel
from app.detection.engine import engine as detection_engine

APP_START_TIME = time.time()


class MetricsService:
    """Computes real-time system metrics and aggregated dashboard statistics."""

    @staticmethod
    def get_uptime_seconds() -> float:
        return time.time() - APP_START_TIME

    @staticmethod
    def get_dashboard_summary(db: Session, crowdsec_status: Dict[str, Any]) -> Dict[str, Any]:
        """Calculates real dashboard aggregates from SQLite database."""
        now = datetime.utcnow()
        day_ago = now - timedelta(hours=24)

        # 1. Total & 24h Events
        total_events = db.query(func.count(EventModel.id)).scalar() or 0
        events_24h = (
            db.query(func.count(EventModel.id))
            .filter(EventModel.timestamp >= day_ago)
            .scalar()
            or 0
        )

        # 2. Total Alerts
        total_alerts = db.query(func.count(AlertModel.id)).scalar() or 0

        # 3. Active Decisions
        active_decisions = (
            db.query(func.count(DecisionModel.id))
            .filter(
                DecisionModel.is_active == True,  # noqa: E712
                DecisionModel.until > now,
            )
            .scalar()
            or 0
        )

        # 4. Top Attacking IPs
        top_ips_query = (
            db.query(EventModel.source_ip, func.count(EventModel.id).label("count"))
            .filter(EventModel.is_suspicious == True)  # noqa: E712
            .group_by(EventModel.source_ip)
            .order_by(func.count(EventModel.id).desc())
            .limit(5)
            .all()
        )
        top_attacking_ips = [
            {"ip": row[0], "event_count": row[1]} for row in top_ips_query
        ]

        # 5. Recent Alerts
        recent_alerts_orm = (
            db.query(AlertModel)
            .order_by(AlertModel.created_at.desc())
            .limit(6)
            .all()
        )
        # Convert to serializable dicts
        recent_alerts = []
        for a in recent_alerts_orm:
            recent_alerts.append({
                "id": a.id,
                "uuid": a.uuid,
                "scenario": a.scenario,
                "message": a.message,
                "severity": a.severity,
                "source_ip": a.source_ip,
                "source_scope": a.source_scope,
                "events_count": a.events_count,
                "capacity": a.capacity,
                "leakspeed": a.leakspeed,
                "start_at": a.start_at.isoformat() if a.start_at else "",
                "stop_at": a.stop_at.isoformat() if a.stop_at else "",
                "created_at": a.created_at.isoformat() if a.created_at else "",
                "status": a.status,
                "is_simulated": bool(a.is_simulated),
                "meta_data": a.meta_data,
                "decisions": [
                    {
                        "id": d.id,
                        "uuid": d.uuid,
                        "origin": d.origin,
                        "type": d.type,
                        "scope": d.scope,
                        "value": d.value,
                        "scenario": d.scenario,
                        "duration": d.duration,
                        "until": d.until.isoformat() if d.until else "",
                        "is_active": d.is_active,
                        "simulated": d.simulated,
                        "created_at": d.created_at.isoformat() if d.created_at else "",
                    }
                    for d in a.decisions
                ],
            })

        # 6. Events by Service
        services_query = (
            db.query(EventModel.service, func.count(EventModel.id))
            .group_by(EventModel.service)
            .all()
        )
        events_by_service = {row[0]: row[1] for row in services_query}

        # 7. Top Scenarios
        scenario_query = (
            db.query(AlertModel.scenario, func.count(AlertModel.id).label("count"))
            .group_by(AlertModel.scenario)
            .order_by(func.count(AlertModel.id).desc())
            .limit(5)
            .all()
        )
        top_scenarios = [
            {"scenario": row[0], "alert_count": row[1]} for row in scenario_query
        ]

        # 8. Hourly Trend for the past 12 hours
        hourly_trend = []
        for i in range(11, -1, -1):
            h_start = now - timedelta(hours=i + 1)
            h_end = now - timedelta(hours=i)
            count = (
                db.query(func.count(EventModel.id))
                .filter(EventModel.timestamp >= h_start, EventModel.timestamp < h_end)
                .scalar()
                or 0
            )
            alerts_in_hour = (
                db.query(func.count(AlertModel.id))
                .filter(AlertModel.created_at >= h_start, AlertModel.created_at < h_end)
                .scalar()
                or 0
            )
            hourly_trend.append({
                "hour": h_start.strftime("%H:00"),
                "events": count,
                "alerts": alerts_in_hour,
            })

        return {
            "engine_status": "operational",
            "uptime_seconds": round(MetricsService.get_uptime_seconds(), 1),
            "total_events": total_events,
            "events_last_24h": events_24h,
            "total_alerts": total_alerts,
            "active_decisions": active_decisions,
            "scenarios_active": len(detection_engine.scenarios),
            "top_attacking_ips": top_attacking_ips,
            "recent_alerts": recent_alerts,
            "top_scenarios": top_scenarios,
            "events_by_service": events_by_service,
            "hourly_trend": hourly_trend,
            "crowdsec_status": crowdsec_status,
        }

    @staticmethod
    def get_system_metrics(db: Session) -> Dict[str, Any]:
        """Exposes detailed operational metrics."""
        now = datetime.utcnow()
        events_total = db.query(func.count(EventModel.id)).scalar() or 0
        events_suspicious = (
            db.query(func.count(EventModel.id))
            .filter(EventModel.is_suspicious == True)  # noqa: E712
            .scalar()
            or 0
        )
        alerts_total = db.query(func.count(AlertModel.id)).scalar() or 0
        decisions_active = (
            db.query(func.count(DecisionModel.id))
            .filter(
                DecisionModel.is_active == True,  # noqa: E712
                DecisionModel.until > now,
            )
            .scalar()
            or 0
        )
        decisions_expired = (
            db.query(func.count(DecisionModel.id))
            .filter(
                (DecisionModel.is_active == False) | (DecisionModel.until <= now)  # noqa: E712
            )
            .scalar()
            or 0
        )

        engine_stats = detection_engine.get_stats()

        return {
            "uptime_seconds": round(MetricsService.get_uptime_seconds(), 1),
            "events_ingested": events_total,
            "events_suspicious": events_suspicious,
            "alerts_triggered": alerts_total,
            "decisions_active": decisions_active,
            "decisions_expired": decisions_expired,
            "live_buckets_count": engine_stats["total_active_buckets"],
            "scenarios": engine_stats["scenarios"],
        }


metrics_service = MetricsService()
