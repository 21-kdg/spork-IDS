"""Health check and service status endpoints."""
from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session
from datetime import datetime
from app.db.session import get_db
from app.models.db_models import AlertModel, DecisionModel, EventModel
from app.models.schemas import HealthResponse
from app.services.metrics_service import metrics_service
from app.integrations.crowdsec_client import crowdsec_client

router = APIRouter(prefix="/health", tags=["Health"])


@router.get("", response_model=HealthResponse)
def get_service_health(db: Session = Depends(get_db)):
    """Returns application health, engine status, and runtime indicators."""
    now = datetime.utcnow()
    active_decisions = (
        db.query(func.count(DecisionModel.id))
        .filter(DecisionModel.is_active == True, DecisionModel.until > now)  # noqa: E712
        .scalar()
        or 0
    )
    total_alerts = db.query(func.count(AlertModel.id)).scalar() or 0
    total_events = db.query(func.count(EventModel.id)).scalar() or 0
    crowdsec_info = crowdsec_client.get_status()

    return HealthResponse(
        status="ok",
        version="1.0.0",
        engine="spork-ids-python",
        uptime_seconds=round(metrics_service.get_uptime_seconds(), 1),
        crowdsec_integration=crowdsec_info["mode"],
        active_decisions=active_decisions,
        total_alerts=total_alerts,
        events_processed=total_events,
    )
