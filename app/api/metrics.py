"""Application telemetry and operational metrics endpoints."""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.models.schemas import MetricsResponse
from app.services.metrics_service import metrics_service

router = APIRouter(prefix="/metrics", tags=["Metrics"])


@router.get("", response_model=MetricsResponse)
def get_metrics(db: Session = Depends(get_db)):
    """Returns granular operational metrics for events, alerts, decisions, and scenario buckets."""
    metrics = metrics_service.get_system_metrics(db)
    return MetricsResponse(**metrics)
