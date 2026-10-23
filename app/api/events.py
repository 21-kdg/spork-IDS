"""Security events ingestion and retrieval endpoints."""
from typing import Optional
from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.models.db_models import EventModel
from app.models.schemas import (
    EventCreate,
    EventResponse,
    EventListResponse,
    RawLogIngestRequest,
    RawLogIngestResponse,
)
from app.services.pipeline import pipeline
from app.core.security import verify_api_key

router = APIRouter(prefix="/events", tags=["Events"])


@router.get("", response_model=EventListResponse)
def list_events(
    db: Session = Depends(get_db),
    service: Optional[str] = Query(None, description="Filter by service name: ssh, nginx, syslog, windows, firewall"),
    is_suspicious: Optional[bool] = Query(None, description="Filter suspicious events only"),
    ip: Optional[str] = Query(None, description="Filter by source IP"),
    action: Optional[str] = Query(None, description="Filter by action name"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(25, ge=1, le=100, description="Items per page"),
):
    """Retrieves paginated normalized security events with filtering."""
    query = db.query(EventModel)

    if service:
        query = query.filter(EventModel.service == service.lower())
    if is_suspicious is not None:
        query = query.filter(EventModel.is_suspicious == is_suspicious)
    if ip:
        query = query.filter(EventModel.source_ip == ip.strip())
    if action:
        query = query.filter(EventModel.action == action.lower())

    total = query.count()
    items = (
        query.order_by(EventModel.timestamp.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )

    return EventListResponse(
        total=total,
        items=items,
        page=page,
        page_size=page_size,
    )


@router.post("", response_model=EventResponse, status_code=status.HTTP_201_CREATED)
def create_event(
    event_in: EventCreate,
    db: Session = Depends(get_db),
    _authorized: bool = Depends(verify_api_key),
):
    """Directly ingests a normalized security event into the detection engine."""
    result = pipeline.process_raw_line(
        db=db,
        raw_line=event_in.raw_log,
        service_hint=event_in.service,
    )
    event_record = db.query(EventModel).filter(EventModel.id == result["event_id"]).first()
    return event_record


@router.post("/raw", response_model=RawLogIngestResponse)
def ingest_raw_logs(
    req: RawLogIngestRequest,
    db: Session = Depends(get_db),
    _authorized: bool = Depends(verify_api_key),
):
    """
    Ingests and parses a batch of raw log lines.
    Executes parsing, normalization, GeoIP enrichment, and scenario detection.
    """
    res = pipeline.process_batch_raw(
        db=db, logs=req.logs, service_hint=req.service_hint
    )
    return RawLogIngestResponse(**res)
