"""Alert query, retrieval, and management endpoints."""
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.models.db_models import AlertModel
from app.models.schemas import AlertResponse, AlertListResponse, AlertResolveRequest
from app.core.security import verify_api_key

router = APIRouter(prefix="/alerts", tags=["Alerts"])


@router.get("", response_model=AlertListResponse)
def list_alerts(
    db: Session = Depends(get_db),
    severity: Optional[str] = Query(None, description="Filter by severity: low, medium, high, critical"),
    scenario: Optional[str] = Query(None, description="Filter by scenario name"),
    ip: Optional[str] = Query(None, description="Filter by attacker IP"),
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by status: active, resolved, dismissed"),
    is_simulated: Optional[bool] = Query(None, description="Filter simulated alerts"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(25, ge=1, le=100, description="Items per page"),
):
    """Retrieves paginated detection alerts with flexible filtering."""
    query = db.query(AlertModel)

    if severity:
        query = query.filter(AlertModel.severity == severity.lower())
    if scenario:
        query = query.filter(AlertModel.scenario.ilike(f"%{scenario}%"))
    if ip:
        query = query.filter(AlertModel.source_ip == ip.strip())
    if status_filter:
        query = query.filter(AlertModel.status == status_filter.lower())
    if is_simulated is not None:
        query = query.filter(AlertModel.is_simulated == is_simulated)

    total = query.count()
    items = (
        query.order_by(AlertModel.created_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )

    return AlertListResponse(
        total=total,
        items=items,
        page=page,
        page_size=page_size,
    )


@router.get("/{alert_id}", response_model=AlertResponse)
def get_alert_detail(alert_id: int, db: Session = Depends(get_db)):
    """Retrieves a single alert record by database ID, including decisions and contributing events."""
    alert = db.query(AlertModel).filter(AlertModel.id == alert_id).first()
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert with ID {alert_id} not found",
        )
    return alert


@router.patch("/{alert_id}/status", response_model=AlertResponse)
def update_alert_status(
    alert_id: int,
    req: AlertResolveRequest,
    db: Session = Depends(get_db),
    _authorized: bool = Depends(verify_api_key),
):
    """Updates an alert status (e.g. resolve or dismiss)."""
    alert = db.query(AlertModel).filter(AlertModel.id == alert_id).first()
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert with ID {alert_id} not found",
        )
    alert.status = req.status.lower()
    db.commit()
    db.refresh(alert)
    return alert


@router.delete("/{alert_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_alert(
    alert_id: int,
    db: Session = Depends(get_db),
    _authorized: bool = Depends(verify_api_key),
):
    """Deletes an alert record."""
    alert = db.query(AlertModel).filter(AlertModel.id == alert_id).first()
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert with ID {alert_id} not found",
        )
    db.delete(alert)
    db.commit()
    return None
