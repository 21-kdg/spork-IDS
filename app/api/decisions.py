"""Decision management endpoints (bans, throttles, unbans)."""
from datetime import datetime
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.models.db_models import DecisionModel
from app.models.schemas import (
    DecisionCreate,
    DecisionResponse,
    DecisionListResponse,
)
from app.services.decision_manager import decision_manager
from app.core.security import verify_api_key

router = APIRouter(prefix="/decisions", tags=["Decisions"])


@router.get("", response_model=DecisionListResponse)
def list_decisions(
    db: Session = Depends(get_db),
    active_only: bool = Query(True, description="Return active unexpired decisions only"),
    scope: Optional[str] = Query(None, description="Scope filter: Ip, Range, User"),
    decision_type: Optional[str] = Query(None, alias="type", description="Type filter: ban, captcha, throttle"),
    ip: Optional[str] = Query(None, alias="value", description="Filter by IP / target value"),
):
    """Retrieves active remediation decisions."""
    now = datetime.utcnow()
    query = db.query(DecisionModel)

    if active_only:
        query = query.filter(
            DecisionModel.is_active == True,  # noqa: E712
            DecisionModel.until > now,
        )
    if scope:
        query = query.filter(DecisionModel.scope == scope)
    if decision_type:
        query = query.filter(DecisionModel.type == decision_type)
    if ip:
        query = query.filter(DecisionModel.value == ip.strip())

    items = query.order_by(DecisionModel.created_at.desc()).all()
    return DecisionListResponse(total=len(items), items=items)


@router.post("", response_model=DecisionResponse, status_code=status.HTTP_201_CREATED)
def create_manual_decision(
    req: DecisionCreate,
    db: Session = Depends(get_db),
    _authorized: bool = Depends(verify_api_key),
):
    """Creates a manual remediation decision (e.g. administrator IP ban)."""
    decision = decision_manager.create_decision(
        db=db,
        value=req.value.strip(),
        scope=req.scope,
        decision_type=req.type,
        duration=req.duration,
        scenario=req.scenario,
        origin="manual",
        simulated=req.simulated,
    )
    return decision


@router.delete("/{decision_id}", status_code=status.HTTP_200_OK)
def revoke_decision(
    decision_id: int,
    db: Session = Depends(get_db),
    _authorized: bool = Depends(verify_api_key),
):
    """Revokes / unbans an active decision."""
    success = decision_manager.revoke_decision(db, decision_id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Decision with ID {decision_id} not found",
        )
    return {"status": "revoked", "id": decision_id}
