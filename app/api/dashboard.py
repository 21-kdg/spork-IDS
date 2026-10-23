"""Dashboard summary endpoints."""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.models.schemas import DashboardSummaryResponse
from app.services.metrics_service import metrics_service
from app.integrations.crowdsec_client import crowdsec_client

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


@router.get("/summary", response_model=DashboardSummaryResponse)
def get_dashboard_summary(db: Session = Depends(get_db)):
    """Returns aggregated real-time statistics and summary feeds for the UI overview."""
    crowdsec_info = crowdsec_client.get_status()
    summary = metrics_service.get_dashboard_summary(db, crowdsec_status=crowdsec_info)
    return summary
