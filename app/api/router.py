"""Central API router mounting all endpoint modules."""
from fastapi import APIRouter
from app.api import health, dashboard, alerts, events, decisions, scenarios, metrics, settings

api_router = APIRouter(prefix="/api")

api_router.include_router(health.router)
api_router.include_router(dashboard.router)
api_router.include_router(alerts.router)
api_router.include_router(events.router)
api_router.include_router(decisions.router)
api_router.include_router(scenarios.router)
api_router.include_router(metrics.router)
api_router.include_router(settings.router)
