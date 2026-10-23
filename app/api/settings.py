"""Configuration and integration settings endpoints."""
from fastapi import APIRouter, Depends
from app.core.config import settings
from app.models.schemas import (
    SettingsResponse,
    SettingsUpdateRequest,
    CrowdSecTestRequest,
    CrowdSecTestResponse,
)
from app.integrations.crowdsec_client import crowdsec_client
from app.core.security import verify_api_key

router = APIRouter(prefix="/settings", tags=["Settings"])


@router.get("", response_model=SettingsResponse)
def get_settings():
    """Returns application configuration and integration state (with credentials masked)."""
    crowdsec_status = crowdsec_client.get_status()
    safe_db = "sqlite:///./data/spork.db" if "sqlite" in settings.SPORK_DATABASE_URL else "Database Connected"

    return SettingsResponse(
        server_host=settings.SPORK_HOST,
        server_port=settings.SPORK_PORT,
        environment=settings.SPORK_ENV,
        database_url_safe=safe_db,
        api_key_enabled=bool(settings.SPORK_API_KEY),
        crowdsec_enabled=crowdsec_status["enabled"],
        crowdsec_lapi_url=crowdsec_status["configured_url"],
        crowdsec_connected=crowdsec_status["connected"],
    )


@router.post("", response_model=SettingsResponse)
def update_settings(
    req: SettingsUpdateRequest,
    _authorized: bool = Depends(verify_api_key),
):
    """Updates integration settings in runtime."""
    if req.crowdsec_enabled is not None:
        crowdsec_client.enabled = req.crowdsec_enabled
    if req.crowdsec_lapi_url:
        crowdsec_client.lapi_url = req.crowdsec_lapi_url.rstrip("/")
    if req.crowdsec_api_key:
        crowdsec_client.api_key = req.crowdsec_api_key

    return get_settings()


@router.post("/test-crowdsec", response_model=CrowdSecTestResponse)
async def test_crowdsec_connection(req: CrowdSecTestRequest):
    """
    Actively tests an HTTP connection to a CrowdSec Local API (LAPI) instance.
    Reports connectivity, HTTP response, or detailed network error.
    """
    res = await crowdsec_client.test_connection(lapi_url=req.lapi_url, api_key=req.api_key)
    return CrowdSecTestResponse(**res)
