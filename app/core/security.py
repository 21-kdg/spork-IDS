"""Security and authentication utilities for Spork-IDS."""
import secrets
from typing import Optional
from fastapi import Header, HTTPException, status
from app.core.config import settings


def verify_api_key(x_api_key: Optional[str] = Header(None, alias="X-Api-Key")) -> bool:
    """
    Validates the X-Api-Key header against configured SPORK_API_KEY.
    If SPORK_API_KEY is not set or empty, API access is permitted (local development mode).
    If SPORK_API_KEY is configured, requests must supply a matching key.
    """
    if not settings.SPORK_API_KEY:
        # Local development / open mode
        return True

    if not x_api_key or not secrets.compare_digest(x_api_key, settings.SPORK_API_KEY):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key in X-Api-Key header",
            headers={"WWW-Authenticate": "ApiKey"},
        )
    return True
