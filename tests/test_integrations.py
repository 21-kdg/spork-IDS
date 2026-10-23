"""Tests for external CrowdSec integration and fallback."""
import asyncio
from unittest.mock import patch, AsyncMock
import httpx
from app.integrations.crowdsec_client import CrowdSecClient


def test_crowdsec_offline_fallback():
    """Verify CrowdSec client returns clean, structured failure when daemon is offline."""
    client = CrowdSecClient()

    async def _run():
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.side_effect = httpx.ConnectError("Connection refused")
            res = await client.test_connection(lapi_url="http://127.0.0.1:8080")
            assert res["success"] is False
            assert "refused" in res["message"].lower()

    asyncio.run(_run())


def test_crowdsec_online_success():
    """Verify CrowdSec client handles 200 OK heartbeat."""
    client = CrowdSecClient()
    mock_resp = httpx.Response(200, headers={"Server": "CrowdSec LAPI v1.6.0"})

    async def _run():
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_resp
            res = await client.test_connection(lapi_url="http://127.0.0.1:8080")
            assert res["success"] is True
            assert res["latency_ms"] is not None

    asyncio.run(_run())


def test_crowdsec_status_standalone():
    """Verify status reports standalone mode when disconnected."""
    client = CrowdSecClient()
    client.last_check_status = False
    status = client.get_status()
    assert status["mode"] == "standalone"
    assert status["connected"] is False
