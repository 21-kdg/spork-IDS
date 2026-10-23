"""External CrowdSec Local API (LAPI) Integration Adapter."""
import time
from typing import Dict, Any, Optional
import httpx
from app.core.config import settings


class CrowdSecClient:
    """
    Adapter for communicating with an external CrowdSec Local API (LAPI) instance.
    Enables Spork-IDS to run in hybrid mode with CrowdSec when installed,
    or operate independently in standalone Python mode when CrowdSec is not running.
    """

    def __init__(self):
        self.enabled = settings.CROWDSEC_ENABLED
        self.lapi_url = settings.CROWDSEC_LAPI_URL.rstrip("/")
        self.api_key = settings.CROWDSEC_API_KEY
        self.last_check_status: bool = False
        self.last_check_time: float = 0.0
        self.last_error: Optional[str] = None

    async def test_connection(
        self, lapi_url: Optional[str] = None, api_key: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Tests connectivity to an external CrowdSec LAPI daemon.
        Safely probes endpoint and returns latency and status.
        """
        url = (lapi_url or self.lapi_url).rstrip("/")
        key = api_key or self.api_key
        headers = {"X-Api-Key": key} if key else {}

        start = time.time()
        try:
            async with httpx.AsyncClient(timeout=3.0) as client:
                # Attempt to query LAPI heartbeat or watch status
                response = await client.get(f"{url}/v1/heartbeat", headers=headers)
                latency = round((time.time() - start) * 1000, 2)

                if response.status_code in [200, 204]:
                    self.last_check_status = True
                    self.last_check_time = time.time()
                    self.last_error = None
                    return {
                        "success": True,
                        "message": f"Successfully connected to CrowdSec LAPI at {url} (HTTP {response.status_code})",
                        "version": response.headers.get("Server", "CrowdSec LAPI"),
                        "latency_ms": latency,
                    }
                elif response.status_code == 401 or response.status_code == 403:
                    return {
                        "success": False,
                        "message": f"CrowdSec LAPI reachable at {url}, but authentication failed (HTTP {response.status_code}). Check API key / bouncer token.",
                        "latency_ms": latency,
                    }
                else:
                    return {
                        "success": False,
                        "message": f"CrowdSec LAPI returned unexpected status HTTP {response.status_code}",
                        "latency_ms": latency,
                    }
        except httpx.ConnectError:
            self.last_check_status = False
            self.last_error = f"Connection refused at {url}. CrowdSec engine daemon is not running."
            return {
                "success": False,
                "message": f"Connection refused at {url}. No CrowdSec daemon is running on this port.",
            }
        except httpx.TimeoutException:
            self.last_check_status = False
            self.last_error = f"Connection timed out at {url}"
            return {
                "success": False,
                "message": f"Connection timed out contacting CrowdSec LAPI at {url}.",
            }
        except Exception as e:
            self.last_check_status = False
            self.last_error = str(e)
            return {
                "success": False,
                "message": f"Error contacting CrowdSec LAPI: {str(e)}",
            }

    def get_status(self) -> Dict[str, Any]:
        """Returns the current connection and operational status of the CrowdSec adapter."""
        return {
            "enabled": self.enabled,
            "configured_url": self.lapi_url,
            "connected": self.last_check_status,
            "last_error": self.last_error,
            "mode": "hybrid" if (self.enabled and self.last_check_status) else "standalone",
            "description": (
                "Operating in Standalone Python Engine mode. Upstream CrowdSec daemon is not connected."
                if not self.last_check_status
                else "Operating in Hybrid Mode. Connected to upstream CrowdSec Local API."
            ),
        }


crowdsec_client = CrowdSecClient()
