"""Detection Scenario definitions and matching rules for Spork-IDS."""
from typing import Dict, Any, Callable, Optional


class ScenarioDefinition:
    def __init__(
        self,
        name: str,
        description: str,
        bucket_type: str,
        capacity: int,
        leakspeed_seconds: float,
        leakspeed_label: str,
        severity: str,
        remediation_type: str,
        remediation_duration: str,
        filter_fn: Callable[[Dict[str, Any]], bool],
        uniq_extractor: Optional[Callable[[Dict[str, Any]], Optional[str]]] = None,
    ):
        self.name = name
        self.description = description
        self.bucket_type = bucket_type  # leaky, trigger, uniq
        self.capacity = capacity
        self.leakspeed_seconds = leakspeed_seconds
        self.leakspeed_label = leakspeed_label
        self.severity = severity  # low, medium, high, critical
        self.remediation_type = remediation_type  # ban, captcha, throttle
        self.remediation_duration = remediation_duration  # 4h, 24h, etc.
        self.filter_fn = filter_fn
        self.uniq_extractor = uniq_extractor


# Filter predicates for scenarios

def _is_ssh_bf(event: Dict[str, Any]) -> bool:
    service = event.get("service", "").lower()
    action = event.get("action", "").lower()
    meta = event.get("meta_data", {})
    return (
        service == "ssh"
        and (action == "failed_login" or meta.get("log_type") in ["ssh_auth_failure", "ssh_invalid_user"])
    )


def _is_http_crawl(event: Dict[str, Any]) -> bool:
    service = event.get("service", "").lower()
    action = event.get("action", "").lower()
    meta = event.get("meta_data", {})
    return (
        service in ["nginx", "http", "apache"]
        and (action == "404_not_found" or meta.get("http_status") in [404, 403])
    )


def _is_sqli(event: Dict[str, Any]) -> bool:
    action = event.get("action", "").lower()
    meta = event.get("meta_data", {})
    return action == "sqli_attempt" or meta.get("is_sqli") is True


def _is_traversal(event: Dict[str, Any]) -> bool:
    action = event.get("action", "").lower()
    meta = event.get("meta_data", {})
    return action == "traversal_attempt" or meta.get("is_traversal") is True


def _is_port_scan(event: Dict[str, Any]) -> bool:
    service = event.get("service", "").lower()
    action = event.get("action", "").lower()
    meta = event.get("meta_data", {})
    return (service == "firewall" or action == "port_probe") and "dest_port" in meta


def _extract_port(event: Dict[str, Any]) -> Optional[str]:
    meta = event.get("meta_data", {})
    port = meta.get("dest_port")
    return str(port) if port is not None else None


def _is_credential_stuffing(event: Dict[str, Any]) -> bool:
    action = event.get("action", "").lower()
    meta = event.get("meta_data", {})
    user = meta.get("user")
    return action in ["failed_login", "failed_auth"] and bool(user)


def _extract_user(event: Dict[str, Any]) -> Optional[str]:
    meta = event.get("meta_data", {})
    return meta.get("user")


BUILTIN_SCENARIOS = {
    "spork/ssh-bf": ScenarioDefinition(
        name="spork/ssh-bf",
        description="SSH authentication brute-force attempt from single IP address",
        bucket_type="leaky",
        capacity=5,
        leakspeed_seconds=20.0,
        leakspeed_label="20s",
        severity="high",
        remediation_type="ban",
        remediation_duration="4h",
        filter_fn=_is_ssh_bf,
    ),
    "spork/http-crawl-bf": ScenarioDefinition(
        name="spork/http-crawl-bf",
        description="Aggressive web route 404/403 enumeration and crawl probing",
        bucket_type="leaky",
        capacity=8,
        leakspeed_seconds=15.0,
        leakspeed_label="15s",
        severity="medium",
        remediation_type="ban",
        remediation_duration="2h",
        filter_fn=_is_http_crawl,
    ),
    "spork/http-sqli": ScenarioDefinition(
        name="spork/http-sqli",
        description="SQL injection exploit payload targeting web applications",
        bucket_type="trigger",
        capacity=0,
        leakspeed_seconds=0.0,
        leakspeed_label="0s",
        severity="critical",
        remediation_type="ban",
        remediation_duration="24h",
        filter_fn=_is_sqli,
    ),
    "spork/http-path-traversal": ScenarioDefinition(
        name="spork/http-path-traversal",
        description="Directory and path traversal payload targeting web server paths",
        bucket_type="trigger",
        capacity=0,
        leakspeed_seconds=0.0,
        leakspeed_label="0s",
        severity="critical",
        remediation_type="ban",
        remediation_duration="24h",
        filter_fn=_is_traversal,
    ),
    "spork/port-scan": ScenarioDefinition(
        name="spork/port-scan",
        description="Horizontal or vertical TCP/UDP port reconnaissance scan",
        bucket_type="uniq",
        capacity=5,
        leakspeed_seconds=45.0,
        leakspeed_label="45s",
        severity="medium",
        remediation_type="ban",
        remediation_duration="6h",
        filter_fn=_is_port_scan,
        uniq_extractor=_extract_port,
    ),
    "spork/auth-credential-stuffing": ScenarioDefinition(
        name="spork/auth-credential-stuffing",
        description="Multi-account credential stuffing attack using distinct user targets",
        bucket_type="uniq",
        capacity=4,
        leakspeed_seconds=60.0,
        leakspeed_label="60s",
        severity="high",
        remediation_type="ban",
        remediation_duration="12h",
        filter_fn=_is_credential_stuffing,
        uniq_extractor=_extract_user,
    ),
}
