"""Security log parser and normalizer for Spork-IDS."""
import re
import urllib.parse
from datetime import datetime
from typing import Dict, Any, Optional

# Pre-compiled Regex Patterns

SSH_FAILED_PWD_RE = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>(?:[0-9]{1,3}\.){3}[0-9]{1,3}|[a-fA-F0-9:]+) port (?P<port>\d+)",
    re.IGNORECASE,
)
SSH_INVALID_USER_RE = re.compile(
    r"Invalid user (?P<user>\S+) from (?P<ip>(?:[0-9]{1,3}\.){3}[0-9]{1,3}|[a-fA-F0-9:]+)(?: port (?P<port>\d+))?",
    re.IGNORECASE,
)
SSH_ACCEPTED_RE = re.compile(
    r"Accepted password for (?P<user>\S+) from (?P<ip>(?:[0-9]{1,3}\.){3}[0-9]{1,3}|[a-fA-F0-9:]+) port (?P<port>\d+)",
    re.IGNORECASE,
)

HTTP_ACCESS_RE = re.compile(
    r'^(?P<ip>(?:[0-9]{1,3}\.){3}[0-9]{1,3}|[a-fA-F0-9:]+)\s+-\s+\S*\s+\[(?P<time>[^\]]+)\]\s+"(?P<method>[A-Z]+)\s+(?P<path>\S+)\s+(?P<proto>[^"]+)"\s+(?P<status>\d{3})\s+(?P<bytes>\d+|-)(?:\s+"(?P<referer>[^"]*)"\s+"(?P<user_agent>[^"]*)")?',
    re.IGNORECASE,
)

WIN_EVENT_4625_RE = re.compile(
    r".*EventID\s*4625.*Account Name:\s*(?P<user>[A-Za-z0-9_\-\.$]+).*Source Network Address:\s*(?P<ip>(?:[0-9]{1,3}\.){3}[0-9]{1,3})",
    re.IGNORECASE | re.DOTALL,
)

FW_DROP_RE = re.compile(
    r".*(?:DROP|BLOCK|DENY).*SRC=(?P<ip>(?:[0-9]{1,3}\.){3}[0-9]{1,3}).*DPT=(?P<port>\d+)",
    re.IGNORECASE,
)

GENERIC_IPV4_RE = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")

SQLI_KEYWORDS = ["union select", "select * from", "1=1", "or 1=1", "drop table", "information_schema", "sleep(", "--", "/*"]
TRAVERSAL_KEYWORDS = ["../", "..\\", "%2e%2e%2f", "%2e%2e/", "..%2f", "/etc/passwd", "win.ini", "boot.ini"]


class ParsedEvent:
    def __init__(
        self,
        source_ip: str,
        service: str,
        action: str,
        raw_log: str,
        is_suspicious: bool = False,
        meta_data: Optional[Dict[str, Any]] = None,
        timestamp: Optional[datetime] = None,
    ):
        self.source_ip = source_ip
        self.service = service
        self.action = action
        self.raw_log = raw_log
        self.is_suspicious = is_suspicious
        self.meta_data = meta_data or {}
        self.timestamp = timestamp or datetime.utcnow()


def parse_log_line(raw_line: str, service_hint: Optional[str] = None) -> ParsedEvent:
    """
    Parses an arbitrary raw log line into a standardized ParsedEvent object.
    Applies heuristics and regex extractors matching CrowdSec parser specifications.
    """
    line = raw_line.strip()

    # 1. SSH Log Parsing
    if service_hint == "ssh" or "sshd[" in line or "ssh" in line.lower():
        match_failed = SSH_FAILED_PWD_RE.search(line)
        if match_failed:
            return ParsedEvent(
                source_ip=match_failed.group("ip"),
                service="ssh",
                action="failed_login",
                raw_log=line,
                is_suspicious=True,
                meta_data={
                    "user": match_failed.group("user").rstrip(",;"),
                    "port": int(match_failed.group("port")),
                    "log_type": "ssh_auth_failure",
                },
            )

        match_invalid = SSH_INVALID_USER_RE.search(line)
        if match_invalid:
            return ParsedEvent(
                source_ip=match_invalid.group("ip"),
                service="ssh",
                action="failed_login",
                raw_log=line,
                is_suspicious=True,
                meta_data={
                    "user": match_invalid.group("user").rstrip(",;"),
                    "port": int(match_invalid.group("port")) if match_invalid.group("port") else 22,
                    "log_type": "ssh_invalid_user",
                },
            )

        match_accept = SSH_ACCEPTED_RE.search(line)
        if match_accept:
            return ParsedEvent(
                source_ip=match_accept.group("ip"),
                service="ssh",
                action="accepted_login",
                raw_log=line,
                is_suspicious=False,
                meta_data={
                    "user": match_accept.group("user").rstrip(",;"),
                    "port": int(match_accept.group("port")),
                    "log_type": "ssh_auth_success",
                },
            )

    # 2. HTTP / Nginx / Apache Log Parsing
    if service_hint == "nginx" or service_hint == "http" or ' "GET ' in line or ' "POST ' in line or ' "PUT ' in line or ' "DELETE ' in line:
        http_match = HTTP_ACCESS_RE.search(line)
        if http_match:
            ip = http_match.group("ip")
            method = http_match.group("method")
            path = http_match.group("path")
            status_code = int(http_match.group("status"))
            user_agent = http_match.group("user_agent") or ""

            # Decode URL encoded characters (e.g. %20 -> space, %2e -> .)
            path_decoded = urllib.parse.unquote(path).lower()
            is_sqli = any(kw in path_decoded for kw in SQLI_KEYWORDS)
            is_traversal = any(kw in path_decoded for kw in TRAVERSAL_KEYWORDS) or ("../" in path)
            is_404 = (status_code == 404 or status_code == 403)

            action = "http_request"
            is_suspicious = False
            if is_sqli:
                action = "sqli_attempt"
                is_suspicious = True
            elif is_traversal:
                action = "traversal_attempt"
                is_suspicious = True
            elif is_404:
                action = "404_not_found"
                is_suspicious = True

            return ParsedEvent(
                source_ip=ip,
                service="nginx",
                action=action,
                raw_log=line,
                is_suspicious=is_suspicious,
                meta_data={
                    "http_method": method,
                    "http_path": path,
                    "http_status": status_code,
                    "user_agent": user_agent,
                    "is_sqli": is_sqli,
                    "is_traversal": is_traversal,
                },
            )

    # 3. Windows Security Event Log
    win_match = WIN_EVENT_4625_RE.search(line)
    if win_match:
        return ParsedEvent(
            source_ip=win_match.group("ip"),
            service="windows",
            action="failed_login",
            raw_log=line,
            is_suspicious=True,
            meta_data={
                "user": win_match.group("user").rstrip(",;"),
                "event_id": 4625,
            },
        )

    # 4. Firewall DROP / Port Scan
    fw_match = FW_DROP_RE.search(line)
    if fw_match:
        return ParsedEvent(
            source_ip=fw_match.group("ip"),
            service="firewall",
            action="port_probe",
            raw_log=line,
            is_suspicious=True,
            meta_data={
                "dest_port": int(fw_match.group("port")),
            },
        )

    # 5. Generic Fallback Parser
    ip_match = GENERIC_IPV4_RE.search(line)
    extracted_ip = ip_match.group(0) if ip_match else "127.0.0.1"

    line_lower = urllib.parse.unquote(line).lower()
    is_suspicious = False
    action = "generic_log"
    meta = {}

    if any(k in line_lower for k in ["failed", "invalid", "unauthorized", "access denied", "denied"]):
        action = "failed_auth"
        is_suspicious = True
    elif any(kw in line_lower for kw in SQLI_KEYWORDS):
        action = "sqli_attempt"
        is_suspicious = True
    elif any(kw in line_lower for kw in TRAVERSAL_KEYWORDS):
        action = "traversal_attempt"
        is_suspicious = True

    return ParsedEvent(
        source_ip=extracted_ip,
        service=service_hint or "system",
        action=action,
        raw_log=line,
        is_suspicious=is_suspicious,
        meta_data=meta,
    )
