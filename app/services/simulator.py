"""Live Attack Simulation and Anomaly Stream Engine for Spork-IDS."""
import random
import threading
import time
from datetime import datetime
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
from app.db.session import SessionLocal
from app.models.db_models import EventModel, AlertModel, DecisionModel
from app.services.pipeline import pipeline
from app.detection.engine import engine as detection_engine


SIMULATION_SCENARIOS_META = [
    {
        "id": "spork/ssh-bf",
        "name": "SSH Brute-Force Attack",
        "description": "Simulates rapid SSH authentication failures from a single attacker targeting administrative usernames.",
        "category": "Authentication",
        "default_ip": "185.220.101.5",
        "sample_payload": "Failed password for invalid user admin from 185.220.101.5 port 42812 ssh2",
        "bucket_type": "leaky",
        "burst_count": 6,
    },
    {
        "id": "spork/http-sqli",
        "name": "SQL Injection (SQLi) Probe",
        "description": "Exploits web endpoint query parameters with UNION SELECT and database extraction syntax.",
        "category": "Web Application",
        "default_ip": "45.33.32.156",
        "sample_payload": 'GET /api/v1/products?id=1%20UNION%20SELECT%20username,password_hash%20FROM%20users-- HTTP/1.1" 200 450 "-" "sqlmap/1.8"',
        "bucket_type": "trigger",
        "burst_count": 1,
    },
    {
        "id": "spork/http-path-traversal",
        "name": "Path / Directory Traversal",
        "description": "Attempts unauthorized access to sensitive system configuration files like /etc/passwd and win.ini.",
        "category": "Web Application",
        "default_ip": "94.102.61.12",
        "sample_payload": 'GET /static/../../../../etc/passwd HTTP/1.1" 404 153 "-" "Mozilla/5.0"',
        "bucket_type": "trigger",
        "burst_count": 1,
    },
    {
        "id": "spork/port-scan",
        "name": "TCP Port Reconnaissance Scan",
        "description": "Probes multiple distinct network service ports (21, 22, 80, 443, 3306, 8080) to identify open services.",
        "category": "Network Recon",
        "default_ip": "198.51.100.27",
        "sample_payload": "iptables: DROP: IN=eth0 SRC=198.51.100.27 DST=10.0.0.1 PROTO=TCP DPT=22",
        "bucket_type": "uniq",
        "burst_count": 6,
    },
    {
        "id": "spork/http-crawl-bf",
        "name": "Aggressive Web Route Enumeration",
        "description": "Probes high-value web endpoints (/wp-admin, /.env, /actuator/health, /phpmyadmin) causing 404/403 errors.",
        "category": "Web Application",
        "default_ip": "116.202.120.88",
        "sample_payload": 'GET /.env HTTP/1.1" 404 162 "-" "Go-http-client/1.1"',
        "bucket_type": "leaky",
        "burst_count": 9,
    },
    {
        "id": "spork/auth-credential-stuffing",
        "name": "Multi-Account Credential Stuffing",
        "description": "Attacker tests credentials against multiple target accounts from a single IP address in rapid succession.",
        "category": "Identity & Access",
        "default_ip": "203.0.113.89",
        "sample_payload": "Failed password for root from 203.0.113.89 port 51230 ssh2",
        "bucket_type": "uniq",
        "burst_count": 5,
    },
    {
        "id": "benign",
        "name": "Benign Network & Web Traffic",
        "description": "Normal legitimate application requests, static asset loads, and successful administrative logins.",
        "category": "Legitimate Traffic",
        "default_ip": "192.168.1.105",
        "sample_payload": 'GET /dashboard HTTP/1.1" 200 4520 "https://app.local" "Mozilla/5.0"',
        "bucket_type": "none",
        "burst_count": 3,
    },
]


class SimulatorService:
    """Manages on-demand and continuous background attack simulation."""

    def __init__(self):
        self._is_running = False
        self._thread: Optional[threading.Thread] = None
        self._interval_seconds = 3.0
        self._include_attacks = True
        self._lock = threading.RLock()
        self._total_simulated_events = 0
        self._total_simulated_alerts = 0
        self._active_scenario: Optional[str] = None
        self._last_run_timestamp: Optional[str] = None

    def get_scenarios(self) -> List[Dict[str, Any]]:
        return list(SIMULATION_SCENARIOS_META)

    def generate_raw_logs(
        self, scenario_name: str, attacker_ip: Optional[str] = None, count: Optional[int] = None
    ) -> List[str]:
        now_str = datetime.utcnow().strftime("%b %d %H:%M:%S")
        http_time = datetime.utcnow().strftime("%d/%b/%Y:%H:%M:%S +0000")

        if scenario_name == "spork/ssh-bf":
            ip = attacker_ip or "185.220.101.5"
            targets = ["admin", "root", "ubuntu", "test", "postgres", "deploy", "oracle", "dev"]
            n = count or 6
            logs = []
            for i in range(n):
                user = targets[i % len(targets)]
                port = 40000 + (i * 2)
                # Alternate between standard sshd syntax and auth failed message
                if i % 2 == 0:
                    logs.append(f"{now_str} srv01 sshd[29{i:03d}]: Failed password for invalid user {user} from {ip} port {port} ssh2")
                else:
                    logs.append(f"{now_str} srv01 sshd[29{i:03d}]: ssh auth failed for user {user} from {ip} port {port} ssh2")
            return logs

        elif scenario_name == "spork/http-sqli":
            ip = attacker_ip or "45.33.32.156"
            payloads = [
                f'{ip} - - [{http_time}] "GET /api/v1/users?id=1%20UNION%20SELECT%20username,password_hash%20FROM%20users-- HTTP/1.1" 200 452 "-" "sqlmap/1.8.2"',
                f'{ip} - - [{http_time}] "POST /login HTTP/1.1" 200 120 "-" "Mozilla/5.0" [Payload: username=\' or 1=1--]',
                f'{ip} - - [{http_time}] "GET /catalog?category=all%27%20OR%201=1-- HTTP/1.1" 200 1890 "-" "sqlmap/1.8.2"',
            ]
            n = count or 1
            return payloads[:n]

        elif scenario_name == "spork/http-path-traversal":
            ip = attacker_ip or "94.102.61.12"
            payloads = [
                f'{ip} - - [{http_time}] "GET /static/../../../../etc/passwd HTTP/1.1" 404 153 "-" "curl/8.4.0"',
                f'{ip} - - [{http_time}] "GET /download?file=..%2f..%2f..%2fetc%2fshadow HTTP/1.1" 404 153 "-" "curl/8.4.0"',
                f'{ip} - - [{http_time}] "GET /view?doc=../../../../windows/win.ini HTTP/1.1" 404 153 "-" "curl/8.4.0"',
            ]
            n = count or 1
            return payloads[:n]

        elif scenario_name == "spork/port-scan":
            ip = attacker_ip or "198.51.100.27"
            ports = [21, 22, 23, 80, 443, 3306, 5432, 8080]
            n = count or 6
            logs = []
            for i in range(min(n, len(ports))):
                p = ports[i]
                logs.append(f"iptables: DROP: IN=eth0 OUT= SRC={ip} DST=10.0.0.1 PROTO=TCP SPT={50000+i} DPT={p}")
            return logs

        elif scenario_name == "spork/http-crawl-bf":
            ip = attacker_ip or "116.202.120.88"
            paths = [
                "/wp-login.php",
                "/admin.php",
                "/phpmyadmin/index.php",
                "/.env",
                "/config.json",
                "/actuator/health",
                "/backup.zip",
                "/shell.php",
                "/console/",
                "/server-status",
            ]
            n = count or 9
            logs = []
            for i in range(min(n, len(paths))):
                path = paths[i]
                logs.append(f'{ip} - - [{http_time}] "GET {path} HTTP/1.1" 404 162 "-" "Go-http-client/1.1"')
            return logs

        elif scenario_name == "spork/auth-credential-stuffing":
            ip = attacker_ip or "203.0.113.89"
            users = ["admin", "root", "charlie", "david", "elena", "finance", "jordan"]
            n = count or 5
            logs = []
            for i in range(min(n, len(users))):
                user = users[i]
                logs.append(f"{now_str} auth01 sshd[31{i:03d}]: Failed password for {user} from {ip} port {52000+i} ssh2")
            return logs

        else:  # Benign
            ip = attacker_ip or "192.168.1.105"
            return [
                f'{ip} - - [{http_time}] "GET /index.html HTTP/1.1" 200 3210 "https://internal.lan" "Mozilla/5.0"',
                f'{ip} - - [{http_time}] "GET /assets/style.css HTTP/1.1" 200 12040 "https://internal.lan" "Mozilla/5.0"',
                f"{now_str} srv01 sshd[32010]: Accepted password for sysadmin from {ip} port 51430 ssh2",
            ]

    def launch_attack_simulation(
        self, db: Session, scenario_name: str, source_ip: Optional[str] = None, count: Optional[int] = None
    ) -> Dict[str, Any]:
        """Launches a simulation burst against the real Spork-IDS detection engine."""
        meta = next((s for s in SIMULATION_SCENARIOS_META if s["id"] == scenario_name), None)
        effective_ip = source_ip.strip() if source_ip else (meta["default_ip"] if meta else "198.51.100.99")
        logs = self.generate_raw_logs(scenario_name, effective_ip, count)

        alerts_created = []
        decisions_created = []

        service_hint = "ssh" if "ssh" in scenario_name or "auth" in scenario_name else ("nginx" if "http" in scenario_name else None)

        for line in logs:
            res = pipeline.process_raw_line(db, line, service_hint=service_hint, is_simulated=True)
            for alert in res.get("alerts", []):
                alerts_created.append(alert)
            for dec in res.get("decisions", []):
                decisions_created.append(dec)

        overflow_triggered = len(alerts_created) > 0

        with self._lock:
            self._total_simulated_events += len(logs)
            self._total_simulated_alerts += len(alerts_created)
            self._active_scenario = scenario_name
            self._last_run_timestamp = datetime.utcnow().isoformat()

        msg = (
            f"Successfully simulated {scenario_name} with {len(logs)} events. "
            f"Bucket overflowed! Triggered {len(alerts_created)} alert(s) and {len(decisions_created)} ban decision(s)."
            if overflow_triggered
            else f"Generated {len(logs)} simulated events for {scenario_name}. No overflow triggered (below capacity)."
        )

        return {
            "status": "success",
            "scenario": scenario_name,
            "attacker_ip": effective_ip,
            "events_generated": len(logs),
            "overflow_triggered": overflow_triggered,
            "logs_generated": logs,
            "alerts_created": alerts_created,
            "decisions_created": decisions_created,
            "message": msg,
        }

    def start_background_simulation(self, interval_seconds: float = 3.0, include_attacks: bool = True):
        with self._lock:
            if self._is_running:
                self._interval_seconds = interval_seconds
                self._include_attacks = include_attacks
                return
            self._is_running = True
            self._interval_seconds = interval_seconds
            self._include_attacks = include_attacks

            self._thread = threading.Thread(target=self._run_loop, daemon=True)
            self._thread.start()

    def stop_background_simulation(self):
        with self._lock:
            self._is_running = False

    def get_status(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "is_running": self._is_running,
                "interval_seconds": self._interval_seconds,
                "total_simulated_events": self._total_simulated_events,
                "total_simulated_alerts": self._total_simulated_alerts,
                "active_scenario": self._active_scenario,
                "last_run_timestamp": self._last_run_timestamp,
            }

    def reset_simulated_data(self, db: Session) -> Dict[str, Any]:
        """Cleans all simulated events, alerts, and decisions from the system."""
        with self._lock:
            self._is_running = False
            self._total_simulated_events = 0
            self._total_simulated_alerts = 0
            self._active_scenario = None

        # Delete simulated decisions
        sim_decisions = db.query(DecisionModel).filter(DecisionModel.simulated == True).all()
        dec_count = len(sim_decisions)
        for d in sim_decisions:
            db.delete(d)

        # Delete simulated alerts
        sim_alerts = db.query(AlertModel).filter(AlertModel.is_simulated == True).all()
        alert_count = len(sim_alerts)
        for a in sim_alerts:
            db.delete(a)

        # Delete simulated events
        sim_events = db.query(EventModel).filter(EventModel.is_simulated == True).all()
        event_count = len(sim_events)
        for e in sim_events:
            db.delete(e)

        db.commit()

        # Clear in-memory bucket instances
        detection_engine.buckets.clear()

        return {
            "status": "success",
            "message": f"Purged {event_count} simulated events, {alert_count} alerts, and {dec_count} decisions.",
            "deleted_events": event_count,
            "deleted_alerts": alert_count,
            "deleted_decisions": dec_count,
        }

    def _run_loop(self):
        cycle = 0
        attack_scenarios = [
            "spork/ssh-bf",
            "spork/http-sqli",
            "spork/http-path-traversal",
            "spork/port-scan",
            "spork/http-crawl-bf",
            "spork/auth-credential-stuffing",
        ]

        while True:
            with self._lock:
                if not self._is_running:
                    break
                interval = self._interval_seconds
                include_attacks = self._include_attacks

            try:
                with SessionLocal() as db:
                    # Every 3rd cycle, trigger an attack burst if enabled
                    if include_attacks and (cycle % 3 == 0):
                        chosen_attack = random.choice(attack_scenarios)
                        self.launch_attack_simulation(db, chosen_attack)
                    else:
                        self.launch_attack_simulation(db, "benign")
            except Exception as e:
                pass

            cycle += 1
            time.sleep(interval)


simulator = SimulatorService()
