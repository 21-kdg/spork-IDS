"""Initial seed data for Spork-IDS."""
import time
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from app.models.db_models import EventModel
from app.services.pipeline import pipeline


def seed_initial_data(db: Session) -> None:
    """Populates the database with realistic sample security events if empty."""
    count = db.query(EventModel).count()
    if count > 0:
        return

    sample_logs = [
        # SSH Brute Force series from 185.220.101.5 (Tor exit node simulation)
        (
            "Oct 23 14:10:01 web01 sshd[28410]: Failed password for invalid user admin from 185.220.101.5 port 42812 ssh2",
            "ssh",
        ),
        (
            "Oct 23 14:10:04 web01 sshd[28412]: Failed password for invalid user root from 185.220.101.5 port 42814 ssh2",
            "ssh",
        ),
        (
            "Oct 23 14:10:07 web01 sshd[28415]: Failed password for invalid user test from 185.220.101.5 port 42818 ssh2",
            "ssh",
        ),
        (
            "Oct 23 14:10:11 web01 sshd[28419]: Failed password for invalid user ubuntu from 185.220.101.5 port 42822 ssh2",
            "ssh",
        ),
        (
            "Oct 23 14:10:14 web01 sshd[28424]: Failed password for invalid user deploy from 185.220.101.5 port 42826 ssh2",
            "ssh",
        ),
        (
            "Oct 23 14:10:18 web01 sshd[28428]: Failed password for invalid user oracle from 185.220.101.5 port 42830 ssh2",
            "ssh",
        ),
        # SQL Injection attempt from 45.33.32.156
        (
            '45.33.32.156 - - [23/Oct/2026:14:15:22 +0000] "GET /api/v1/products?id=1%20UNION%20SELECT%20username,password%20FROM%20users-- HTTP/1.1" 200 450 "-" "sqlmap/1.7.2"',
            "nginx",
        ),
        # Path Traversal attempt from 94.102.61.12
        (
            '94.102.61.12 - - [23/Oct/2026:14:18:05 +0000] "GET /static/../../../../etc/passwd HTTP/1.1" 404 153 "-" "Mozilla/5.0"',
            "nginx",
        ),
        # Web Route Scanning / Crawl from 116.202.120.88
        (
            '116.202.120.88 - - [23/Oct/2026:14:20:01 +0000] "GET /wp-login.php HTTP/1.1" 404 162 "-" "Go-http-client/1.1"',
            "nginx",
        ),
        (
            '116.202.120.88 - - [23/Oct/2026:14:20:02 +0000] "GET /admin.php HTTP/1.1" 404 162 "-" "Go-http-client/1.1"',
            "nginx",
        ),
        (
            '116.202.120.88 - - [23/Oct/2026:14:20:03 +0000] "GET /phpmyadmin/index.php HTTP/1.1" 404 162 "-" "Go-http-client/1.1"',
            "nginx",
        ),
        (
            '116.202.120.88 - - [23/Oct/2026:14:20:04 +0000] "GET /.env HTTP/1.1" 404 162 "-" "Go-http-client/1.1"',
            "nginx",
        ),
        (
            '116.202.120.88 - - [23/Oct/2026:14:20:05 +0000] "GET /config.json HTTP/1.1" 404 162 "-" "Go-http-client/1.1"',
            "nginx",
        ),
        (
            '116.202.120.88 - - [23/Oct/2026:14:20:06 +0000] "GET /actuator/health HTTP/1.1" 404 162 "-" "Go-http-client/1.1"',
            "nginx",
        ),
        (
            '116.202.120.88 - - [23/Oct/2026:14:20:07 +0000] "GET /backup.zip HTTP/1.1" 404 162 "-" "Go-http-client/1.1"',
            "nginx",
        ),
        (
            '116.202.120.88 - - [23/Oct/2026:14:20:08 +0000] "GET /shell.php HTTP/1.1" 404 162 "-" "Go-http-client/1.1"',
            "nginx",
        ),
        (
            '116.202.120.88 - - [23/Oct/2026:14:20:09 +0000] "GET /console/ HTTP/1.1" 404 162 "-" "Go-http-client/1.1"',
            "nginx",
        ),
        # Normal traffic for contrast
        (
            '192.168.1.100 - - [23/Oct/2026:14:22:15 +0000] "GET /index.html HTTP/1.1" 200 1204 "https://internal.lan" "Mozilla/5.0"',
            "nginx",
        ),
        (
            "Oct 23 14:22:30 web01 sshd[28500]: Accepted password for developer from 192.168.1.100 port 51230 ssh2",
            "ssh",
        ),
    ]

    for line, hint in sample_logs:
        pipeline.process_raw_line(db, line, service_hint=hint)
