"""Unit tests for the Spork-IDS security log parser and normalizer."""
from app.services.parser import parse_log_line


def test_parse_ssh_failed_password():
    raw = "Failed password for invalid user admin from 192.168.1.105 port 53421 ssh2"
    event = parse_log_line(raw, service_hint="ssh")
    assert event.source_ip == "192.168.1.105"
    assert event.service == "ssh"
    assert event.action == "failed_login"
    assert event.is_suspicious is True
    assert event.meta_data.get("user") == "admin"
    assert event.meta_data.get("port") == 53421


def test_parse_ssh_accepted():
    raw = "Accepted password for developer from 10.0.0.12 port 50123 ssh2"
    event = parse_log_line(raw, service_hint="ssh")
    assert event.source_ip == "10.0.0.12"
    assert event.service == "ssh"
    assert event.action == "accepted_login"
    assert event.is_suspicious is False


def test_parse_http_sqli_signature():
    raw = '185.220.101.4 - - [23/Oct/2026:12:00:00 +0000] "GET /items?id=1%20UNION%20SELECT%20*%20FROM%20users HTTP/1.1" 200 500 "-" "curl/7.68.0"'
    event = parse_log_line(raw, service_hint="nginx")
    assert event.source_ip == "185.220.101.4"
    assert event.service == "nginx"
    assert event.action == "sqli_attempt"
    assert event.is_suspicious is True
    assert event.meta_data.get("is_sqli") is True


def test_parse_http_path_traversal():
    raw = '94.102.61.12 - - [23/Oct/2026:12:00:00 +0000] "GET /static/../../../../etc/passwd HTTP/1.1" 404 153 "-" "Mozilla/5.0"'
    event = parse_log_line(raw, service_hint="nginx")
    assert event.source_ip == "94.102.61.12"
    assert event.service == "nginx"
    assert event.action == "traversal_attempt"
    assert event.is_suspicious is True
    assert event.meta_data.get("is_traversal") is True


def test_parse_windows_event():
    raw = "EventID 4625: An account failed to log on. Account Name: Guest, Source Network Address: 172.16.0.45"
    event = parse_log_line(raw)
    assert event.source_ip == "172.16.0.45"
    assert event.service == "windows"
    assert event.action == "failed_login"
    assert event.is_suspicious is True
    assert event.meta_data.get("user") == "Guest"


def test_parse_firewall_drop():
    raw = "iptables DROP: IN=eth0 SRC=198.51.100.22 DST=192.168.1.1 PROTO=TCP DPT=23"
    event = parse_log_line(raw)
    assert event.source_ip == "198.51.100.22"
    assert event.service == "firewall"
    assert event.action == "port_probe"
    assert event.is_suspicious is True
    assert event.meta_data.get("dest_port") == 23
