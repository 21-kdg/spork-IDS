"""Unit tests for the Python Leaky Bucket detection engine and scenario rules."""
import time
from app.detection.buckets import LeakyBucket, TriggerBucket, UniqBucket
from app.detection.engine import DetectionEngine
from app.detection.scenarios import BUILTIN_SCENARIOS


def test_leaky_bucket_overflow():
    """Verify standard leaky bucket overflows when capacity is reached."""
    bucket = LeakyBucket("test/ssh-bf", "192.168.1.50", capacity=3, leakspeed_seconds=10.0)
    now = time.time()

    # Drop 1
    overflow, count = bucket.pour(now, {"event": 1})
    assert not overflow
    assert count == 1

    # Drop 2
    overflow, count = bucket.pour(now + 1, {"event": 2})
    assert not overflow
    assert count == 2

    # Drop 3 - Reaches capacity
    overflow, count = bucket.pour(now + 2, {"event": 3})
    assert overflow
    assert count == 3


def test_leaky_bucket_draining():
    """Verify leaky bucket drains drops over elapsed time and prevents false positive."""
    bucket = LeakyBucket("test/slow-attempts", "192.168.1.50", capacity=3, leakspeed_seconds=5.0)
    now = time.time()

    # Drop 1
    bucket.pour(now, {"event": 1})
    assert bucket.current_drops == 1.0

    # 15 seconds later (3 * 5s leak intervals), drops should drain to 0
    bucket.pour(now + 15.0, {"event": 2})
    # Since previous drop leaked away, current drops should be 1.0, not 2.0
    assert bucket.current_drops == 1.0


def test_trigger_bucket_immediate_overflow():
    """Verify trigger bucket immediately overflows on a single event."""
    bucket = TriggerBucket("test/sqli", "10.0.0.99")
    overflow, count = bucket.pour(time.time(), {"sqli": True})
    assert overflow is True
    assert count == 1


def test_uniq_bucket_cardinality():
    """Verify uniq bucket only counts unique values and overflows on threshold."""
    bucket = UniqBucket("test/portscan", "10.0.0.1", capacity=3, leakspeed_seconds=60.0)
    now = time.time()

    # Pour port 80 twice - should count as 1 unique port
    bucket.pour(now, {}, uniq_val="80")
    overflow, count = bucket.pour(now + 1, {}, uniq_val="80")
    assert not overflow
    assert count == 1

    # Pour port 443 - 2 unique ports
    overflow, count = bucket.pour(now + 2, {}, uniq_val="443")
    assert not overflow
    assert count == 2

    # Pour port 22 - 3 unique ports -> capacity reached!
    overflow, count = bucket.pour(now + 3, {}, uniq_val="22")
    assert overflow is True
    assert count == 3


def test_detection_engine_ssh_bruteforce():
    """Verify detection engine processes SSH brute-force events and generates alert."""
    engine = DetectionEngine()
    ip = "192.168.1.200"

    event_template = {
        "source_ip": ip,
        "service": "ssh",
        "action": "failed_login",
        "raw_log": f"Failed password for invalid user admin from {ip} port 44321 ssh2",
        "meta_data": {"user": "admin", "log_type": "ssh_auth_failure"},
    }

    # Pour 4 attempts - threshold is 5
    for _ in range(4):
        overflows = engine.process_event(event_template)
        assert len(overflows) == 0

    # 5th attempt triggers overflow
    overflows = engine.process_event(event_template)
    assert len(overflows) == 1
    assert overflows[0].scenario.name == "spork/ssh-bf"
    assert overflows[0].source_ip == ip
    assert overflows[0].scenario.remediation_type == "ban"


def test_detection_engine_sqli_trigger():
    """Verify SQL injection triggers immediate overflow on first sight."""
    engine = DetectionEngine()
    sqli_event = {
        "source_ip": "45.33.32.1",
        "service": "nginx",
        "action": "sqli_attempt",
        "raw_log": "GET /products?id=1 UNION SELECT null,username FROM users-- HTTP/1.1",
        "meta_data": {"is_sqli": True, "http_status": 200},
    }

    overflows = engine.process_event(sqli_event)
    assert len(overflows) == 1
    assert overflows[0].scenario.name == "spork/http-sqli"
    assert overflows[0].scenario.severity == "critical"


def test_detection_engine_false_positive_normal_traffic():
    """Verify normal traffic does not trigger any scenario."""
    engine = DetectionEngine()
    normal_event = {
        "source_ip": "192.168.1.10",
        "service": "nginx",
        "action": "http_request",
        "raw_log": '192.168.1.10 - - [23/Oct/2026:12:00:00 +0000] "GET /about.html HTTP/1.1" 200 4500',
        "meta_data": {"http_status": 200, "is_sqli": False, "is_traversal": False},
    }

    for _ in range(20):
        overflows = engine.process_event(normal_event)
        assert len(overflows) == 0
