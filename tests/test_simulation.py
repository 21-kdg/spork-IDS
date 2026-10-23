"""Unit and integration tests for Live Attack Simulation Engine."""
import pytest
from fastapi.testclient import TestClient
from app.main import app


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


def test_simulation_scenarios_list(client):
    res = client.get("/api/simulation/scenarios")
    assert res.status_code == 200
    scenarios = res.json()
    assert len(scenarios) >= 6
    ids = [s["id"] for s in scenarios]
    assert "spork/ssh-bf" in ids
    assert "spork/http-sqli" in ids
    assert "spork/port-scan" in ids
    assert "benign" in ids


def test_simulation_launch_ssh_brute_force(client):
    res = client.post(
        "/api/simulation/launch",
        json={"scenario": "spork/ssh-bf", "source_ip": "185.220.101.99"},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    assert data["scenario"] == "spork/ssh-bf"
    assert data["attacker_ip"] == "185.220.101.99"
    assert data["events_generated"] >= 5
    assert data["overflow_triggered"] is True
    assert len(data["alerts_created"]) >= 1
    assert len(data["decisions_created"]) >= 1

    # Verify alert exists in API with is_simulated=True
    alerts_res = client.get("/api/alerts?ip=185.220.101.99")
    assert alerts_res.status_code == 200
    alert_items = alerts_res.json()["items"]
    assert len(alert_items) >= 1
    assert alert_items[0]["is_simulated"] is True


def test_simulation_launch_sqli(client):
    res = client.post(
        "/api/simulation/launch",
        json={"scenario": "spork/http-sqli", "source_ip": "45.33.32.99"},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    assert data["overflow_triggered"] is True
    assert len(data["alerts_created"]) >= 1


def test_simulation_launch_benign(client):
    res = client.post(
        "/api/simulation/launch",
        json={"scenario": "benign", "source_ip": "192.168.1.200"},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    assert data["overflow_triggered"] is False
    assert len(data["alerts_created"]) == 0


def test_scenarios_simulate_alias(client):
    res = client.post(
        "/api/scenarios/simulate",
        json={"scenario": "spork/http-path-traversal", "source_ip": "94.102.61.99"},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    assert data["overflow_triggered"] is True


def test_simulation_status_and_lifecycle(client):
    # Check status
    res = client.get("/api/simulation/status")
    assert res.status_code == 200
    assert "is_running" in res.json()

    # Start
    start_res = client.post("/api/simulation/start", json={"interval_seconds": 2.0})
    assert start_res.status_code == 200
    assert start_res.json()["is_running"] is True

    # Stop
    stop_res = client.post("/api/simulation/stop")
    assert stop_res.status_code == 200
    assert stop_res.json()["is_running"] is False


def test_simulation_reset(client):
    # Launch something first
    client.post("/api/simulation/launch", json={"scenario": "spork/ssh-bf"})
    # Reset
    res = client.post("/api/simulation/reset")
    assert res.status_code == 200
    assert res.json()["status"] == "success"
