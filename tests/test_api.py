"""Integration tests for Spork-IDS REST API endpoints."""


def test_api_health(client):
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["engine"] == "spork-ids-python"


def test_api_dashboard_summary(client):
    response = client.get("/api/dashboard/summary")
    assert response.status_code == 200
    data = response.json()
    assert "total_events" in data
    assert "total_alerts" in data
    assert "active_decisions" in data
    assert "top_attacking_ips" in data


def test_api_events_ingest_and_list(client):
    # Ingest raw logs
    raw_payload = {
        "logs": [
            "Failed password for invalid user hacker from 192.0.2.1 port 55111 ssh2",
            '192.0.2.2 - - [23/Oct/2026:12:00:00 +0000] "GET /index.html HTTP/1.1" 200 1024',
        ],
        "service_hint": "ssh",
    }
    post_res = client.post("/api/events/raw", json=raw_payload)
    assert post_res.status_code == 200
    post_data = post_res.json()
    assert post_data["processed_count"] == 2

    # Query events list
    list_res = client.get("/api/events")
    assert list_res.status_code == 200
    events_data = list_res.json()
    assert events_data["total"] >= 2


def test_api_alerts_lifecycle(client):
    # Ingest a critical SQL injection exploit to trigger an alert
    sqli_payload = {
        "logs": [
            '198.51.100.77 - - [23/Oct/2026:12:00:00 +0000] "GET /users?id=1%20UNION%20SELECT%20*%20FROM%20admin HTTP/1.1" 200 1000 "-" "sqlmap"'
        ],
        "service_hint": "nginx",
    }
    ingest_res = client.post("/api/events/raw", json=sqli_payload)
    assert ingest_res.status_code == 200
    assert ingest_res.json()["alerts_triggered"] == 1

    # Query alerts list
    list_res = client.get("/api/alerts?severity=critical")
    assert list_res.status_code == 200
    alerts_data = list_res.json()
    assert alerts_data["total"] >= 1
    alert_item = alerts_data["items"][0]
    alert_id = alert_item["id"]

    # Get single alert detail
    detail_res = client.get(f"/api/alerts/{alert_id}")
    assert detail_res.status_code == 200
    assert detail_res.json()["scenario"] == "spork/http-sqli"
    assert len(detail_res.json()["decisions"]) >= 1

    # Update alert status to resolved
    patch_res = client.patch(f"/api/alerts/{alert_id}/status", json={"status": "resolved"})
    assert patch_res.status_code == 200
    assert patch_res.json()["status"] == "resolved"

    # Delete alert
    del_res = client.delete(f"/api/alerts/{alert_id}")
    assert del_res.status_code == 204

    # Verify not found after delete
    get_after = client.get(f"/api/alerts/{alert_id}")
    assert get_after.status_code == 404


def test_api_scenarios_list_and_evaluate(client):
    # List scenarios
    list_res = client.get("/api/scenarios")
    assert list_res.status_code == 200
    scenarios = list_res.json()
    assert scenarios["total"] >= 5

    # Evaluate sandbox on SQL injection
    eval_payload = {
        "scenario_name": "spork/http-sqli",
        "source_ip": "198.51.100.99",
        "raw_log": "GET /api?id=1 UNION SELECT * FROM users HTTP/1.1",
        "service": "nginx",
        "meta_data": {"is_sqli": True},
    }
    eval_res = client.post("/api/scenarios/evaluate", json=eval_payload)
    assert eval_res.status_code == 200
    eval_data = eval_res.json()
    assert eval_data["matched_filter"] is True
    assert eval_data["overflow"] is True
    assert eval_data["alert_generated"] is not None


def test_api_decisions_crud(client):
    # Create manual decision
    create_payload = {
        "value": "203.0.113.50",
        "scope": "Ip",
        "type": "ban",
        "duration": "2h",
        "scenario": "manual/unit-test",
    }
    create_res = client.post("/api/decisions", json=create_payload)
    assert create_res.status_code == 201
    decision = create_res.json()
    dec_id = decision["id"]
    assert decision["value"] == "203.0.113.50"
    assert decision["is_active"] is True

    # List active decisions
    list_res = client.get("/api/decisions?active_only=true")
    assert list_res.status_code == 200
    active = list_res.json()
    assert any(d["id"] == dec_id for d in active["items"])

    # Revoke decision
    del_res = client.delete(f"/api/decisions/{dec_id}")
    assert del_res.status_code == 200

    # Verify no longer active
    list_after = client.get("/api/decisions?active_only=true")
    assert not any(d["id"] == dec_id for d in list_after.json()["items"])


def test_api_metrics(client):
    response = client.get("/api/metrics")
    assert response.status_code == 200
    data = response.json()
    assert "events_ingested" in data
    assert "alerts_triggered" in data
    assert "scenarios" in data


def test_api_settings(client):
    response = client.get("/api/settings")
    assert response.status_code == 200
    data = response.json()
    assert "server_host" in data
    assert "crowdsec_connected" in data
