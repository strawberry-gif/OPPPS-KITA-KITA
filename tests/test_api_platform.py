from __future__ import annotations

import pytest

pytestmark = pytest.mark.api


# ---------------------------------------------------------------------------
# Health / overview / analytics
# ---------------------------------------------------------------------------


def test_health_is_public_and_reports_dependencies(client):
    response = client.get("/api/dashboard/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["database"] == "connected"
    assert body["models_ready"] is True
    assert body["active_classifier"]["id"]
    assert body["active_anomaly_model"]["id"]
    assert body["live_capture_available"] is False
    assert body["live_capture_running"] is False
    assert body["server_time"]


@pytest.mark.parametrize("range_value", ["24h", "7d", "30d", "all"])
def test_overview_supports_every_range(client, analyst_headers, range_value):
    response = client.get(
        f"/api/dashboard/overview?range={range_value}", headers=analyst_headers
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["range"] == range_value
    assert {
        "total_records",
        "analyzed",
        "anomalies",
        "attacks",
        "suspicious_ips",
        "incidents",
    } <= set(body["totals"])
    assert isinstance(body["timeline"], list)
    assert isinstance(body["protocol_distribution"], list)
    assert isinstance(body["attack_distribution"], list)
    assert len(body["active_models"]) == 2
    assert body["generated_at"]
    if range_value == "all":
        assert body["totals"]["total_records"] > 0
        assert body["totals"]["analyzed"] > 0


def test_overview_rejects_invalid_range(client, analyst_headers):
    response = client.get(
        "/api/dashboard/overview?range=90d", headers=analyst_headers
    )
    assert response.status_code == 422


def test_analytics_returns_real_aggregates(client, analyst_headers):
    response = client.get("/api/analytics?range=all", headers=analyst_headers)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["range"] == "all"
    assert body["totals"]["total_records"] > 0
    assert body["timeline"]
    assert all(
        {"bucket", "total", "anomalies", "attacks", "critical", "high"}
        <= set(point)
        for point in body["timeline"]
    )
    assert body["protocol_distribution"]
    assert body["top_destination_ports"]
    assert {"label", "count"} <= set(body["protocol_distribution"][0])
    sums = {item["label"]: item["count"] for item in body["status_distribution"]}
    assert sum(sums.values()) >= body["totals"]["incidents"]


def test_analytics_rejects_invalid_range(client, analyst_headers):
    assert (
        client.get("/api/analytics?range=year", headers=analyst_headers).status_code
        == 422
    )


def test_analytics_requires_authentication(client):
    assert client.get("/api/analytics").status_code == 401


# ---------------------------------------------------------------------------
# Settings and audit log
# ---------------------------------------------------------------------------


def test_settings_are_readable_by_any_role(client, viewer_headers):
    response = client.get("/api/settings", headers=viewer_headers)
    assert response.status_code == 200
    body = response.json()
    assert {
        "incident_min_severity",
        "default_dashboard_range",
        "analyst_note_required_on_close",
    } <= set(body["values"])
    assert body["descriptions"]["incident_min_severity"]


def test_admin_can_update_and_restore_settings(client, admin_headers):
    updated = client.put(
        "/api/settings",
        headers=admin_headers,
        json={
            "values": {
                "incident_min_severity": "MEDIUM",
                "default_dashboard_range": "24h",
                "analyst_note_required_on_close": "true",
            }
        },
    )
    assert updated.status_code == 200, updated.text
    values = updated.json()["values"]
    assert values["incident_min_severity"] == "MEDIUM"
    assert values["default_dashboard_range"] == "24h"
    assert values["analyst_note_required_on_close"] == "true"

    fetched = client.get("/api/settings", headers=admin_headers).json()["values"]
    assert fetched["incident_min_severity"] == "MEDIUM"

    restored = client.put(
        "/api/settings",
        headers=admin_headers,
        json={
            "values": {
                "incident_min_severity": "HIGH",
                "default_dashboard_range": "7d",
                "analyst_note_required_on_close": "false",
            }
        },
    )
    assert restored.status_code == 200
    assert restored.json()["values"]["incident_min_severity"] == "HIGH"


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("incident_min_severity", "SEVERE"),
        ("default_dashboard_range", "12h"),
        ("analyst_note_required_on_close", "yes"),
        ("unknown_setting", "x"),
    ],
)
def test_settings_validation(client, admin_headers, key, value):
    response = client.put(
        "/api/settings", headers=admin_headers, json={"values": {key: value}}
    )
    assert response.status_code == 422


def test_settings_updates_are_admin_only(client, analyst_headers):
    response = client.put(
        "/api/settings",
        headers=analyst_headers,
        json={"values": {"default_dashboard_range": "30d"}},
    )
    assert response.status_code == 403


def test_audit_log_records_settings_changes(client, admin_headers):
    client.put(
        "/api/settings",
        headers=admin_headers,
        json={"values": {"default_dashboard_range": "7d"}},
    )
    response = client.get("/api/settings/audit?limit=50", headers=admin_headers)
    assert response.status_code == 200
    entries = response.json()
    assert entries
    assert any(entry["action"] == "settings.update" for entry in entries)
    assert {"id", "action", "entity_type", "detail", "created_at"} <= set(entries[0])


def test_audit_log_is_admin_only(client, viewer_headers):
    assert client.get("/api/settings/audit", headers=viewer_headers).status_code == 403


# ---------------------------------------------------------------------------
# Model registry
# ---------------------------------------------------------------------------


def test_model_listing_active_and_comparison(client, analyst_headers):
    listing = client.get("/api/models", headers=analyst_headers)
    assert listing.status_code == 200
    models = listing.json()
    assert len(models) >= 3
    algorithms = {row["algorithm"] for row in models}
    assert {"RandomForest", "DecisionTree", "IsolationForest"} <= algorithms

    active = client.get("/api/models/active", headers=analyst_headers)
    assert active.status_code == 200
    active_rows = active.json()
    assert {row["task_type"] for row in active_rows} == {"classification", "anomaly"}
    assert all(row["is_active"] for row in active_rows)

    comparison = client.get("/api/models/comparison", headers=analyst_headers)
    assert comparison.status_code == 200
    latest = comparison.json()["latest_run"]
    assert latest is not None
    assert latest["selected_classifier"] in {"RandomForest", "DecisionTree"}
    assert "IsolationForest" in latest["comparison"]


def test_model_detail_and_missing(client, analyst_headers):
    listing = client.get("/api/models", headers=analyst_headers).json()
    model_id = listing[0]["id"]
    detail = client.get(f"/api/models/{model_id}", headers=analyst_headers)
    assert detail.status_code == 200
    assert detail.json()["id"] == model_id
    assert client.get("/api/models/99999999", headers=analyst_headers).status_code == 404


def test_admin_can_activate_model_and_restore(client, admin_headers):
    listing = client.get("/api/models", headers=admin_headers).json()
    rf = next(row for row in listing if row["algorithm"] == "RandomForest")
    dt = next(row for row in listing if row["algorithm"] == "DecisionTree")

    activated = client.post(
        f"/api/models/{dt['id']}/activate", headers=admin_headers
    )
    assert activated.status_code == 200, activated.text
    assert activated.json()["is_active"] is True

    active = client.get("/api/models/active", headers=admin_headers).json()
    classification = next(row for row in active if row["task_type"] == "classification")
    assert classification["id"] == dt["id"]

    restored = client.post(
        f"/api/models/{rf['id']}/activate", headers=admin_headers
    )
    assert restored.status_code == 200
    active = client.get("/api/models/active", headers=admin_headers).json()
    classification = next(row for row in active if row["task_type"] == "classification")
    assert classification["id"] == rf["id"]


def test_model_activation_is_admin_only(client, analyst_headers):
    listing = client.get("/api/models", headers=analyst_headers).json()
    response = client.post(
        f"/api/models/{listing[0]['id']}/activate", headers=analyst_headers
    )
    assert response.status_code == 403


def test_training_endpoint_is_admin_only(client, analyst_headers):
    response = client.post(
        "/api/models/train",
        headers=analyst_headers,
        json={"test_size": 0.25, "random_state": 42},
    )
    assert response.status_code == 403


def test_training_rejects_unsafe_dataset_paths(client, admin_headers):
    outside = client.post(
        "/api/models/train",
        headers=admin_headers,
        json={"dataset_path": "C:/Windows/System32/drivers/etc/hosts.csv"},
    )
    assert outside.status_code == 422
    assert "datasets directory" in outside.json()["detail"]

    missing = client.post(
        "/api/models/train",
        headers=admin_headers,
        json={"dataset_path": "datasets/processed/does-not-exist.csv"},
    )
    assert missing.status_code == 422
    assert "does not exist" in missing.json()["detail"]


# ---------------------------------------------------------------------------
# Live monitoring metadata
# ---------------------------------------------------------------------------


def test_monitoring_status_and_interfaces(client, viewer_headers):
    status = client.get("/api/monitoring/status", headers=viewer_headers)
    assert status.status_code == 200
    body = status.json()
    assert body["available"] is False
    assert body["running"] is False
    assert "permissions_note" in body

    interfaces = client.get("/api/monitoring/interfaces", headers=viewer_headers)
    assert interfaces.status_code == 200
    assert isinstance(interfaces.json()["interfaces"], list)


def test_monitoring_start_requires_analyst(client, viewer_headers):
    response = client.post("/api/monitoring/start", headers=viewer_headers)
    assert response.status_code == 403


def test_monitoring_stop_is_safe_when_idle(client, analyst_headers):
    response = client.post("/api/monitoring/stop", headers=analyst_headers)
    assert response.status_code == 200
    assert response.json()["running"] is False


def test_api_root_metadata(client):
    response = client.get("/api")
    assert response.status_code == 200
    body = response.json()
    assert body["name"] == "OPPPS KITA-KITA"
    assert body["health"] == "/api/dashboard/health"
