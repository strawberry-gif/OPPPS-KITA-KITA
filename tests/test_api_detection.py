from __future__ import annotations

import pytest

pytestmark = pytest.mark.api

SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"}

ATTACK_FEATURES = {
    "flow_duration": 0.4,
    "fwd_packet_count": 900,
    "bwd_packet_count": 5,
    "packet_count": 905,
    "packet_length_mean": 78.0,
    "packet_length_std": 12.0,
    "min_packet_length": 54,
    "max_packet_length": 120,
    "flow_bytes_per_sec": 176000.0,
    "flow_packets_per_sec": 2262.0,
    "syn_count": 870,
    "ack_count": 10,
    "rst_count": 0,
    "fin_count": 0,
    "psh_count": 0,
    "header_length": 18000,
    "active_mean": 0.4,
    "idle_mean": 0.0,
    "down_up_ratio": 0.01,
    "destination_port": 80,
    "protocol_num": 6,
}


def test_detection_results_pagination_and_filters(client, analyst_headers):
    response = client.get(
        "/api/detection/results?page=1&page_size=5", headers=analyst_headers
    )
    assert response.status_code == 200
    body = response.json()
    assert body["total"] > 0
    assert len(body["items"]) <= 5
    first = body["items"][0]
    assert {
        "id",
        "traffic_record_id",
        "predicted_label",
        "confidence",
        "is_anomaly",
        "severity",
        "explanation",
    } <= set(first)
    assert first["severity"] in SEVERITIES
    assert 0 <= first["confidence"] <= 1

    severity = first["severity"]
    filtered = client.get(
        f"/api/detection/results?severity={severity}&page_size=10",
        headers=analyst_headers,
    )
    assert filtered.status_code == 200
    assert all(item["severity"] == severity for item in filtered.json()["items"])

    anomalies = client.get(
        "/api/detection/results?anomaly=true&page_size=10", headers=analyst_headers
    )
    assert anomalies.status_code == 200
    assert all(item["is_anomaly"] is True for item in anomalies.json()["items"])

    label = first["predicted_label"]
    by_label = client.get(
        f"/api/detection/results?predicted_label={label}&page_size=10",
        headers=analyst_headers,
    )
    assert by_label.status_code == 200
    assert all(item["predicted_label"] == label for item in by_label.json()["items"])

    search = client.get(
        f"/api/detection/results?search={first['source_ip']}&page_size=10",
        headers=analyst_headers,
    )
    assert search.status_code == 200
    assert search.json()["total"] >= 1


def test_detection_detail_returns_source_flow(client, analyst_headers):
    listing = client.get(
        "/api/detection/results?page_size=1", headers=analyst_headers
    ).json()
    detection_id = listing["items"][0]["id"]
    detail = client.get(
        f"/api/detection/results/{detection_id}", headers=analyst_headers
    )
    assert detail.status_code == 200
    body = detail.json()
    assert body["traffic_record_id"]
    assert body["traffic_record"]["id"] == body["traffic_record_id"]
    assert "features" in body["traffic_record"]
    assert body["traffic_record"]["features"]

    missing = client.get(
        "/api/detection/results/99999999", headers=analyst_headers
    )
    assert missing.status_code == 404


def test_predict_returns_explainable_result(client, analyst_headers):
    response = client.post(
        "/api/detection/predict",
        headers=analyst_headers,
        json={
            "src_ip": "45.155.205.233",
            "dst_ip": "10.0.0.5",
            "dst_port": 80,
            "protocol": "TCP",
            "features": ATTACK_FEATURES,
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["predicted_label"] in {
        "BENIGN",
        "DoS",
        "PortScan",
        "BruteForce",
        "WebAttack",
        "Botnet",
        "Infiltration",
        "ATTACK",
        "ANOMALY",
    }
    assert 0 <= body["confidence"] <= 1
    assert 0 <= body["anomaly_score"] <= 1
    assert body["severity"] in SEVERITIES
    assert 0 <= body["severity_score"] <= 100
    assert body["model_version_id"] is not None
    assert body["explanation"]["signals"]
    assert "caveats" in body["explanation"]


def test_predict_validates_port_range(client, analyst_headers):
    response = client.post(
        "/api/detection/predict",
        headers=analyst_headers,
        json={"dst_port": 70000, "features": ATTACK_FEATURES},
    )
    assert response.status_code == 422


def test_run_detection_processes_pending_records(client, analyst_headers):
    response = client.post(
        "/api/detection/run", headers=analyst_headers, json={"limit": 50}
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["processed"] >= 0
    assert body["model"]
    assert body["anomaly_model"]
    assert set(body["severity_counts"]) == SEVERITIES


def test_run_detection_is_analyst_only(client, viewer_headers):
    response = client.post(
        "/api/detection/run", headers=viewer_headers, json={"limit": 10}
    )
    assert response.status_code == 403


def test_run_detection_rejects_invalid_limit(client, analyst_headers):
    response = client.post(
        "/api/detection/run", headers=analyst_headers, json={"limit": 0}
    )
    assert response.status_code == 422


def test_detection_endpoints_require_authentication(client):
    assert client.get("/api/detection/results").status_code == 401
