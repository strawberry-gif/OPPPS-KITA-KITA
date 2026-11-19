from __future__ import annotations

import pytest

pytestmark = pytest.mark.api


def _ip_list(client, headers, query: str = "?page=1&page_size=10") -> dict:
    response = client.get(f"/api/ips{query}", headers=headers)
    assert response.status_code == 200, response.text
    return response.json()


def test_ip_list_and_filters(client, analyst_headers):
    body = _ip_list(client, analyst_headers)
    assert body["total"] >= 1
    first = body["items"][0]
    assert {
        "id",
        "ip_address",
        "direction",
        "classification",
        "risk_score",
        "event_count",
        "anomaly_count",
        "incident_count",
        "max_severity",
    } <= set(first)
    assert 0 <= first["risk_score"] <= 100
    assert body["items"] == sorted(
        body["items"], key=lambda row: row["risk_score"], reverse=True
    )

    min_risk = client.get(
        "/api/ips?min_risk=1&page_size=50", headers=analyst_headers
    )
    assert min_risk.status_code == 200
    assert all(row["risk_score"] >= 1 for row in min_risk.json()["items"])

    source_only = client.get(
        "/api/ips?direction=source&page_size=50", headers=analyst_headers
    )
    assert source_only.status_code == 200
    assert all(row["direction"] in {"source", "both"} for row in source_only.json()["items"])

    private_only = client.get(
        "/api/ips?private=true&page_size=50", headers=analyst_headers
    )
    assert private_only.status_code == 200
    assert all(row["is_private"] is True for row in private_only.json()["items"])

    invalid = client.get("/api/ips?min_risk=500", headers=analyst_headers)
    assert invalid.status_code == 422


def test_ip_detail_includes_context(client, analyst_headers):
    listing = _ip_list(client, analyst_headers)
    ip_id = listing["items"][0]["id"]
    detail = client.get(f"/api/ips/{ip_id}", headers=analyst_headers)
    assert detail.status_code == 200
    body = detail.json()
    assert body["id"] == ip_id
    assert "related_incidents" in body
    assert "recent_activity" in body
    assert "not a reputation score" in body["risk_model"].lower()

    missing = client.get("/api/ips/99999999", headers=analyst_headers)
    assert missing.status_code == 404


def test_analyst_can_annotate_ip(client, analyst_headers):
    listing = _ip_list(client, analyst_headers)
    row = next(
        item for item in listing["items"] if item["direction"] != "destination"
    )
    response = client.patch(
        f"/api/ips/{row['id']}",
        headers=analyst_headers,
        json={
            "notes": "Correlated with incident triage on the SOC runbook.",
            "classification": "SUSPICIOUS",
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["notes"].startswith("Correlated")
    assert body["classification"] == "SUSPICIOUS"


def test_ip_update_validates_classification(client, analyst_headers):
    listing = _ip_list(client, analyst_headers)
    ip_id = listing["items"][0]["id"]
    response = client.patch(
        f"/api/ips/{ip_id}",
        headers=analyst_headers,
        json={"classification": "BANNED"},
    )
    assert response.status_code == 422

    missing = client.patch(
        "/api/ips/99999999",
        headers=analyst_headers,
        json={"notes": "n/a"},
    )
    assert missing.status_code == 404


def test_viewer_cannot_update_ip(client, viewer_headers):
    listing = _ip_list(client, viewer_headers)
    ip_id = listing["items"][0]["id"]
    response = client.patch(
        f"/api/ips/{ip_id}",
        headers=viewer_headers,
        json={"notes": "should fail"},
    )
    assert response.status_code == 403


def test_ips_require_authentication(client):
    assert client.get("/api/ips").status_code == 401
