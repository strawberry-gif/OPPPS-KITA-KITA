from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest

from app.models.incident import SecurityIncident

pytestmark = pytest.mark.api


def _incident_list(client, headers, query: str = "?page=1&page_size=10") -> dict:
    response = client.get(f"/api/incidents{query}", headers=headers)
    assert response.status_code == 200, response.text
    return response.json()


def _create_incident(db, *, title: str, notes: str | None = None) -> SecurityIncident:
    incident = SecurityIncident(
        incident_code=f"INC-TEST-{uuid.uuid4().hex[:8].upper()}",
        title=title,
        description="Created by automated tests.",
        severity="HIGH",
        status="NEW",
        source_ip="198.51.100.250",
        destination_ip="10.0.0.5",
        investigation_notes=notes,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    db.add(incident)
    db.commit()
    db.refresh(incident)
    return incident


def test_incident_list_and_filters(client, analyst_headers):
    body = _incident_list(client, analyst_headers)
    assert body["total"] >= 1
    assert len(body["items"]) >= 1
    first = body["items"][0]
    assert {
        "id",
        "incident_code",
        "title",
        "severity",
        "status",
        "source_ip",
        "created_at",
    } <= set(first)

    status = first["status"]
    filtered = _incident_list(client, analyst_headers, f"?status={status}&page_size=10")
    assert all(item["status"] == status for item in filtered["items"])

    severity = first["severity"]
    filtered = _incident_list(
        client, analyst_headers, f"?severity={severity}&page_size=10"
    )
    assert all(item["severity"] == severity for item in filtered["items"])

    search = _incident_list(
        client, analyst_headers, f"?search={first['incident_code']}&page_size=10"
    )
    assert search["total"] >= 1

    invalid = client.get(
        "/api/incidents?status=WHATEVER", headers=analyst_headers
    )
    assert invalid.status_code == 422


def test_incident_detail_includes_related_activity(client, analyst_headers):
    listing = _incident_list(client, analyst_headers)
    incident_id = listing["items"][0]["id"]
    detail = client.get(f"/api/incidents/{incident_id}", headers=analyst_headers)
    assert detail.status_code == 200
    body = detail.json()
    assert body["id"] == incident_id
    assert "related_records" in body
    assert isinstance(body["related_records"], list)
    assert isinstance(body["activity_log"], list)

    missing = client.get("/api/incidents/99999999", headers=analyst_headers)
    assert missing.status_code == 404


def test_analyst_can_update_incident_notes_and_status(
    client, analyst_headers, user_ids
):
    listing = _incident_list(client, analyst_headers)
    incident = listing["items"][0]
    analyst_id = user_ids["analyst@test.local"]

    updated = client.patch(
        f"/api/incidents/{incident['id']}",
        headers=analyst_headers,
        json={
            "status": "INVESTIGATING",
            "investigation_notes": "Reviewed flow metadata; escalating for containment.",
            "assigned_to": analyst_id,
        },
    )
    assert updated.status_code == 200, updated.text
    body = updated.json()
    assert body["status"] == "INVESTIGATING"
    assert body["investigation_notes"].startswith("Reviewed")
    assert body["assigned_to"] == analyst_id
    assert body["assignee_name"] == "Pytest Analyst"
    assert body["resolved_at"] is None
    assert body["activity_log"]

    cleared = client.patch(
        f"/api/incidents/{incident['id']}",
        headers=analyst_headers,
        json={"assigned_to": 0},
    )
    assert cleared.status_code == 200
    assert cleared.json()["assigned_to"] is None


def test_closing_requires_notes_when_setting_enabled(
    client, admin_headers, analyst_headers, db_session
):
    incident = _create_incident(db_session, title="Notes enforcement test")
    enabled = client.put(
        "/api/settings",
        headers=admin_headers,
        json={"values": {"analyst_note_required_on_close": "true"}},
    )
    assert enabled.status_code == 200, enabled.text
    try:
        rejected = client.patch(
            f"/api/incidents/{incident.id}",
            headers=analyst_headers,
            json={"status": "RESOLVED"},
        )
        assert rejected.status_code == 422
        assert "notes are required" in rejected.json()["detail"].lower()

        accepted = client.patch(
            f"/api/incidents/{incident.id}",
            headers=analyst_headers,
            json={
                "status": "RESOLVED",
                "investigation_notes": "Confirmed with the asset owner; no compromise.",
            },
        )
        assert accepted.status_code == 200, accepted.text
        body = accepted.json()
        assert body["status"] == "RESOLVED"
        assert body["resolved_at"] is not None
    finally:
        client.put(
            "/api/settings",
            headers=admin_headers,
            json={"values": {"analyst_note_required_on_close": "false"}},
        )


def test_incident_update_validates_status_and_assignee(
    client, analyst_headers, db_session
):
    incident = _create_incident(db_session, title="Validation test")

    bad_status = client.patch(
        f"/api/incidents/{incident.id}",
        headers=analyst_headers,
        json={"status": "CLOSED"},
    )
    assert bad_status.status_code == 422

    bad_assignee = client.patch(
        f"/api/incidents/{incident.id}",
        headers=analyst_headers,
        json={"assigned_to": 99999999},
    )
    assert bad_assignee.status_code == 422
    assert "does not exist" in bad_assignee.json()["detail"].lower()

    missing = client.patch(
        "/api/incidents/99999999",
        headers=analyst_headers,
        json={"status": "RESOLVED"},
    )
    assert missing.status_code == 404


def test_viewer_cannot_update_incident(client, viewer_headers):
    listing = _incident_list(client, viewer_headers)
    incident_id = listing["items"][0]["id"]
    response = client.patch(
        f"/api/incidents/{incident_id}",
        headers=viewer_headers,
        json={"status": "RESOLVED"},
    )
    assert response.status_code == 403


def test_incidents_require_authentication(client):
    assert client.get("/api/incidents").status_code == 401
