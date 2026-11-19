from __future__ import annotations

import csv
import io
import json
import uuid

import pytest

pytestmark = pytest.mark.api

COLUMNS = [
    "flow_duration",
    "fwd_packet_count",
    "bwd_packet_count",
    "packet_count",
    "packet_length_mean",
    "packet_length_std",
    "min_packet_length",
    "max_packet_length",
    "flow_bytes_per_sec",
    "flow_packets_per_sec",
    "syn_count",
    "ack_count",
    "rst_count",
    "fin_count",
    "psh_count",
    "header_length",
    "active_mean",
    "idle_mean",
    "down_up_ratio",
    "destination_port",
    "protocol_num",
    "src_ip",
    "dst_ip",
    "src_port",
    "protocol",
    "label",
    "timestamp",
]

MAPPING = {
    "column_map": {column: column for column in COLUMNS if column not in {
        "src_ip", "dst_ip", "src_port", "protocol", "label", "timestamp"
    }},
    "metadata_map": {
        "src_ip": "src_ip",
        "dst_ip": "dst_ip",
        "src_port": "src_port",
        "protocol": "protocol",
        "timestamp": "timestamp",
    },
    "scales": {},
}


def _row(index: int, *, label: str = "BENIGN", src_ip: str = "203.0.113.10") -> dict:
    return {
        "flow_duration": f"{0.5 + index / 10:.4f}",
        "fwd_packet_count": 12 + index,
        "bwd_packet_count": 8 + index,
        "packet_count": 20 + (index * 2),
        "packet_length_mean": 540.5,
        "packet_length_std": 120.0,
        "min_packet_length": 64,
        "max_packet_length": 1200,
        "flow_bytes_per_sec": 12000.0 + index,
        "flow_packets_per_sec": 40.0 + index,
        "syn_count": 1,
        "ack_count": 15,
        "rst_count": 0,
        "fin_count": 1,
        "psh_count": 5,
        "header_length": 400,
        "active_mean": 0.2,
        "idle_mean": 0.1,
        "down_up_ratio": 0.7,
        "destination_port": 443,
        "protocol_num": 6,
        "src_ip": src_ip,
        "dst_ip": "10.0.0.5",
        "src_port": 51000 + index,
        "protocol": "TCP",
        "label": label,
        "timestamp": f"2026-02-{index + 1:02d} 10:00:00+00:00",
    }


def _csv_bytes(rows: list[dict]) -> bytes:
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=COLUMNS)
    writer.writeheader()
    writer.writerows(rows)
    return buffer.getvalue().encode("utf-8")


def _import_payload(content: bytes, *, analyze: bool = False) -> dict:
    return {
        "files": {"file": ("flows.csv", content, "text/csv")},
        "data": {
            "mapping": json.dumps(MAPPING),
            "label_column": "label",
            "analyze": "true" if analyze else "false",
        },
    }


def test_schema_lists_canonical_features(client, analyst_headers):
    response = client.get("/api/traffic/schema", headers=analyst_headers)
    assert response.status_code == 200
    body = response.json()
    assert "destination_port" in body["canonical_features"]
    assert body["required_minimum"] == 3
    assert ".csv" in body["allowed_extensions"]
    assert body["max_upload_mb"] > 0
    assert body["max_rows"] > 0


def test_import_csv_with_mapping_and_no_false_dst_port_warning(
    client, analyst_headers
):
    content = _csv_bytes([_row(i) for i in range(3)])
    response = client.post(
        "/api/traffic/import", headers=analyst_headers, **_import_payload(content)
    )
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["dataset"]["status"] == "completed"
    assert body["dataset"]["accepted_rows"] == 3
    assert body["dataset"]["rejected_rows"] == 0
    assert body["detected_columns"]["destination_port"] == "destination_port"
    assert body["analysis"]["metadata_columns"].get("destination_port") == "dst_port"
    assert "dst_port" in body["analysis"]["metadata_columns"].values()
    assert not any("dst_port" in warning for warning in body["warnings"])
    assert body["analysis"]["accepted"] == 3
    assert body["analysis"]["label_distribution"] == {"BENIGN": 3}


def test_duplicate_import_is_rejected(client, analyst_headers):
    content = _csv_bytes([_row(i, src_ip="203.0.113.20") for i in range(2)])
    first = client.post(
        "/api/traffic/import", headers=analyst_headers, **_import_payload(content)
    )
    assert first.status_code == 201, first.text
    second = client.post(
        "/api/traffic/import", headers=analyst_headers, **_import_payload(content)
    )
    assert second.status_code == 409
    assert "already imported" in second.json()["detail"].lower()


def test_import_rejects_unsupported_extension(client, analyst_headers):
    response = client.post(
        "/api/traffic/import",
        headers=analyst_headers,
        files={"file": ("flows.txt", b"a,b,c\n1,2,3\n", "text/plain")},
    )
    assert response.status_code == 422
    assert "unsupported file type" in response.json()["detail"].lower()


def test_import_rejects_empty_file(client, analyst_headers):
    response = client.post(
        "/api/traffic/import",
        headers=analyst_headers,
        files={"file": ("empty.csv", b"", "text/csv")},
    )
    assert response.status_code == 422
    assert "empty" in response.json()["detail"].lower()


def test_import_rejects_malformed_mapping_json(client, analyst_headers):
    content = _csv_bytes([_row(0)])
    response = client.post(
        "/api/traffic/import",
        headers=analyst_headers,
        files={"file": ("flows.csv", content, "text/csv")},
        data={"mapping": "{not-json"},
    )
    assert response.status_code == 422
    assert "invalid mapping json" in response.json()["detail"].lower()


def test_import_rejects_mapping_with_too_few_features(client, analyst_headers):
    # A CSV containing metadata only cannot satisfy the minimum feature count.
    content = (
        b"src_ip,dst_ip,protocol,timestamp\n"
        b"203.0.113.9,10.0.0.5,TCP,2026-02-01 10:00:00+00:00\n"
    )
    response = client.post(
        "/api/traffic/import",
        headers=analyst_headers,
        files={"file": ("metadata_only.csv", content, "text/csv")},
        data={
            "mapping": json.dumps(
                {
                    "column_map": {"destination_port": "destination_port"},
                    "metadata_map": {"src_ip": "src_ip", "dst_ip": "dst_ip"},
                    "scales": {},
                }
            )
        },
    )
    assert response.status_code == 422
    assert "enough network-flow features" in response.json()["detail"]


def test_import_with_analysis_runs_real_detection(client, analyst_headers):
    content = _csv_bytes(
        [_row(i, src_ip=f"198.51.100.{40 + i}") for i in range(4)]
    )
    response = client.post(
        "/api/traffic/import", headers=analyst_headers, **_import_payload(content, analyze=True)
    )
    assert response.status_code == 201, response.text
    body = response.json()
    detection = body["analysis"].get("detection")
    assert detection is not None
    assert detection["processed"] == 4
    assert detection["model"]
    assert detection["anomaly_model"]


def test_viewer_cannot_import(client, viewer_headers):
    content = _csv_bytes([_row(0)])
    response = client.post(
        "/api/traffic/import", headers=viewer_headers, **_import_payload(content)
    )
    assert response.status_code == 403


def test_records_pagination_filters_and_detail(client, analyst_headers):
    response = client.get(
        "/api/traffic/records?page=1&page_size=5", headers=analyst_headers
    )
    assert response.status_code == 200
    body = response.json()
    assert body["total"] >= 1
    assert len(body["items"]) <= 5
    assert body["pages"] >= 1
    first = body["items"][0]
    assert {"id", "timestamp", "protocol", "source"} <= set(first)

    protocol_filtered = client.get(
        "/api/traffic/records?protocol=TCP&page_size=5", headers=analyst_headers
    )
    assert protocol_filtered.status_code == 200
    assert all(item["protocol"] == "TCP" for item in protocol_filtered.json()["items"])

    search = client.get(
        f"/api/traffic/records?search={first['src_ip']}&page_size=5",
        headers=analyst_headers,
    )
    assert search.status_code == 200
    assert search.json()["total"] >= 1

    detail = client.get(
        f"/api/traffic/records/{first['id']}", headers=analyst_headers
    )
    assert detail.status_code == 200
    detail_body = detail.json()
    assert "features" in detail_body
    assert detail_body["features"]

    missing = client.get("/api/traffic/records/99999999", headers=analyst_headers)
    assert missing.status_code == 404


def test_traffic_stats_and_imports(client, analyst_headers):
    stats = client.get("/api/traffic/stats", headers=analyst_headers)
    assert stats.status_code == 200
    body = stats.json()
    assert body["total_records"] >= 1
    assert body["analyzed"] >= 1
    assert body["unprocessed"] >= 0

    imports = client.get("/api/traffic/imports", headers=analyst_headers)
    assert imports.status_code == 200
    rows = imports.json()
    assert rows
    assert all(row["status"] in {"completed", "processing", "failed"} for row in rows)


def test_records_require_authentication(client):
    assert client.get("/api/traffic/records").status_code == 401
