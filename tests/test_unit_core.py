from __future__ import annotations

import jwt
import numpy as np
import pandas as pd
import pytest

from app.core.errors import ValidationError
from app.core.security import (
    create_access_token,
    decode_access_token,
    hash_password,
    role_allows,
    verify_password,
)
from app.ml.features import (
    CANONICAL_FEATURES,
    normalize_column,
    normalize_label,
    prepare_dataframe,
    resolve_schema,
)
from app.services.analytics import resolve_range
from app.services.severity import (
    classify_severity,
    score_to_severity,
    severity_rank,
)
from app.utils.ip import is_private_ip, is_public_ip, is_valid_port, validate_ip

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# Authentication primitives
# ---------------------------------------------------------------------------


def test_password_hash_round_trip():
    hashed = hash_password("CorrectHorseBattery1!")
    assert hashed != "CorrectHorseBattery1!"
    assert verify_password("CorrectHorseBattery1!", hashed) is True
    assert verify_password("wrong-password", hashed) is False


def test_password_longer_than_bcrypt_limit_is_rejected():
    with pytest.raises(ValueError):
        hash_password("a" * 73)


def test_access_token_round_trip():
    token = create_access_token("analyst@test.local", "analyst")
    payload = decode_access_token(token)
    assert payload["sub"] == "analyst@test.local"
    assert payload["role"] == "analyst"
    assert payload["type"] == "access"
    assert payload["exp"] > payload["iat"]


def test_tampered_token_is_rejected():
    token = create_access_token("analyst@test.local", "analyst")
    with pytest.raises(jwt.PyJWTError):
        decode_access_token(token + "tampered")


@pytest.mark.parametrize(
    ("role", "minimum", "expected"),
    [
        ("viewer", "viewer", True),
        ("viewer", "analyst", False),
        ("analyst", "viewer", True),
        ("analyst", "analyst", True),
        ("analyst", "admin", False),
        ("admin", "admin", True),
        ("unknown", "viewer", False),
    ],
)
def test_role_matrix(role: str, minimum: str, expected: bool):
    assert role_allows(role, minimum) is expected


# ---------------------------------------------------------------------------
# Column normalization and label mapping
# ---------------------------------------------------------------------------


def test_normalize_column_handles_bom_punctuation_and_underscores():
    assert normalize_column("\ufeffTotal_Fwd Packets") == "total fwd packets"
    assert normalize_column("Flow  Bytes/s") == "flow bytes s"
    assert normalize_column(" Label ") == "label"


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("BENIGN", "BENIGN"),
        ("Normal", "BENIGN"),
        ("DoS Hulk", "DoS"),
        ("PortScan", "PortScan"),
        ("SSH-Patator", "BruteForce"),
        ("Web Attack - XSS", "WebAttack"),
        ("Bot", "Botnet"),
        ("Infiltration", "Infiltration"),
        ("0", "BENIGN"),
        ("1", "ATTACK"),
        ("some-new-label", "ATTACK"),
        (None, None),
        ("", None),
        ("nan", None),
    ],
)
def test_normalize_label(raw, expected):
    assert normalize_label(raw) == expected


# ---------------------------------------------------------------------------
# Schema resolution / dataframe preparation
# ---------------------------------------------------------------------------

CICIDS_COLUMNS = [
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Packet Length Mean",
    "Destination Port",
    "Source IP",
    "Destination IP",
    "Source Port",
    "Protocol",
    "Timestamp",
    "Label",
]


def test_resolve_schema_auto_detects_cicids_columns():
    column_map, scales, metadata = resolve_schema(CICIDS_COLUMNS)
    assert column_map["Flow Duration"] == "flow_duration"
    assert scales["Flow Duration"] == pytest.approx(1e-6)
    assert column_map["Destination Port"] == "destination_port"
    assert metadata["Destination Port"] == "dst_port"
    assert metadata["Source IP"] == "src_ip"
    assert metadata["Destination IP"] == "dst_ip"
    assert metadata["Source Port"] == "src_port"
    assert metadata["Protocol"] == "protocol"
    assert metadata["Timestamp"] == "timestamp"
    assert metadata["Label"] == "dataset_label"


def test_explicit_destination_port_mapping_also_registers_metadata():
    """Regression test: explicit destination_port mappings must not warn about dst_port."""
    frame = pd.DataFrame(
        [
            {
                "Flow Duration": 200_000,
                "Total Fwd Packets": 5,
                "Packet Count": 10,
                "Destination Port": 443,
                "Source IP": "8.8.8.8",
                "Destination IP": "10.0.0.5",
                "Timestamp": "2026-01-01 00:00:00",
                "Label": "BENIGN",
            }
        ]
    )
    mapping = {
        "column_map": {
            "Flow Duration": "flow_duration",
            "Total Fwd Packets": "fwd_packet_count",
            "Packet Count": "packet_count",
            "Destination Port": "destination_port",
        },
        "metadata_map": {},
        "scales": {"Flow Duration": 1e-6},
    }
    prepared = prepare_dataframe(frame, explicit_mapping=mapping, label_column="Label")
    assert prepared["metadata_map"]["Destination Port"] == "dst_port"
    assert "dst_port" not in prepared["missing_metadata"]
    assert prepared["records"][0]["dst_port"] == 443
    assert prepared["records"][0]["flow_duration"] == pytest.approx(0.2)


def test_prepare_dataframe_accepts_cicids_style_rows():
    frame = pd.DataFrame(
        {
            "Flow Duration": [1_000_000, 2_000_000],
            "Total Fwd Packets": [10, 20],
            "Total Backward Packets": [5, 10],
            "Total Length of Fwd Packets": [5000, 9000],
            "Total Length of Bwd Packets": [4000, 7000],
            "Flow Bytes/s": [9000, 8000],
            "Flow Packets/s": [15, 15],
            "Packet Length Mean": [600, 533],
            "Destination Port": [443, 80],
            "Source IP": ["8.8.8.8", "1.1.1.1"],
            "Destination IP": ["10.0.0.5", "10.0.0.10"],
            "Source Port": [51000, 52000],
            "Protocol": [6, 6],
            "Timestamp": ["2026-01-01 00:00:00", "2026-01-01 00:01:00"],
            "Label": ["BENIGN", "DoS Hulk"],
        }
    )
    prepared = prepare_dataframe(frame, label_column="Label")
    assert prepared["accepted"] == 2
    assert prepared["rejected"] == 0
    assert prepared["records"][0]["protocol"] == "TCP"
    assert prepared["records"][1]["dataset_label"] == "DoS"
    assert prepared["records"][1]["dst_port"] == 80
    assert prepared["label_distribution"] == {"BENIGN": 1, "DoS": 1}


def test_prepare_dataframe_rejects_rows_without_timestamps_or_features():
    frame = pd.DataFrame(
        {
            "Flow Duration": [1_000_000, 2_000_000],
            "Total Fwd Packets": [10, 20],
            "Packet Count": [15, 30],
            "Timestamp": ["2026-01-01 00:00:00", "not-a-timestamp"],
        }
    )
    prepared = prepare_dataframe(frame)
    assert prepared["accepted"] == 1
    assert prepared["rejected"] == 1


def test_prepare_dataframe_requires_three_features():
    frame = pd.DataFrame(
        {
            "Flow Duration": [1_000_000],
            "Timestamp": ["2026-01-01 00:00:00"],
        }
    )
    with pytest.raises(ValueError):
        prepare_dataframe(frame)


def test_canonical_feature_names_are_stable():
    assert len(CANONICAL_FEATURES) == 21
    assert "destination_port" in CANONICAL_FEATURES
    assert "protocol_num" in CANONICAL_FEATURES


# ---------------------------------------------------------------------------
# Severity heuristic
# ---------------------------------------------------------------------------


def test_score_to_severity_boundaries():
    assert score_to_severity(0) == "INFORMATIONAL"
    assert score_to_severity(24.9) == "INFORMATIONAL"
    assert score_to_severity(25) == "LOW"
    assert score_to_severity(45) == "MEDIUM"
    assert score_to_severity(65) == "HIGH"
    assert score_to_severity(85) == "CRITICAL"
    assert severity_rank("CRITICAL") > severity_rank("HIGH") > severity_rank("LOW")


def test_benign_informational_flow_scores_low():
    severity, score, explanation = classify_severity(
        predicted_label="BENIGN",
        confidence=0.99,
        attack_probability=0.01,
        is_anomaly=False,
        anomaly_score=0.0,
        features={"packet_count": 20, "flow_packets_per_sec": 5, "destination_port": 443},
        source_ip="10.0.0.5",
        source_is_public=False,
        recent_events=0,
    )
    assert severity == "INFORMATIONAL"
    assert score == 0.0
    assert explanation["signals"] == []
    assert any("not a calibrated" in item for item in explanation["caveats"])


def test_attack_flow_accumulates_explainable_signals():
    features = {
        "packet_count": 800,
        "flow_packets_per_sec": 1600,
        "syn_count": 760,
        "psh_count": 0,
        "rst_count": 0,
        "flow_duration": 0.5,
        "destination_port": 80,
    }
    severity, score, explanation = classify_severity(
        predicted_label="DoS",
        confidence=0.98,
        attack_probability=0.98,
        is_anomaly=True,
        anomaly_score=0.91,
        features=features,
        source_ip="45.155.205.233",
        source_is_public=True,
        recent_events=25,
    )
    assert severity in {"HIGH", "CRITICAL"}
    assert 0 <= score <= 100
    rules = {signal["rule"] for signal in explanation["signals"]}
    assert {"model_classification", "anomaly_detector", "syn_dominance"} <= rules
    assert explanation["model"]["predicted_label"] == "DoS"
    assert all(0 <= signal["weight"] <= 100 for signal in explanation["signals"])


def test_severity_never_exceeds_100():
    severity, score, _ = classify_severity(
        predicted_label="Infiltration",
        confidence=1.0,
        attack_probability=1.0,
        is_anomaly=True,
        anomaly_score=1.0,
        features={
            "packet_count": 100,
            "flow_packets_per_sec": 5000,
            "syn_count": 100,
            "psh_count": 50,
            "rst_count": 50,
            "flow_duration": 0.01,
            "destination_port": 22,
        },
        source_ip="45.155.205.233",
        source_is_public=True,
        recent_events=100,
    )
    assert severity == "CRITICAL"
    assert score == 100.0


# ---------------------------------------------------------------------------
# IP / range helpers
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "private"),
    [
        ("10.0.0.5", True),
        ("192.168.1.20", True),
        ("127.0.0.1", True),
        ("8.8.8.8", False),
        ("45.155.205.233", False),
        ("not-an-ip", True),
        (None, True),
    ],
)
def test_ip_privacy_classification(value, private):
    assert is_private_ip(value) is private
    assert is_public_ip(value) is (not private)


def test_validate_ip_and_port():
    assert validate_ip("8.8.8.8") == "8.8.8.8"
    assert validate_ip("not-an-ip") is None
    assert validate_ip(None) is None
    assert is_valid_port(443) is True
    assert is_valid_port(0) is True
    assert is_valid_port(65536) is False
    assert is_valid_port("nope") is False


def test_resolve_range_rejects_unknown_labels():
    assert resolve_range("7d")[0] == "7d"
    assert resolve_range("all")[1] is None
    with pytest.raises(ValidationError):
        resolve_range("90d")
    with pytest.raises(ValidationError):
        resolve_range("; drop table")


def test_feature_frame_handles_missing_values():
    from app.ml.features import feature_frame_from_records

    frame = feature_frame_from_records(
        [{"flow_duration": 1.0}, {"packet_count": np.nan}]
    )
    assert list(frame.columns) == CANONICAL_FEATURES
    assert frame.shape == (2, len(CANONICAL_FEATURES))
