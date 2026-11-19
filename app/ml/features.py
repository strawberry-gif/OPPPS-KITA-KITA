import ipaddress
import math
import re
from datetime import datetime, timezone

import numpy as np
import pandas as pd

CANONICAL_FEATURES: list[str] = [
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
]

FEATURE_LABELS = {
    "flow_duration": "Flow duration (s)",
    "fwd_packet_count": "Forward packets",
    "bwd_packet_count": "Backward packets",
    "packet_count": "Total packets",
    "packet_length_mean": "Mean packet length (B)",
    "packet_length_std": "Packet length std. dev.",
    "min_packet_length": "Minimum packet length",
    "max_packet_length": "Maximum packet length",
    "flow_bytes_per_sec": "Flow bytes per second",
    "flow_packets_per_sec": "Flow packets per second",
    "syn_count": "SYN flags",
    "ack_count": "ACK flags",
    "rst_count": "RST flags",
    "fin_count": "FIN flags",
    "psh_count": "PSH flags",
    "header_length": "Header length",
    "active_mean": "Active time mean",
    "idle_mean": "Idle time mean",
    "down_up_ratio": "Down/up ratio",
    "destination_port": "Destination port",
    "protocol_num": "Protocol number",
}

METADATA_FIELDS = [
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "protocol",
    "timestamp",
    "dataset_label",
    "tcp_flags",
]

ALIASES: dict[str, list[str]] = {
    "flow_duration": [
        "flow duration",
        "flow_duration",
        "duration",
        "flow time",
        "connection duration",
    ],
    "fwd_packet_count": [
        "total fwd packets",
        "fwd packet count",
        "fwd packets",
        "forward packets",
        "subflow fwd packets",
        "src packet count",
    ],
    "bwd_packet_count": [
        "total backward packets",
        "total bwd packets",
        "bwd packet count",
        "bwd packets",
        "backward packets",
        "subflow bwd packets",
        "dst packet count",
    ],
    "packet_count": [
        "packet count",
        "total packets",
        "flow packets",
        "packets",
        "count",
    ],
    "packet_length_mean": [
        "packet length mean",
        "average packet size",
        "avg packet size",
        "mean packet length",
        "fwd packet length mean",
    ],
    "packet_length_std": [
        "packet length std",
        "packet length standard deviation",
        "fwd packet length std",
    ],
    "min_packet_length": ["min packet length", "minimum packet length"],
    "max_packet_length": ["max packet length", "maximum packet length"],
    "flow_bytes_per_sec": [
        "flow bytes s",
        "flow bytes/sec",
        "flow bytes per second",
        "bytes per second",
        "byte rate",
    ],
    "flow_packets_per_sec": [
        "flow packets s",
        "flow packets/sec",
        "flow packets per second",
        "packets per second",
        "packet rate",
    ],
    "syn_count": ["syn flag count", "syn count", "syn flags"],
    "ack_count": ["ack flag count", "ack count", "ack flags"],
    "rst_count": ["rst flag count", "rst count", "rst flags"],
    "fin_count": ["fin flag count", "fin count", "fin flags"],
    "psh_count": ["psh flag count", "psh count", "psh flags"],
    "header_length": [
        "fwd header length",
        "header length",
        "fwd header length 1",
        "bwd header length",
    ],
    "active_mean": ["active mean", "active time mean", "active avg"],
    "idle_mean": ["idle mean", "idle time mean", "idle avg"],
    "down_up_ratio": ["down up ratio", "down/up ratio", "download upload ratio"],
    "destination_port": ["destination port", "dst port", "dest port", "dport"],
}

INTERNAL_ALIASES: dict[str, list[str]] = {
    "fwd_bytes": [
        "total length of fwd packets",
        "fwd bytes",
        "forward bytes",
        "src bytes",
        "sbytes",
    ],
    "bwd_bytes": [
        "total length of bwd packets",
        "bwd bytes",
        "backward bytes",
        "dst bytes",
        "dbytes",
    ],
    "total_bytes": ["total bytes", "flow bytes", "bytes"],
    "source_port": ["source port", "src port", "sport"],
}

METADATA_ALIASES: dict[str, list[str]] = {
    "src_ip": ["source ip", "src ip", "srcip", "source address", "srcaddr"],
    "dst_ip": ["destination ip", "dst ip", "dstip", "destination address", "dstaddr"],
    "src_port": ["source port", "src port", "sport"],
    "dst_port": ["destination port", "dst port", "dport"],
    "protocol": ["protocol", "proto", "protocol type"],
    "timestamp": ["timestamp", "time", "date", "flow start time", "start time", "datetime"],
    "dataset_label": ["label", "class", "attack", "attack type", "category", "target"],
    "tcp_flags": ["tcp flags", "tcp flag", "flags"],
}

PROTOCOL_MAP = {
    "6": "TCP",
    "tcp": "TCP",
    "17": "UDP",
    "udp": "UDP",
    "1": "ICMP",
    "icmp": "ICMP",
    "icmpv6": "ICMP",
    "58": "ICMP",
    "0": "HOPOPT",
    "2": "IGMP",
    "47": "GRE",
    "50": "ESP",
    "51": "AH",
    "132": "SCTP",
}

LABEL_CATEGORY_MAP = {
    "benign": "BENIGN",
    "normal": "BENIGN",
    "background": "BENIGN",
    "dos hulk": "DoS",
    "ddos": "DoS",
    "dos goldeneye": "DoS",
    "dos slowloris": "DoS",
    "dos slowhttptest": "DoS",
    "heartbleed": "DoS",
    "dos": "DoS",
    "portscan": "PortScan",
    "port scan": "PortScan",
    "ftp-patator": "BruteForce",
    "ssh-patator": "BruteForce",
    "brute force": "BruteForce",
    "bruteforce": "BruteForce",
    "web attack  brute force": "WebAttack",
    "web attack  xss": "WebAttack",
    "web attack  sql injection": "WebAttack",
    "web attack": "WebAttack",
    "webattack": "WebAttack",
    "bot": "Botnet",
    "botnet": "Botnet",
    "infiltration": "Infiltration",
    "attack": "ATTACK",
    "malicious": "ATTACK",
}

ESSENTIAL_FEATURES = {
    "flow_duration",
    "packet_count",
    "flow_bytes_per_sec",
    "flow_packets_per_sec",
    "packet_length_mean",
    "total_bytes",
}

DURATION_ALIASES = {"flow duration", "duration", "flow time", "connection duration"}


def normalize_column(name: str) -> str:
    text = str(name).replace("\ufeff", "").strip().lower()
    text = text.replace("_", " ")
    text = re.sub(r"[^a-z0-9 ]+", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


# Normalize the label dictionary keys the same way incoming values are
# normalized, so aliases such as "SSH-Patator" still match after punctuation
# and whitespace cleanup.
LABEL_CATEGORY_LOOKUP: dict[str, str] = {
    normalize_column(pattern): category
    for pattern, category in LABEL_CATEGORY_MAP.items()
}


def _build_lookup() -> dict[str, str]:
    lookup: dict[str, str] = {}
    for canonical, aliases in {**ALIASES, **INTERNAL_ALIASES}.items():
        for alias in aliases:
            lookup[normalize_column(alias)] = canonical
    return lookup


COLUMN_LOOKUP = _build_lookup()

METADATA_LOOKUP: dict[str, str] = {}
for field, aliases in METADATA_ALIASES.items():
    for alias in aliases:
        METADATA_LOOKUP[normalize_column(alias)] = field




def normalize_label(value: object) -> str | None:
    if value is None or (isinstance(value, float) and math.isnan(value)):
        return None
    text = str(value).strip()
    if not text or text.lower() in {"nan", "none", "null"}:
        return None
    key = normalize_column(text)
    if key in LABEL_CATEGORY_LOOKUP:
        return LABEL_CATEGORY_LOOKUP[key]
    for pattern, category in LABEL_CATEGORY_LOOKUP.items():
        if pattern and pattern in key:
            return category
    if key in {"0", "false"}:
        return "BENIGN"
    return "ATTACK"


def resolve_schema(
    columns: list[str], explicit_mapping: dict | None = None
) -> tuple[dict[str, str], dict[str, float], dict[str, str]]:
    explicit = explicit_mapping or {}
    explicit_columns = {
        str(k): str(v) for k, v in (explicit.get("column_map") or {}).items()
    }
    explicit_metadata = {
        str(k): str(v) for k, v in (explicit.get("metadata_map") or {}).items()
    }
    scales = {str(k): float(v) for k, v in (explicit.get("scales") or {}).items()}

    column_map: dict[str, str] = {}
    metadata_map: dict[str, str] = {}
    by_normalized = {normalize_column(c): c for c in columns}

    for source, target in explicit_columns.items():
        if source in columns and target in CANONICAL_FEATURES + list(INTERNAL_ALIASES):
            column_map[source] = target
        elif normalize_column(source) in by_normalized:
            original = by_normalized[normalize_column(source)]
            if target in CANONICAL_FEATURES + list(INTERNAL_ALIASES):
                column_map[original] = target
    for source, target in explicit_metadata.items():
        if source in columns and target in METADATA_FIELDS:
            metadata_map[source] = target

    for column in columns:
        norm = normalize_column(column)
        if column in column_map:
            # A feature explicitly mapped to destination_port/source_port also
            # supplies the matching metadata field; without this the importer
            # would falsely warn that the port column was never detected.
            canonical = column_map[column]
            if canonical == "destination_port":
                metadata_map.setdefault(column, "dst_port")
            elif canonical == "source_port":
                metadata_map.setdefault(column, "src_port")
            continue
        if column in metadata_map:
            continue
        if norm in METADATA_LOOKUP:
            field = METADATA_LOOKUP[norm]
            if field in METADATA_FIELDS:
                metadata_map[column] = field
                if field == "dst_port":
                    column_map[column] = "destination_port"
            continue
        canonical = COLUMN_LOOKUP.get(norm)
        if canonical:
            column_map[column] = canonical
            if canonical == "flow_duration" and column.strip().lower() == "flow duration":
                scales.setdefault(column, 1e-6)

    return column_map, scales, metadata_map


def _numeric(series: pd.Series, scale: float = 1.0) -> pd.Series:
    values = pd.to_numeric(series, errors="coerce")
    if scale != 1.0:
        values = values * scale
    return values.replace([np.inf, -np.inf], np.nan)


def build_feature_frame(
    df: pd.DataFrame, column_map: dict[str, str], scales: dict[str, float]
) -> pd.DataFrame:
    out = pd.DataFrame(index=df.index)
    total_bytes = pd.Series(np.nan, index=df.index, dtype="float64")

    for source, canonical in column_map.items():
        values = _numeric(df[source], scales.get(source, 1.0))
        if canonical in ("fwd_bytes", "bwd_bytes", "total_bytes"):
            total_bytes = total_bytes.fillna(0) + values.fillna(0)
            continue
        if canonical in INTERNAL_ALIASES:
            continue
        if canonical in out.columns:
            out[canonical] = out[canonical].fillna(values)
        else:
            out[canonical] = values

    for feature in CANONICAL_FEATURES:
        if feature not in out.columns:
            out[feature] = np.nan

    for feature in ("fwd_packet_count", "bwd_packet_count"):
        out[feature] = out[feature].fillna(0).clip(lower=0)

    derived_count = out["fwd_packet_count"] + out["bwd_packet_count"]
    out["packet_count"] = out["packet_count"].fillna(derived_count)
    out.loc[out["packet_count"] <= 0, "packet_count"] = np.nan

    out["flow_duration"] = out["flow_duration"].clip(lower=0)
    duration = out["flow_duration"].replace(0, np.nan)

    if total_bytes.notna().any():
        out["packet_length_mean"] = out["packet_length_mean"].fillna(
            total_bytes / out["packet_count"]
        )

    derived_bps = total_bytes / duration
    out["flow_bytes_per_sec"] = out["flow_bytes_per_sec"].fillna(derived_bps)
    derived_pps = out["packet_count"] / duration
    out["flow_packets_per_sec"] = out["flow_packets_per_sec"].fillna(derived_pps)

    fallback_length = out["packet_length_mean"]
    out["packet_length_std"] = out["packet_length_std"].fillna(0)
    out["min_packet_length"] = out["min_packet_length"].fillna(fallback_length)
    out["max_packet_length"] = out["max_packet_length"].fillna(fallback_length)

    for flag in ("syn_count", "ack_count", "rst_count", "fin_count", "psh_count"):
        out[flag] = out[flag].fillna(0).clip(lower=0)
    out["header_length"] = out["header_length"].fillna(0).clip(lower=0)
    out["active_mean"] = out["active_mean"].fillna(0).clip(lower=0)
    out["idle_mean"] = out["idle_mean"].fillna(0).clip(lower=0)

    derived_ratio = out["bwd_packet_count"] / out["fwd_packet_count"].replace(0, np.nan)
    out["down_up_ratio"] = out["down_up_ratio"].fillna(derived_ratio).fillna(0)

    out["destination_port"] = out["destination_port"].clip(0, 65535)
    out["protocol_num"] = out["protocol_num"]

    for feature in CANONICAL_FEATURES:
        out[feature] = pd.to_numeric(out[feature], errors="coerce").replace(
            [np.inf, -np.inf], np.nan
        )
    return out[CANONICAL_FEATURES]


def _parse_timestamp(value: object) -> datetime | None:
    if value is None:
        return None
    try:
        stamp = pd.to_datetime(value, errors="coerce", utc=True)
    except (ValueError, TypeError):
        return None
    if pd.isna(stamp):
        return None
    return stamp.to_pydatetime()


def _safe_protocol(value: object) -> str:
    if value is None or (isinstance(value, float) and math.isnan(value)):
        return "OTHER"
    text = str(value).strip().lower()
    if text in {"", "nan", "none"}:
        return "OTHER"
    if text.endswith(".0"):
        text = text[:-2]
    return PROTOCOL_MAP.get(text, text.upper()[:16])


def _protocol_number(protocol: str) -> float:
    reverse = {"TCP": 6, "UDP": 17, "ICMP": 1, "GRE": 47}
    return float(reverse.get(protocol, 0))


def _safe_port(value: object) -> int | None:
    if value is None or (isinstance(value, float) and math.isnan(value)):
        return None
    try:
        port = int(float(value))
    except (TypeError, ValueError):
        return None
    return port if 0 <= port <= 65535 else None


def _safe_ip(value: object) -> str | None:
    if value is None or (isinstance(value, float) and math.isnan(value)):
        return None
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError:
        return None


def prepare_dataframe(
    df: pd.DataFrame,
    explicit_mapping: dict | None = None,
    label_column: str | None = None,
    now: datetime | None = None,
) -> dict:
    columns = [str(c) for c in df.columns]
    column_map, scales, metadata_map = resolve_schema(columns, explicit_mapping)
    mapped_features = {
        source: target
        for source, target in column_map.items()
        if target in CANONICAL_FEATURES
    }
    if len(mapped_features) < 3:
        raise ValueError(
            "Could not map enough network-flow features. Provide a mapping with at "
            "least three canonical fields (see /api/traffic/schema)."
        )

    missing_metadata = [field for field in METADATA_FIELDS if field not in metadata_map.values()]
    features = build_feature_frame(df, column_map, scales)

    if label_column:
        if label_column not in df.columns:
            raise ValueError(f"Label column '{label_column}' was not found")
        metadata_map[label_column] = "dataset_label"
    elif "dataset_label" not in metadata_map.values():
        norm_cols = {normalize_column(c): c for c in columns}
        for alias in ("label", "class", "attack", "attack type", "category"):
            if alias in norm_cols:
                metadata_map[norm_cols[alias]] = "dataset_label"
                break

    timestamp_col = next(
        (src for src, target in metadata_map.items() if target == "timestamp"), None
    )
    protocol_col = next(
        (src for src, target in metadata_map.items() if target == "protocol"), None
    )
    label_source = next(
        (src for src, target in metadata_map.items() if target == "dataset_label"), None
    )

    if timestamp_col:
        timestamps = df[timestamp_col].map(_parse_timestamp)
    else:
        base = now or datetime.now(timezone.utc)
        timestamps = pd.Series(
            [base] * len(df), index=df.index, dtype="object"
        )

    protocols = (
        df[protocol_col].map(_safe_protocol) if protocol_col else pd.Series("TCP", index=df.index)
    )
    features = features.copy()
    features["protocol_num"] = features["protocol_num"].fillna(
        protocols.map(_protocol_number)
    )

    def source_col(field: str) -> str | None:
        return next((src for src, target in metadata_map.items() if target == field), None)

    metadata_df = pd.DataFrame(
        {
            "src_ip": df[source_col("src_ip")].map(_safe_ip)
            if source_col("src_ip")
            else None,
            "dst_ip": df[source_col("dst_ip")].map(_safe_ip)
            if source_col("dst_ip")
            else None,
            "src_port": df[source_col("src_port")].map(_safe_port)
            if source_col("src_port")
            else None,
            "dst_port": df[source_col("dst_port")].map(_safe_port)
            if source_col("dst_port")
            else None,
            "tcp_flags": df[source_col("tcp_flags")].astype(str)
            if source_col("tcp_flags")
            else None,
        },
        index=df.index,
    )
    metadata_df["timestamp"] = timestamps
    metadata_df["protocol"] = protocols

    if label_source:
        metadata_df["dataset_label"] = df[label_source].map(normalize_label)
    else:
        metadata_df["dataset_label"] = None

    valid_feature_rows = features.notna().any(axis=1)
    essential_present = features[
        [c for c in ESSENTIAL_FEATURES if c in features.columns]
    ].notna().any(axis=1)
    valid = valid_feature_rows & essential_present
    valid &= pd.Series(timestamps, index=df.index).notna()

    rejected = int((~valid).sum())
    features = features.loc[valid]
    metadata_df = metadata_df.loc[valid]

    medians = features.median(numeric_only=True).fillna(0)
    filled = features.fillna(medians).clip(lower=0)

    def optional_int(value: object) -> int | None:
        return None if value is None or pd.isna(value) else int(value)

    def optional_str(value: object) -> str | None:
        return None if value is None or pd.isna(value) else str(value)

    def as_datetime(value: object) -> datetime:
        if hasattr(value, "to_pydatetime"):
            return value.to_pydatetime()
        return value  # type: ignore[return-value]

    records: list[dict] = []
    for idx in range(len(filled)):
        row = filled.iloc[idx]
        meta = metadata_df.iloc[idx]
        feature_dict = {
            feature: round(float(row[feature]), 6)
            for feature in CANONICAL_FEATURES
            if not pd.isna(row[feature])
        }
        records.append(
            {
                "timestamp": as_datetime(meta["timestamp"]),
                "src_ip": optional_str(meta["src_ip"]),
                "dst_ip": optional_str(meta["dst_ip"]),
                "src_port": optional_int(meta["src_port"]),
                "dst_port": optional_int(meta["dst_port"]),
                "protocol": optional_str(meta["protocol"]) or "OTHER",
                "packet_count": float(feature_dict.get("packet_count", 0.0)),
                "flow_duration": float(feature_dict.get("flow_duration", 0.0)),
                "packet_length": float(feature_dict.get("packet_length_mean", 0.0)),
                "flow_bytes_per_sec": float(
                    feature_dict.get("flow_bytes_per_sec", 0.0)
                ),
                "flow_packets_per_sec": float(
                    feature_dict.get("flow_packets_per_sec", 0.0)
                ),
                "tcp_flags": optional_str(meta["tcp_flags"]),
                "dataset_label": optional_str(meta["dataset_label"]),
                "features": feature_dict,
            }
        )

    return {
        "records": records,
        "rejected": rejected,
        "source_rows": len(df),
        "accepted": len(records),
        "column_map": mapped_features,
        "metadata_map": metadata_map,
        "scale_map": {k: v for k, v in scales.items() if k in column_map},
        "missing_metadata": [
            field
            for field in missing_metadata
            if field not in {"dataset_label", "tcp_flags"}
        ],
        "label_column": label_source,
        "label_distribution": metadata_df["dataset_label"]
        .dropna()
        .value_counts()
        .to_dict(),
        "protocol_distribution": metadata_df["protocol"].value_counts().to_dict(),
        "median_features": {k: round(float(v), 6) for k, v in medians.items()},
    }


def features_from_mapping(values: dict[str, float]) -> pd.DataFrame:
    row = {feature: np.nan for feature in CANONICAL_FEATURES}
    for key, value in values.items():
        if key in row:
            try:
                row[key] = float(value)
            except (TypeError, ValueError):
                row[key] = np.nan
    return pd.DataFrame([row])[CANONICAL_FEATURES]


def feature_frame_from_records(features: list[dict]) -> pd.DataFrame:
    rows = []
    for item in features:
        row = {feature: item.get(feature, np.nan) for feature in CANONICAL_FEATURES}
        rows.append(row)
    frame = pd.DataFrame(rows)
    if frame.empty:
        return pd.DataFrame(columns=CANONICAL_FEATURES)
    return frame[CANONICAL_FEATURES].apply(pd.to_numeric, errors="coerce")
