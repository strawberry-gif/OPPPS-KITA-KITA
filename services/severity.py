"""Rule-assisted severity scoring.

The score is an explainable heuristic on a 0-100 scale. It is NOT a calibrated
attack probability. Every contributing signal is returned in the explanation.
"""

from __future__ import annotations

SEVERITY_ORDER = ["INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
SEVERITY_POINTS = {
    "INFORMATIONAL": 0,
    "LOW": 25,
    "MEDIUM": 50,
    "HIGH": 75,
    "CRITICAL": 100,
}
ATTACK_BASE = {
    "BENIGN": 0,
    "ATTACK": 42,
    "PortScan": 38,
    "BruteForce": 42,
    "Botnet": 40,
    "WebAttack": 45,
    "DoS": 50,
    "Infiltration": 52,
}
SENSITIVE_PORTS = {21, 22, 23, 445, 1433, 3306, 3389, 5432, 5900, 6379, 27017}


def score_to_severity(score: float) -> str:
    if score >= 85:
        return "CRITICAL"
    if score >= 65:
        return "HIGH"
    if score >= 45:
        return "MEDIUM"
    if score >= 25:
        return "LOW"
    return "INFORMATIONAL"


def severity_rank(value: str) -> int:
    try:
        return SEVERITY_ORDER.index(value)
    except ValueError:
        return 0


def classify_severity(
    *,
    predicted_label: str,
    confidence: float,
    attack_probability: float,
    is_anomaly: bool,
    anomaly_score: float,
    features: dict,
    source_ip: str | None,
    source_is_public: bool,
    recent_events: int,
) -> tuple[str, float, dict]:
    signals: list[dict] = []
    label = predicted_label if predicted_label in ATTACK_BASE else "ATTACK"
    base = ATTACK_BASE.get(label, 0)
    score = 0.0

    if base > 0:
        weighted = base * (0.6 + 0.4 * max(0.0, min(1.0, attack_probability)))
        score += weighted
        signals.append(
            {
                "rule": "model_classification",
                "weight": round(weighted, 1),
                "detail": f"Classifier predicted {predicted_label} with attack probability {attack_probability:.2f}.",
            }
        )

    if is_anomaly:
        anomaly_points = 8.0 + 12.0 * max(0.0, min(1.0, anomaly_score))
        score += anomaly_points
        signals.append(
            {
                "rule": "anomaly_detector",
                "weight": round(anomaly_points, 1),
                "detail": f"Isolation Forest flagged a statistical outlier (score {anomaly_score:.2f}).",
            }
        )

    packets = max(float(features.get("packet_count", 0) or 0), 1.0)
    pps = float(features.get("flow_packets_per_sec", 0) or 0)
    syn = float(features.get("syn_count", 0) or 0)
    psh = float(features.get("psh_count", 0) or 0)
    rst = float(features.get("rst_count", 0) or 0)
    duration = float(features.get("flow_duration", 0) or 0)
    dst_port = int(float(features.get("destination_port", 0) or 0))

    if syn >= 20 and syn / packets >= 0.5:
        score += 14
        signals.append(
            {
                "rule": "syn_dominance",
                "weight": 14,
                "detail": f"{int(syn)} SYN flags across {int(packets)} packets is consistent with connection-flood behaviour.",
            }
        )
    if pps >= 500:
        score += 12
        signals.append(
            {
                "rule": "very_high_packet_rate",
                "weight": 12,
                "detail": f"Flow packet rate of {pps:.0f} pps exceeds the high-rate threshold (500 pps).",
            }
        )
    elif pps >= 100:
        score += 6
        signals.append(
            {
                "rule": "elevated_packet_rate",
                "weight": 6,
                "detail": f"Flow packet rate of {pps:.0f} pps exceeds 100 pps.",
            }
        )
    if packets <= 3 and duration < 0.1 and dst_port:
        score += 10
        signals.append(
            {
                "rule": "probe_signature",
                "weight": 10,
                "detail": "Single/few-packet short-lived flow toward a destination port resembles probe traffic.",
            }
        )
    if dst_port in SENSITIVE_PORTS and label != "BENIGN":
        score += 6
        signals.append(
            {
                "rule": "sensitive_port",
                "weight": 6,
                "detail": f"Destination port {dst_port} is a commonly targeted service port.",
            }
        )
    if source_is_public and label != "BENIGN":
        score += 4
        signals.append(
            {
                "rule": "external_source",
                "weight": 4,
                "detail": "Non-benign classification originates from a public (external) address.",
            }
        )
    if psh / packets >= 0.3 and packets >= 8:
        score += 5
        signals.append(
            {
                "rule": "payload_push_ratio",
                "weight": 5,
                "detail": "High PSH-to-packet ratio suggests repeated payload transfer.",
            }
        )
    if rst / packets >= 0.3 and packets >= 10:
        score += 5
        signals.append(
            {
                "rule": "reset_ratio",
                "weight": 5,
                "detail": "High RST ratio may indicate failed connections or scanning.",
            }
        )
    if recent_events >= 50:
        score += 20
        signals.append(
            {
                "rule": "repeat_activity",
                "weight": 20,
                "detail": f"{recent_events} related suspicious events from this source in the recent window.",
            }
        )
    elif recent_events >= 20:
        score += 16
        signals.append(
            {
                "rule": "repeat_activity",
                "weight": 16,
                "detail": f"{recent_events} related suspicious events from this source in the recent window.",
            }
        )
    elif recent_events >= 5:
        score += 8
        signals.append(
            {
                "rule": "repeat_activity",
                "weight": 8,
                "detail": f"{recent_events} related suspicious events from this source in the recent window.",
            }
        )

    if predicted_label == "BENIGN" and anomaly_score >= 0.7:
        score += 5
        signals.append(
            {
                "rule": "unexplained_anomaly",
                "weight": 5,
                "detail": "The flow is statistically unusual even though the classifier did not predict an attack class.",
            }
        )

    score = round(max(0.0, min(100.0, score)), 1)
    severity = score_to_severity(score)
    explanation = {
        "summary": (
            f"{severity.title()} severity from a heuristic score of {score}/100. "
            "The score combines model output, anomaly evidence, traffic rules and "
            "recent source activity."
        ),
        "signals": signals,
        "model": {
            "predicted_label": predicted_label,
            "confidence": round(float(confidence), 4),
            "attack_probability": round(float(attack_probability), 4),
            "is_anomaly": bool(is_anomaly),
            "anomaly_score": round(float(anomaly_score), 4),
        },
        "caveats": [
            "An anomaly is not proof of an attack.",
            "Severity is an operational triage heuristic, not a calibrated probability.",
            "Dataset ground-truth labels, when present, are stored separately from model predictions.",
        ],
    }
    return severity, score, explanation
