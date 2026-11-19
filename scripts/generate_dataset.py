"""Generate a documented synthetic network-flow dataset for training and demos.

The generator produces labelled flow records with signatures inspired by the
public CICIDS2017 feature schema. It is synthetic and is NOT a substitute for
evaluation on real production traffic.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
SAMPLE_DIR = ROOT / "datasets" / "sample"
PROCESSED_DIR = ROOT / "datasets" / "processed"

ATTACK_CATEGORIES = [
    "DoS",
    "PortScan",
    "BruteForce",
    "WebAttack",
    "Botnet",
    "Infiltration",
]

PUBLIC_CLIENTS = [
    "8.8.8.8",
    "1.1.1.1",
    "104.18.32.7",
    "151.101.1.140",
    "142.250.72.14",
]
BENIGN_DESTINATIONS = [
    "10.0.0.5",
    "10.0.0.10",
    "10.0.0.20",
    "192.168.1.20",
    "192.168.1.35",
    "172.16.0.12",
]
ATTACK_SOURCES = [
    "45.155.205.233",
    "185.220.101.47",
    "91.240.118.172",
    "193.32.162.89",
    "5.188.206.14",
    "103.145.13.10",
    "89.248.165.41",
]
VICTIM_HOSTS = ["10.0.0.5", "10.0.0.10", "192.168.1.20", "172.16.0.12"]

NORMAL_PORTS = [443, 443, 443, 80, 53, 123, 22, 8080, 8443, 3306]
SENSITIVE_PORTS = [21, 22, 23, 445, 3389, 3306, 5432, 8080]


def _ip(rng: np.random.Generator, pool: list[str]) -> str:
    return pool[int(rng.integers(0, len(pool)))]


def _normal_row(rng: np.random.Generator) -> dict:
    duration = float(np.clip(rng.lognormal(mean=-1.1, sigma=1.1), 0.001, 600))
    packets = int(np.clip(rng.lognormal(mean=2.2, sigma=0.8), 2, 400))
    fwd = max(1, int(packets * rng.uniform(0.35, 0.65)))
    bwd = max(0, packets - fwd)
    mean_len = float(np.clip(rng.normal(760, 260), 54, 1500))
    std_len = float(np.clip(rng.normal(180, 90), 0, 700))
    syn = int(rng.binomial(1, 0.55))
    ack = int(max(0, packets * rng.uniform(0.4, 0.9)))
    psh = int(max(0, packets * rng.uniform(0.05, 0.3)))
    return {
        "flow_duration": duration,
        "fwd_packet_count": fwd,
        "bwd_packet_count": bwd,
        "packet_count": packets,
        "packet_length_mean": mean_len,
        "packet_length_std": std_len,
        "min_packet_length": max(54, mean_len - std_len),
        "max_packet_length": mean_len + std_len * rng.uniform(1.0, 2.0),
        "flow_bytes_per_sec": packets * mean_len / duration,
        "flow_packets_per_sec": packets / duration,
        "syn_count": syn,
        "ack_count": ack,
        "rst_count": int(rng.binomial(1, 0.03)),
        "fin_count": int(rng.binomial(1, 0.08)),
        "psh_count": psh,
        "header_length": float(20 * fwd + 20 * bwd),
        "active_mean": float(duration * rng.uniform(0.1, 0.6)),
        "idle_mean": float(duration * rng.uniform(0.0, 0.3)),
        "down_up_ratio": (bwd / fwd) if fwd else 0.0,
        "destination_port": int(rng.choice(NORMAL_PORTS)),
        "protocol_num": 6 if rng.random() < 0.75 else (17 if rng.random() < 0.8 else 1),
        "src_ip": _ip(rng, PUBLIC_CLIENTS + BENIGN_DESTINATIONS[:4]),
        "dst_ip": _ip(rng, BENIGN_DESTINATIONS),
        "src_port": int(rng.integers(1024, 65535)),
        "protocol": "TCP",
        "label": "BENIGN",
    }


def _attack_row(rng: np.random.Generator, category: str, src: str, dst: str) -> dict:
    if category == "DoS":
        duration = float(rng.uniform(0.01, 2.5))
        packets = int(rng.integers(400, 6000))
        fwd = max(1, int(packets * rng.uniform(0.9, 0.99)))
        bwd = max(0, packets - fwd)
        mean_len = float(rng.uniform(60, 110))
        syn = int(packets * rng.uniform(0.7, 0.95))
        ack = int(packets * rng.uniform(0.0, 0.2))
        dst_port = 80
        psh = int(packets * rng.uniform(0.0, 0.05))
        proto = 6
    elif category == "PortScan":
        duration = float(rng.uniform(0.00005, 0.02))
        packets = int(rng.integers(1, 4))
        fwd, bwd = packets, int(rng.integers(0, 2))
        mean_len = float(rng.uniform(54, 74))
        syn = int(rng.integers(1, 3))
        ack = 0
        dst_port = int(rng.integers(1, 65535))
        psh = 0
        proto = 6
    elif category == "BruteForce":
        duration = float(rng.uniform(0.05, 3.0))
        packets = int(rng.integers(4, 28))
        fwd = int(packets * 0.6)
        bwd = packets - fwd
        mean_len = float(rng.uniform(90, 320))
        syn = int(rng.integers(1, 4))
        ack = int(packets * 0.5)
        dst_port = int(rng.choice([21, 22, 3389, 445, 5432]))
        psh = int(packets * 0.15)
        proto = 6
    elif category == "WebAttack":
        duration = float(rng.uniform(0.2, 12.0))
        packets = int(rng.integers(8, 140))
        fwd = int(packets * 0.55)
        bwd = packets - fwd
        mean_len = float(rng.uniform(620, 1800))
        syn = 1
        ack = int(packets * 0.6)
        dst_port = int(rng.choice([80, 443, 8080]))
        psh = int(packets * 0.4)
        proto = 6
    elif category == "Botnet":
        duration = float(rng.uniform(0.1, 2.0))
        packets = int(rng.integers(2, 10))
        fwd, bwd = 2, packets - 2
        mean_len = float(rng.uniform(110, 520))
        syn = 1
        ack = int(packets * 0.5)
        dst_port = int(rng.choice([443, 8080, 4444, 8443]))
        psh = int(packets * 0.2)
        proto = 6
    else:
        duration = float(rng.uniform(12, 420))
        packets = int(rng.integers(60, 900))
        fwd = int(packets * 0.45)
        bwd = packets - fwd
        mean_len = float(rng.uniform(520, 1500))
        syn = 1
        ack = int(packets * 0.7)
        dst_port = int(rng.choice([443, 445, 3389]))
        psh = int(packets * 0.25)
        proto = 6

    mean_len = float(max(54, mean_len))
    std_len = float(rng.uniform(0, mean_len * 0.4))
    return {
        "flow_duration": duration,
        "fwd_packet_count": fwd,
        "bwd_packet_count": bwd,
        "packet_count": packets,
        "packet_length_mean": mean_len,
        "packet_length_std": std_len,
        "min_packet_length": max(54, mean_len - std_len),
        "max_packet_length": mean_len + std_len * rng.uniform(1.0, 2.0),
        "flow_bytes_per_sec": packets * mean_len / duration,
        "flow_packets_per_sec": packets / duration,
        "syn_count": syn,
        "ack_count": ack,
        "rst_count": int(rng.binomial(1, 0.1)),
        "fin_count": int(rng.binomial(1, 0.2)),
        "psh_count": psh,
        "header_length": float(20 * packets),
        "active_mean": float(duration * rng.uniform(0.1, 0.8)),
        "idle_mean": float(duration * rng.uniform(0.0, 0.1)),
        "down_up_ratio": (bwd / fwd) if fwd else 0.0,
        "destination_port": dst_port,
        "protocol_num": proto,
        "src_ip": src,
        "dst_ip": dst,
        "src_port": int(rng.integers(1024, 65535)),
        "protocol": "TCP",
        "label": category,
    }


def generate(
    rows: int = 12000,
    days: int = 14,
    seed: int = 42,
    output: Path | None = None,
    raw_output: Path | None = None,
) -> Path:
    rng = np.random.default_rng(seed)
    now = datetime.now(timezone.utc).replace(microsecond=0)
    start = now - timedelta(days=days)

    attack_count = int(rows * 0.135)
    normal_count = rows - attack_count
    category_counts = {
        "DoS": int(attack_count * 0.27),
        "PortScan": int(attack_count * 0.23),
        "BruteForce": int(attack_count * 0.18),
        "WebAttack": int(attack_count * 0.14),
        "Botnet": int(attack_count * 0.11),
    }
    category_counts["Infiltration"] = attack_count - sum(category_counts.values())

    records: list[dict] = []
    for _ in range(normal_count):
        row = _normal_row(rng)
        row["timestamp"] = start + timedelta(
            seconds=float(rng.uniform(0, days * 86400))
        )
        records.append(row)

    for category, count in category_counts.items():
        for _ in range(count):
            src = _ip(rng, ATTACK_SOURCES)
            dst = _ip(rng, VICTIM_HOSTS)
            row = _attack_row(rng, category, src, dst)
            row["timestamp"] = start + timedelta(
                seconds=float(rng.uniform(0, days * 86400))
            )
            records.append(row)

    frame = pd.DataFrame(records)
    frame = frame.sort_values("timestamp").reset_index(drop=True)
    frame["timestamp"] = pd.to_datetime(frame["timestamp"], utc=True)
    output = output or SAMPLE_DIR / "synthetic_flows.csv"
    output.parent.mkdir(parents=True, exist_ok=True)
    frame.to_csv(output, index=False)

    raw_output = raw_output or SAMPLE_DIR / "cicids2017_style_sample.csv"
    raw = pd.DataFrame(
        {
            "Flow Duration": (frame["flow_duration"] * 1_000_000).round(0),
            "Total Fwd Packets": frame["fwd_packet_count"],
            "Total Backward Packets": frame["bwd_packet_count"],
            "Total Length of Fwd Packets": (
                frame["fwd_packet_count"] * frame["packet_length_mean"]
            ).round(0),
            "Total Length of Bwd Packets": (
                frame["bwd_packet_count"] * frame["packet_length_mean"]
            ).round(0),
            "Flow Bytes/s": frame["flow_bytes_per_sec"].round(2),
            "Flow Packets/s": frame["flow_packets_per_sec"].round(2),
            "Packet Length Mean": frame["packet_length_mean"].round(2),
            "Packet Length Std": frame["packet_length_std"].round(2),
            "Min Packet Length": frame["min_packet_length"].round(2),
            "Max Packet Length": frame["max_packet_length"].round(2),
            "SYN Flag Count": frame["syn_count"],
            "ACK Flag Count": frame["ack_count"],
            "RST Flag Count": frame["rst_count"],
            "FIN Flag Count": frame["fin_count"],
            "PSH Flag Count": frame["psh_count"],
            "Fwd Header Length": frame["header_length"],
            "Active Mean": frame["active_mean"].round(2),
            "Idle Mean": frame["idle_mean"].round(2),
            "Down/Up Ratio": frame["down_up_ratio"].round(3),
            "Destination Port": frame["destination_port"],
            "Protocol": frame["protocol_num"],
            "Source IP": frame["src_ip"],
            "Destination IP": frame["dst_ip"],
            "Source Port": frame["src_port"],
            "Timestamp": frame["timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S"),
            " Label": frame["label"],
        }
    )
    raw.to_csv(raw_output, index=False)

    train_path = PROCESSED_DIR / "train.csv"
    train_path.parent.mkdir(parents=True, exist_ok=True)
    frame.to_csv(train_path, index=False)
    return output


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rows", type=int, default=12000)
    parser.add_argument("--days", type=int, default=14)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--output", type=Path, default=None)
    parser.add_argument("--raw-output", type=Path, default=None)
    args = parser.parse_args()
    path = generate(args.rows, args.days, args.seed, args.output, args.raw_output)
    print(f"Wrote synthetic dataset: {path}")
    print(f"Wrote CICIDS-style sample: {args.raw_output or SAMPLE_DIR / 'cicids2017_style_sample.csv'}")
    print(f"Wrote processed training copy: {PROCESSED_DIR / 'train.csv'}")


if __name__ == "__main__":
    main()
