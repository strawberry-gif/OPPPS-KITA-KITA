"""Optional passive packet capture.

Requires Npcap (Windows) and elevated privileges. Capture is metadata-only:
payloads are never stored. The application remains fully usable without it.
"""

from __future__ import annotations

import math
import threading
import time
from collections import defaultdict
from datetime import datetime, timezone

from app.core.config import settings
from app.core.errors import ConflictError, ServiceUnavailableError, ValidationError
from app.database.session import SessionLocal
from app.models.traffic import TrafficRecord

try:
    from scapy.all import ICMP, IP, TCP, UDP, AsyncSniffer, conf, get_if_list

    SCAPY_AVAILABLE = True
    SCAPY_ERROR: str | None = None
except Exception as exc:  # pragma: no cover - depends on host installation
    SCAPY_AVAILABLE = False
    SCAPY_ERROR = str(exc)
    AsyncSniffer = None  # type: ignore[assignment]

PROTOCOL_NUMBERS = {"TCP": 6, "UDP": 17, "ICMP": 1}


def list_interfaces() -> list[dict]:
    if not SCAPY_AVAILABLE:
        return []
    interfaces: list[dict] = []
    try:
        for name, value in conf.ifaces.items():
            addresses = getattr(value, "ips", None) or []
            interfaces.append(
                {
                    "name": getattr(value, "name", name),
                    "description": getattr(value, "description", "") or "",
                    "addresses": list(addresses),
                }
            )
    except Exception:
        for name in get_if_list():
            interfaces.append({"name": name, "description": "", "addresses": []})
    return interfaces


class LiveCaptureManager:
    def __init__(self) -> None:
        self._sniffer = None
        self._flush_thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._lock = threading.RLock()
        self._buffer: dict[tuple, dict] = {}
        self._running = False
        self._started_at: datetime | None = None
        self._stopped_at: datetime | None = None
        self._interface: str | None = None
        self._bpf_filter: str | None = None
        self._packets_seen = 0
        self._records_created = 0
        self._flows_flushed = 0
        self._last_flush_at: datetime | None = None
        self._last_error: str | None = None

    @property
    def running(self) -> bool:
        return self._running

    def status(self) -> dict:
        return {
            "available": bool(SCAPY_AVAILABLE and settings.live_capture_enabled),
            "scapy_available": SCAPY_AVAILABLE,
            "scapy_error": SCAPY_ERROR,
            "running": self._running,
            "interface": self._interface,
            "bpf_filter": self._bpf_filter,
            "started_at": self._started_at,
            "stopped_at": self._stopped_at,
            "packets_seen": self._packets_seen,
            "flows_buffered": len(self._buffer),
            "flows_flushed": self._flows_flushed,
            "records_created": self._records_created,
            "last_flush_at": self._last_flush_at,
            "last_error": self._last_error,
            "flush_seconds": settings.live_capture_flush_seconds,
            "permissions_note": (
                "Passive capture on Windows requires Npcap and an elevated (Administrator) "
                "process. Only packet metadata is aggregated; payloads are not stored."
            ),
        }

    def start(self, interface: str | None, bpf_filter: str | None) -> dict:
        if not settings.live_capture_enabled:
            raise ServiceUnavailableError("Live capture is disabled in configuration")
        if not SCAPY_AVAILABLE:
            raise ServiceUnavailableError(
                f"Scapy is unavailable: {SCAPY_ERROR}. Install scapy/Npcap or use dataset mode."
            )
        with self._lock:
            if self._running:
                raise ConflictError("Live capture is already running")
            if bpf_filter and len(bpf_filter) > 200:
                raise ValidationError("BPF filter is too long")
            self._buffer.clear()
            self._packets_seen = 0
            self._records_created = 0
            self._flows_flushed = 0
            self._last_error = None
            self._last_flush_at = None
            sniffer = AsyncSniffer(
                prn=self._handle_packet,
                store=False,
                iface=interface or None,
                filter=bpf_filter or None,
            )
            try:
                sniffer.start()
            except Exception as exc:
                raise ServiceUnavailableError(
                    "Could not start capture. Run the server as Administrator, verify the "
                    f"interface and Npcap installation. Details: {exc}"
                ) from exc
            self._sniffer = sniffer
            self._running = True
            self._started_at = datetime.now(timezone.utc)
            self._stopped_at = None
            self._interface = interface
            self._bpf_filter = bpf_filter
            self._stop_event.clear()
            self._flush_thread = threading.Thread(
                target=self._flush_loop, name="oppps-live-flush", daemon=True
            )
            self._flush_thread.start()
            return self.status()

    def stop(self) -> dict:
        with self._lock:
            if not self._running:
                return self.status()
            self._running = False
            self._stop_event.set()
            sniffer = self._sniffer
        if sniffer is not None:
            try:
                sniffer.stop()
            except Exception as exc:
                self._last_error = f"Sniffer stop warning: {exc}"
        if self._flush_thread is not None:
            self._flush_thread.join(timeout=10)
        self.flush()
        with self._lock:
            self._sniffer = None
            self._stopped_at = datetime.now(timezone.utc)
        return self.status()

    def _flush_loop(self) -> None:
        while not self._stop_event.wait(settings.live_capture_flush_seconds):
            self.flush()

    def _handle_packet(self, packet) -> None:  # type: ignore[no-untyped-def]
        try:
            if not packet.haslayer(IP):
                return
            with self._lock:
                if not self._running and self._stop_event.is_set():
                    return
                if self._packets_seen >= settings.live_capture_max_packets:
                    return
                self._packets_seen += 1
                if len(self._buffer) > 20000:
                    self._last_error = "Flow buffer limit reached; packets are being skipped"
                    return

                ip_layer = packet[IP]
                src, dst = ip_layer.src, ip_layer.dst
                sport = dport = 0
                protocol = "OTHER"
                tcp_flags = ""
                if packet.haslayer(TCP):
                    protocol = "TCP"
                    sport, dport = int(packet[TCP].sport), int(packet[TCP].dport)
                    tcp_flags = str(packet[TCP].flags)
                elif packet.haslayer(UDP):
                    protocol = "UDP"
                    sport, dport = int(packet[UDP].sport), int(packet[UDP].dport)
                elif packet.haslayer(ICMP):
                    protocol = "ICMP"

                endpoints = sorted([(src, sport), (dst, dport)])
                key = (endpoints[0], endpoints[1], protocol)
                now_ts = float(getattr(packet, "time", time.time()))
                entry = self._buffer.get(key)
                if entry is None:
                    entry = {
                        "first_ts": now_ts,
                        "last_ts": now_ts,
                        "first": (src, sport),
                        "src": src,
                        "dst": dst,
                        "sport": sport,
                        "dport": dport,
                        "protocol": protocol,
                        "fwd": 0,
                        "bwd": 0,
                        "packets": 0,
                        "bytes": 0,
                        "sum_sq": 0.0,
                        "min_len": 10**9,
                        "max_len": 0,
                        "syn": 0,
                        "ack": 0,
                        "rst": 0,
                        "fin": 0,
                        "psh": 0,
                        "flags": set(),
                    }
                    self._buffer[key] = entry
                length = len(packet)
                entry["last_ts"] = now_ts
                entry["packets"] += 1
                entry["bytes"] += length
                entry["sum_sq"] += length * length
                entry["min_len"] = min(entry["min_len"], length)
                entry["max_len"] = max(entry["max_len"], length)
                if (src, sport) == entry["first"]:
                    entry["fwd"] += 1
                else:
                    entry["bwd"] += 1
                if tcp_flags:
                    entry["flags"].update(ch for ch in tcp_flags if ch in "SAFRP")
                    if "S" in tcp_flags:
                        entry["syn"] += 1
                    if "A" in tcp_flags:
                        entry["ack"] += 1
                    if "R" in tcp_flags:
                        entry["rst"] += 1
                    if "F" in tcp_flags:
                        entry["fin"] += 1
                    if "P" in tcp_flags:
                        entry["psh"] += 1
        except Exception as exc:  # pragma: no cover - defensive callback
            self._last_error = f"Packet processing error: {exc}"

    def flush(self) -> int:
        with self._lock:
            if not self._buffer:
                return 0
            snapshot = self._buffer
            self._buffer = {}
        created = 0
        db = SessionLocal()
        try:
            records = []
            for entry in snapshot.values():
                duration = max(entry["last_ts"] - entry["first_ts"], 0.001)
                packets = max(entry["packets"], 1)
                mean_len = entry["bytes"] / packets
                variance = max(entry["sum_sq"] / packets - mean_len**2, 0)
                features = {
                    "flow_duration": round(duration, 6),
                    "fwd_packet_count": entry["fwd"],
                    "bwd_packet_count": entry["bwd"],
                    "packet_count": packets,
                    "packet_length_mean": round(mean_len, 6),
                    "packet_length_std": round(math.sqrt(variance), 6),
                    "min_packet_length": float(entry["min_len"]),
                    "max_packet_length": float(entry["max_len"]),
                    "flow_bytes_per_sec": round(entry["bytes"] / duration, 6),
                    "flow_packets_per_sec": round(packets / duration, 6),
                    "syn_count": entry["syn"],
                    "ack_count": entry["ack"],
                    "rst_count": entry["rst"],
                    "fin_count": entry["fin"],
                    "psh_count": entry["psh"],
                    "header_length": float(40 * packets),
                    "active_mean": round(duration, 6),
                    "idle_mean": 0.0,
                    "down_up_ratio": round(entry["bwd"] / max(entry["fwd"], 1), 6),
                    "destination_port": float(entry["dport"]),
                    "protocol_num": float(PROTOCOL_NUMBERS.get(entry["protocol"], 0)),
                }
                timestamp = datetime.fromtimestamp(entry["first_ts"], tz=timezone.utc)
                record = TrafficRecord(
                    timestamp=timestamp,
                    src_ip=entry["src"],
                    dst_ip=entry["dst"],
                    src_port=entry["sport"] or None,
                    dst_port=entry["dport"] or None,
                    protocol=entry["protocol"],
                    packet_count=float(packets),
                    flow_duration=features["flow_duration"],
                    packet_length=features["packet_length_mean"],
                    flow_bytes_per_sec=features["flow_bytes_per_sec"],
                    flow_packets_per_sec=features["flow_packets_per_sec"],
                    tcp_flags=",".join(sorted(entry["flags"])) or None,
                    dataset_label=None,
                    source="live",
                    features=features,
                )
                db.add(record)
                records.append(record)
            db.commit()
            for record in records:
                db.refresh(record)
            created = len(records)
            ids = [record.id for record in records]
        except Exception as exc:
            db.rollback()
            self._last_error = f"Failed to store captured flows: {exc}"
            db.close()
            return 0
        finally:
            if db.is_active:
                db.close()

        try:
            from app.services.detection import run_detection

            session = SessionLocal()
            try:
                if ids:
                    run_detection(session, limit=len(ids), record_ids=ids)
            finally:
                session.close()
        except Exception as exc:
            self._last_error = f"Captured flows stored but detection was deferred: {exc}"

        with self._lock:
            self._records_created += created
            self._flows_flushed += created
            self._last_flush_at = datetime.now(timezone.utc)
        return created


capture_manager = LiveCaptureManager()


def capture_exceptions() -> dict:
    return capture_manager.status()
