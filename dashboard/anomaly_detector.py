"""
anomaly_detector.py — Anomaly Detection Engine
Detects port scans, DDoS patterns, connection bursts,
and flow rate anomalies using statistical profiling.
"""

import math
from collections import defaultdict
from dataclasses import dataclass, field
from typing import List, Dict


@dataclass
class AnomalyAlert:
    """A detected anomaly."""
    alert_id: int = 0
    severity: str = "info"      # critical, warning, info
    category: str = ""          # port_scan, ddos, burst, unusual_flow, large_flow
    title: str = ""
    description: str = ""
    source_ip: str = ""
    timestamp: float = 0.0
    details: dict = field(default_factory=dict)

    def to_dict(self):
        return {
            "id": self.alert_id,
            "severity": self.severity,
            "category": self.category,
            "title": self.title,
            "description": self.description,
            "source_ip": self.source_ip,
            "timestamp": self.timestamp,
            "details": self.details,
        }


class AnomalyDetector:
    """
    Detects network anomalies from analyzed packet data.
    
    Detection types:
    - Port Scan: >10 unique dst ports from single IP in 60s window
    - DDoS Pattern: >100 packets/sec from single IP
    - Connection Burst: >5x baseline new connections/sec
    - Unusual Protocol: Non-TCP/UDP on unexpected ports
    - Large Flow: Single flow >1MB
    """

    # Thresholds
    PORT_SCAN_THRESHOLD = 8          # unique ports to trigger
    PORT_SCAN_WINDOW = 60            # seconds
    DDOS_PPS_THRESHOLD = 50          # packets per second
    BURST_MULTIPLIER = 3.0           # times baseline
    LARGE_FLOW_BYTES = 500_000       # bytes (~500KB)
    ENTROPY_THRESHOLD = 7.5          # high entropy payload

    def __init__(self):
        self.alerts: List[AnomalyAlert] = []
        self._alert_counter = 0

    def analyze(self, packets, flows) -> List[dict]:
        """Run all anomaly detectors on packet/flow data."""
        self.alerts = []
        self._alert_counter = 0

        self._detect_port_scans(packets)
        self._detect_ddos_patterns(packets)
        self._detect_connection_bursts(packets)
        self._detect_large_flows(flows)
        self._detect_unusual_protocols(packets)
        self._detect_syn_floods(packets)

        # Sort by severity
        severity_order = {"critical": 0, "warning": 1, "info": 2}
        self.alerts.sort(key=lambda a: severity_order.get(a.severity, 3))

        return [a.to_dict() for a in self.alerts]

    def _add_alert(self, severity, category, title, description, source_ip="", timestamp=0.0, details=None):
        self._alert_counter += 1
        self.alerts.append(AnomalyAlert(
            alert_id=self._alert_counter,
            severity=severity,
            category=category,
            title=title,
            description=description,
            source_ip=source_ip,
            timestamp=timestamp,
            details=details or {},
        ))

    # ── Port Scan Detection ────────────────────────────────────────────────

    def _detect_port_scans(self, packets):
        """Detect IPs connecting to many unique destination ports."""
        # Group packets by source IP and time window
        ip_ports = defaultdict(set)  # ip -> set of dst_ports
        ip_timestamps = defaultdict(list)

        for pkt in packets:
            if pkt.protocol == 6 and pkt.dst_port > 0:  # TCP only
                ip_ports[pkt.src_ip].add(pkt.dst_port)
                ip_timestamps[pkt.src_ip].append(pkt.timestamp)

        for ip, ports in ip_ports.items():
            if len(ports) >= self.PORT_SCAN_THRESHOLD:
                timestamps = ip_timestamps[ip]
                if timestamps:
                    duration = max(timestamps) - min(timestamps)
                    if duration <= self.PORT_SCAN_WINDOW or duration == 0:
                        self._add_alert(
                            severity="critical",
                            category="port_scan",
                            title=f"Port Scan Detected from {ip}",
                            description=f"IP {ip} connected to {len(ports)} unique ports within {duration:.0f}s",
                            source_ip=ip,
                            timestamp=min(timestamps),
                            details={
                                "unique_ports": len(ports),
                                "sample_ports": sorted(list(ports))[:20],
                                "duration_sec": round(duration, 1),
                            }
                        )

    # ── DDoS Pattern Detection ─────────────────────────────────────────────

    def _detect_ddos_patterns(self, packets):
        """Detect abnormally high packet rates from single IPs."""
        ip_packets = defaultdict(list)  # ip -> list of timestamps

        for pkt in packets:
            ip_packets[pkt.src_ip].append(pkt.timestamp)

        for ip, timestamps in ip_packets.items():
            if len(timestamps) < 10:
                continue
            timestamps.sort()
            duration = max(timestamps[-1] - timestamps[0], 0.001)
            pps = len(timestamps) / duration

            if pps >= self.DDOS_PPS_THRESHOLD:
                self._add_alert(
                    severity="critical",
                    category="ddos",
                    title=f"DDoS Pattern from {ip}",
                    description=f"IP {ip} sending {pps:.0f} packets/sec ({len(timestamps)} packets in {duration:.1f}s)",
                    source_ip=ip,
                    timestamp=timestamps[0],
                    details={
                        "packets_per_sec": round(pps, 1),
                        "total_packets": len(timestamps),
                        "duration_sec": round(duration, 1),
                    }
                )

    # ── Connection Burst Detection ─────────────────────────────────────────

    def _detect_connection_bursts(self, packets):
        """Detect sudden spikes in new TCP connections (SYN packets)."""
        syn_times = []
        for pkt in packets:
            if pkt.protocol == 6 and (pkt.tcp_flags & 0x02) and not (pkt.tcp_flags & 0x10):
                syn_times.append(pkt.timestamp)

        if len(syn_times) < 5:
            return

        syn_times.sort()
        duration = max(syn_times[-1] - syn_times[0], 0.001)
        baseline_rate = len(syn_times) / duration

        # Sliding window to find spikes
        window_size = 5.0  # seconds
        for i, t in enumerate(syn_times):
            window_syns = sum(1 for t2 in syn_times if t <= t2 <= t + window_size)
            window_rate = window_syns / window_size

            if window_rate >= baseline_rate * self.BURST_MULTIPLIER and window_syns >= 10:
                self._add_alert(
                    severity="warning",
                    category="burst",
                    title="Connection Burst Detected",
                    description=f"SYN rate spiked to {window_rate:.0f}/sec (baseline: {baseline_rate:.1f}/sec)",
                    timestamp=t,
                    details={
                        "burst_rate": round(window_rate, 1),
                        "baseline_rate": round(baseline_rate, 1),
                        "multiplier": round(window_rate / max(baseline_rate, 0.001), 1),
                    }
                )
                break  # One alert per analysis

    # ── SYN Flood Detection ────────────────────────────────────────────────

    def _detect_syn_floods(self, packets):
        """Detect SYN flood patterns (many SYNs without corresponding ACKs)."""
        ip_syns = defaultdict(int)
        ip_syn_acks = defaultdict(int)

        for pkt in packets:
            if pkt.protocol == 6:
                if (pkt.tcp_flags & 0x02) and not (pkt.tcp_flags & 0x10):
                    ip_syns[pkt.src_ip] += 1
                elif (pkt.tcp_flags & 0x02) and (pkt.tcp_flags & 0x10):
                    ip_syn_acks[pkt.dst_ip] += 1

        for ip, syn_count in ip_syns.items():
            ack_count = ip_syn_acks.get(ip, 0)
            if syn_count >= 10 and ack_count < syn_count * 0.5:
                self._add_alert(
                    severity="warning",
                    category="syn_flood",
                    title=f"Possible SYN Flood from {ip}",
                    description=f"{syn_count} SYN packets sent but only {ack_count} SYN-ACKs received",
                    source_ip=ip,
                    details={
                        "syn_count": syn_count,
                        "syn_ack_count": ack_count,
                        "completion_rate": round(ack_count / max(syn_count, 1) * 100, 1),
                    }
                )

    # ── Large Flow Detection ───────────────────────────────────────────────

    def _detect_large_flows(self, flows):
        """Detect unusually large flows."""
        for flow_id, flow in flows.items():
            if flow.bytes_total >= self.LARGE_FLOW_BYTES:
                self._add_alert(
                    severity="info",
                    category="large_flow",
                    title=f"Large Flow: {flow.sni or flow.app_type}",
                    description=f"Flow transferred {flow.bytes_total / 1024:.0f}KB in {flow.packets} packets",
                    source_ip=flow.key.src_ip if flow.key else "",
                    timestamp=flow.first_seen,
                    details={
                        "bytes": flow.bytes_total,
                        "packets": flow.packets,
                        "app": flow.app_type,
                        "sni": flow.sni,
                    }
                )

    # ── Unusual Protocol Detection ─────────────────────────────────────────

    def _detect_unusual_protocols(self, packets):
        """Detect non-standard protocol usage."""
        unusual = defaultdict(int)
        for pkt in packets:
            if pkt.protocol not in (6, 17, 1):  # Not TCP, UDP, or ICMP
                unusual[pkt.protocol] += 1

        for proto, count in unusual.items():
            if count >= 3:
                self._add_alert(
                    severity="info",
                    category="unusual_protocol",
                    title=f"Unusual Protocol Detected (ID: {proto})",
                    description=f"Protocol {proto} seen in {count} packets",
                    details={"protocol": proto, "count": count}
                )
