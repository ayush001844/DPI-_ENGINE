"""
pcap_analyzer.py — Core PCAP Analysis Module
Reads PCAP files directly in Python, computes traffic statistics,
protocol distributions, bandwidth timelines, and feeds data to
anomaly detection and ML classification.
"""

import struct
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple

# ── PCAP Constants ──────────────────────────────────────────────────────────
PCAP_MAGIC_LE = 0xA1B2C3D4
PCAP_MAGIC_BE = 0xD4C3B2A1
ETH_HEADER_LEN = 14
MIN_IP_HEADER_LEN = 20
TCP_HEADER_MIN = 20
UDP_HEADER_LEN = 8

# TLS constants
TLS_HANDSHAKE = 0x16
TLS_CLIENT_HELLO = 0x01
SNI_EXTENSION = 0x0000

# Application signatures (SNI -> app name)
APP_SIGNATURES = {
    "google": "Google", "gstatic": "Google", "googleapis": "Google",
    "youtube": "YouTube", "ytimg": "YouTube", "youtu.be": "YouTube",
    "facebook": "Facebook", "fbcdn": "Facebook", "fb.com": "Facebook",
    "instagram": "Instagram", "cdninstagram": "Instagram",
    "twitter": "Twitter/X", "twimg": "Twitter/X", "x.com": "Twitter/X",
    "netflix": "Netflix", "nflxvideo": "Netflix",
    "amazon": "Amazon", "amazonaws": "Amazon", "cloudfront": "Amazon",
    "microsoft": "Microsoft", "msn.com": "Microsoft", "azure": "Microsoft",
    "apple": "Apple", "icloud": "Apple", "itunes": "Apple",
    "whatsapp": "WhatsApp", "wa.me": "WhatsApp",
    "telegram": "Telegram", "t.me": "Telegram",
    "tiktok": "TikTok", "bytedance": "TikTok",
    "spotify": "Spotify", "scdn.co": "Spotify",
    "zoom": "Zoom",
    "discord": "Discord", "discordapp": "Discord",
    "github": "GitHub", "githubusercontent": "GitHub",
    "cloudflare": "Cloudflare",
}


@dataclass
class PacketInfo:
    """Parsed packet information."""
    timestamp: float = 0.0
    src_mac: str = ""
    dst_mac: str = ""
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int = 0
    dst_port: int = 0
    protocol: int = 0  # 6=TCP, 17=UDP
    tcp_flags: int = 0
    length: int = 0
    payload: bytes = b""
    payload_offset: int = 0
    raw_data: bytes = b""


@dataclass
class FlowKey:
    """Five-tuple flow identifier."""
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int

    def __hash__(self):
        return hash((self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.protocol))

    def __eq__(self, other):
        return (self.src_ip == other.src_ip and self.dst_ip == other.dst_ip and
                self.src_port == other.src_port and self.dst_port == other.dst_port and
                self.protocol == other.protocol)

    def reverse(self):
        return FlowKey(self.dst_ip, self.src_ip, self.dst_port, self.src_port, self.protocol)

    def to_dict(self):
        return {
            "src_ip": self.src_ip, "dst_ip": self.dst_ip,
            "src_port": self.src_port, "dst_port": self.dst_port,
            "protocol": "TCP" if self.protocol == 6 else "UDP" if self.protocol == 17 else str(self.protocol)
        }


@dataclass
class FlowInfo:
    """Tracked flow state."""
    key: FlowKey = None
    app_type: str = "Unknown"
    sni: str = ""
    packets: int = 0
    bytes_total: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0
    blocked: bool = False
    classified: bool = False
    packet_sizes: list = field(default_factory=list)
    inter_arrival_times: list = field(default_factory=list)
    tcp_flags_seen: list = field(default_factory=list)

    def duration(self):
        return max(self.last_seen - self.first_seen, 0.001)

    def to_dict(self):
        return {
            "flow_key": self.key.to_dict() if self.key else {},
            "app_type": self.app_type,
            "sni": self.sni,
            "packets": self.packets,
            "bytes": self.bytes_total,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "duration": round(self.duration(), 3),
            "blocked": self.blocked,
            "avg_packet_size": round(self.bytes_total / max(self.packets, 1), 1),
        }


class PcapAnalyzer:
    """Full PCAP analysis engine."""

    def __init__(self):
        self.packets: List[PacketInfo] = []
        self.flows: Dict[str, FlowInfo] = {}
        self.blocked_ips: set = set()
        self.blocked_apps: set = set()
        self.blocked_domains: list = []
        self.stats = {}

    def analyze(self, filepath: str) -> dict:
        """Full analysis of a PCAP file. Returns structured results."""
        self.packets = []
        self.flows = {}
        start_time = time.time()

        packets_raw = self._read_pcap(filepath)

        for raw_ts, raw_data in packets_raw:
            pkt = self._parse_packet(raw_ts, raw_data)
            if pkt and pkt.src_ip:
                self.packets.append(pkt)
                self._track_flow(pkt)

        analysis_time = time.time() - start_time

        self.stats = self._compute_stats(analysis_time)
        return self.stats

    # ── PCAP Reading ────────────────────────────────────────────────────────

    def _read_pcap(self, filepath: str) -> list:
        """Read all packets from a PCAP file."""
        packets = []
        with open(filepath, "rb") as f:
            # Global header (24 bytes)
            ghdr = f.read(24)
            if len(ghdr) < 24:
                return packets

            magic = struct.unpack("<I", ghdr[0:4])[0]
            if magic == PCAP_MAGIC_LE:
                endian = "<"
            elif magic == PCAP_MAGIC_BE:
                endian = ">"
            else:
                return packets

            while True:
                phdr = f.read(16)
                if len(phdr) < 16:
                    break
                ts_sec, ts_usec, incl_len, orig_len = struct.unpack(f"{endian}IIII", phdr)
                data = f.read(incl_len)
                if len(data) < incl_len:
                    break
                timestamp = ts_sec + ts_usec / 1_000_000
                packets.append((timestamp, data))

        return packets

    # ── Packet Parsing ──────────────────────────────────────────────────────

    def _parse_packet(self, timestamp: float, data: bytes) -> Optional[PacketInfo]:
        """Parse raw packet bytes into PacketInfo."""
        pkt = PacketInfo(timestamp=timestamp, raw_data=data, length=len(data))

        if len(data) < ETH_HEADER_LEN:
            return None

        # Ethernet
        pkt.dst_mac = self._format_mac(data[0:6])
        pkt.src_mac = self._format_mac(data[6:12])
        ether_type = struct.unpack("!H", data[12:14])[0]

        if ether_type != 0x0800:  # IPv4 only
            return pkt

        offset = ETH_HEADER_LEN
        if len(data) < offset + MIN_IP_HEADER_LEN:
            return pkt

        # IPv4
        version_ihl = data[offset]
        ihl = (version_ihl & 0x0F) * 4
        if ihl < MIN_IP_HEADER_LEN or len(data) < offset + ihl:
            return pkt

        pkt.protocol = data[offset + 9]
        pkt.src_ip = f"{data[offset+12]}.{data[offset+13]}.{data[offset+14]}.{data[offset+15]}"
        pkt.dst_ip = f"{data[offset+16]}.{data[offset+17]}.{data[offset+18]}.{data[offset+19]}"
        offset += ihl

        # TCP
        if pkt.protocol == 6 and len(data) >= offset + TCP_HEADER_MIN:
            pkt.src_port = struct.unpack("!H", data[offset:offset+2])[0]
            pkt.dst_port = struct.unpack("!H", data[offset+2:offset+4])[0]
            pkt.tcp_flags = data[offset + 13]
            tcp_data_offset = ((data[offset + 12] >> 4) & 0x0F) * 4
            offset += max(tcp_data_offset, TCP_HEADER_MIN)

        # UDP
        elif pkt.protocol == 17 and len(data) >= offset + UDP_HEADER_LEN:
            pkt.src_port = struct.unpack("!H", data[offset:offset+2])[0]
            pkt.dst_port = struct.unpack("!H", data[offset+2:offset+4])[0]
            offset += UDP_HEADER_LEN

        pkt.payload_offset = offset
        if offset < len(data):
            pkt.payload = data[offset:]

        return pkt

    # ── Flow Tracking ───────────────────────────────────────────────────────

    def _track_flow(self, pkt: PacketInfo):
        """Track and classify flows."""
        if not pkt.src_ip or pkt.protocol not in (6, 17):
            return

        fk = FlowKey(pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port, pkt.protocol)
        flow_id = f"{pkt.src_ip}:{pkt.src_port}->{pkt.dst_ip}:{pkt.dst_port}/{pkt.protocol}"

        # Check reverse flow too
        rev_id = f"{pkt.dst_ip}:{pkt.dst_port}->{pkt.src_ip}:{pkt.src_port}/{pkt.protocol}"
        if rev_id in self.flows:
            flow_id = rev_id

        if flow_id not in self.flows:
            self.flows[flow_id] = FlowInfo(key=fk, first_seen=pkt.timestamp)

        flow = self.flows[flow_id]
        flow.packets += 1
        flow.bytes_total += pkt.length
        flow.last_seen = pkt.timestamp
        flow.packet_sizes.append(pkt.length)
        flow.tcp_flags_seen.append(pkt.tcp_flags)

        if flow.packets > 1 and len(flow.packet_sizes) > 1:
            iat = pkt.timestamp - flow.last_seen if flow.last_seen > 0 else 0
            flow.inter_arrival_times.append(max(iat, 0))

        # Classify if not done
        if not flow.classified:
            self._classify_flow(pkt, flow)

        # Check blocking
        if not flow.blocked:
            flow.blocked = self._check_blocked(pkt, flow)

    def _classify_flow(self, pkt: PacketInfo, flow: FlowInfo):
        """Classify a flow using SNI/Host/DNS inspection."""
        # TLS SNI extraction
        if pkt.dst_port == 443 and len(pkt.payload) > 5:
            sni = self._extract_sni(pkt.payload)
            if sni:
                flow.sni = sni
                flow.app_type = self._sni_to_app(sni)
                flow.classified = True
                return

        # HTTP Host extraction
        if pkt.dst_port == 80 and len(pkt.payload) > 10:
            host = self._extract_http_host(pkt.payload)
            if host:
                flow.sni = host
                flow.app_type = self._sni_to_app(host)
                flow.classified = True
                return

        # DNS
        if pkt.dst_port == 53 or pkt.src_port == 53:
            flow.app_type = "DNS"
            flow.classified = True
            return

        # Port-based fallback
        if pkt.dst_port == 443:
            flow.app_type = "HTTPS"
        elif pkt.dst_port == 80:
            flow.app_type = "HTTP"

    def _extract_sni(self, payload: bytes) -> Optional[str]:
        """Extract SNI from TLS Client Hello."""
        if len(payload) < 9:
            return None
        if payload[0] != TLS_HANDSHAKE:
            return None

        version = struct.unpack("!H", payload[1:3])[0]
        if version < 0x0300 or version > 0x0304:
            return None

        if payload[5] != TLS_CLIENT_HELLO:
            return None

        try:
            offset = 43  # Skip to session ID
            if offset >= len(payload):
                return None

            session_id_len = payload[offset]
            offset += 1 + session_id_len

            if offset + 2 > len(payload):
                return None
            cipher_suites_len = struct.unpack("!H", payload[offset:offset+2])[0]
            offset += 2 + cipher_suites_len

            if offset >= len(payload):
                return None
            comp_len = payload[offset]
            offset += 1 + comp_len

            if offset + 2 > len(payload):
                return None
            ext_len = struct.unpack("!H", payload[offset:offset+2])[0]
            offset += 2

            ext_end = min(offset + ext_len, len(payload))
            while offset + 4 <= ext_end:
                ext_type = struct.unpack("!H", payload[offset:offset+2])[0]
                ext_data_len = struct.unpack("!H", payload[offset+2:offset+4])[0]
                offset += 4

                if ext_type == SNI_EXTENSION and ext_data_len >= 5:
                    sni_len = struct.unpack("!H", payload[offset+3:offset+5])[0]
                    sni = payload[offset+5:offset+5+sni_len].decode("ascii", errors="ignore")
                    return sni

                offset += ext_data_len
        except (IndexError, struct.error):
            pass
        return None

    def _extract_http_host(self, payload: bytes) -> Optional[str]:
        """Extract Host header from HTTP request."""
        try:
            text = payload[:2048].decode("ascii", errors="ignore")
            if not text.startswith(("GET ", "POST", "PUT ", "HEAD", "DELETE", "PATCH", "OPTIONS")):
                return None
            for line in text.split("\r\n"):
                if line.lower().startswith("host:"):
                    host = line[5:].strip()
                    if ":" in host:
                        host = host.split(":")[0]
                    return host
        except Exception:
            pass
        return None

    def _sni_to_app(self, sni: str) -> str:
        """Map SNI to application name."""
        lower = sni.lower()
        for pattern, app_name in APP_SIGNATURES.items():
            if pattern in lower:
                return app_name
        return "HTTPS" if sni else "Unknown"

    def _check_blocked(self, pkt: PacketInfo, flow: FlowInfo) -> bool:
        """Check if packet/flow should be blocked."""
        if pkt.src_ip in self.blocked_ips:
            return True
        if flow.app_type in self.blocked_apps:
            return True
        for dom in self.blocked_domains:
            if dom in flow.sni.lower():
                return True
        return False

    # ── Statistics ──────────────────────────────────────────────────────────

    def _compute_stats(self, analysis_time: float) -> dict:
        """Compute comprehensive traffic statistics."""
        total_packets = len(self.packets)
        total_bytes = sum(p.length for p in self.packets)
        tcp_packets = sum(1 for p in self.packets if p.protocol == 6)
        udp_packets = sum(1 for p in self.packets if p.protocol == 17)

        forwarded = sum(1 for f in self.flows.values() if not f.blocked) 
        dropped = sum(f.packets for f in self.flows.values() if f.blocked)

        # App distribution
        app_counts = defaultdict(int)
        for f in self.flows.values():
            app_counts[f.app_type] += f.packets

        app_distribution = sorted(
            [{"app": k, "packets": v, "percent": round(100 * v / max(total_packets, 1), 1)}
             for k, v in app_counts.items()],
            key=lambda x: x["packets"], reverse=True
        )

        # Detected SNIs
        detected_snis = [
            {"sni": f.sni, "app": f.app_type}
            for f in self.flows.values() if f.sni
        ]
        # Deduplicate
        seen = set()
        unique_snis = []
        for s in detected_snis:
            if s["sni"] not in seen:
                seen.add(s["sni"])
                unique_snis.append(s)

        # Timeline (packets per second)
        if self.packets:
            t_start = self.packets[0].timestamp
            t_end = self.packets[-1].timestamp
            duration = max(t_end - t_start, 1)
            bucket_count = min(60, max(10, int(duration)))
            bucket_size = duration / bucket_count
            timeline = [0] * bucket_count
            bytes_timeline = [0] * bucket_count
            for p in self.packets:
                idx = min(int((p.timestamp - t_start) / bucket_size), bucket_count - 1)
                timeline[idx] += 1
                bytes_timeline[idx] += p.length
        else:
            timeline = []
            bytes_timeline = []

        # Top talkers (by bytes)
        ip_bytes = defaultdict(int)
        for p in self.packets:
            ip_bytes[p.src_ip] += p.length
        top_talkers = sorted(
            [{"ip": k, "bytes": v} for k, v in ip_bytes.items()],
            key=lambda x: x["bytes"], reverse=True
        )[:10]

        # Flow list
        flow_list = sorted(
            [f.to_dict() for f in self.flows.values()],
            key=lambda x: x["bytes"], reverse=True
        )

        # Protocol distribution
        proto_dist = {
            "TCP": tcp_packets,
            "UDP": udp_packets,
            "Other": total_packets - tcp_packets - udp_packets
        }

        return {
            "summary": {
                "total_packets": total_packets,
                "total_bytes": total_bytes,
                "tcp_packets": tcp_packets,
                "udp_packets": udp_packets,
                "total_flows": len(self.flows),
                "forwarded_flows": forwarded,
                "blocked_flows": len(self.flows) - forwarded,
                "dropped_packets": dropped,
                "analysis_time_ms": round(analysis_time * 1000, 1),
            },
            "app_distribution": app_distribution,
            "detected_snis": unique_snis,
            "timeline": {
                "packets_per_sec": timeline,
                "bytes_per_sec": bytes_timeline,
            },
            "top_talkers": top_talkers,
            "flows": flow_list,
            "protocol_distribution": proto_dist,
        }

    # ── Helpers ─────────────────────────────────────────────────────────────

    @staticmethod
    def _format_mac(data: bytes) -> str:
        return ":".join(f"{b:02x}" for b in data)
