"""
flow_replayer.py — Flow Replay Module
Reconstructs individual TCP/UDP flows from PCAPs for debugging
and incident investigation. Generates per-flow PCAP slices.
"""

import struct
from collections import defaultdict
from typing import List, Dict, Optional


class FlowReplayer:
    """
    Extracts and replays individual flows from PCAP data.
    Each flow can be inspected packet-by-packet with hex dumps.
    """

    def __init__(self):
        self.flows: Dict[str, list] = {}  # flow_id -> list of packet dicts

    def extract_flows(self, packets) -> dict:
        """Extract all flows from analyzed packets."""
        self.flows = defaultdict(list)

        for i, pkt in enumerate(packets):
            if not pkt.src_ip or pkt.protocol not in (6, 17):
                continue

            flow_id = self._get_flow_id(pkt)

            self.flows[flow_id].append({
                "index": i,
                "timestamp": pkt.timestamp,
                "src_ip": pkt.src_ip,
                "dst_ip": pkt.dst_ip,
                "src_port": pkt.src_port,
                "dst_port": pkt.dst_port,
                "protocol": "TCP" if pkt.protocol == 6 else "UDP",
                "length": pkt.length,
                "tcp_flags": self._format_tcp_flags(pkt.tcp_flags) if pkt.protocol == 6 else "",
                "payload_len": len(pkt.payload),
                "has_payload": len(pkt.payload) > 0,
            })

        return {
            "total_flows": len(self.flows),
            "flows": [
                {
                    "flow_id": fid,
                    "packets": len(pkts),
                    "bytes": sum(p["length"] for p in pkts),
                    "start_time": pkts[0]["timestamp"] if pkts else 0,
                    "end_time": pkts[-1]["timestamp"] if pkts else 0,
                    "duration": round((pkts[-1]["timestamp"] - pkts[0]["timestamp"]), 3) if len(pkts) > 1 else 0,
                    "src": f"{pkts[0]['src_ip']}:{pkts[0]['src_port']}" if pkts else "",
                    "dst": f"{pkts[0]['dst_ip']}:{pkts[0]['dst_port']}" if pkts else "",
                    "protocol": pkts[0]["protocol"] if pkts else "",
                }
                for fid, pkts in sorted(self.flows.items(), key=lambda x: -len(x[1]))
            ]
        }

    def get_flow_detail(self, flow_id: str, packets) -> Optional[dict]:
        """Get detailed packet-by-packet view of a specific flow."""
        if flow_id not in self.flows:
            return None

        flow_packets = self.flows[flow_id]
        detailed = []

        for fp in flow_packets:
            pkt = packets[fp["index"]]
            detail = {
                **fp,
                "hex_dump": self._hex_dump(pkt.raw_data[:256]),
                "ascii_dump": self._ascii_dump(pkt.raw_data[:256]),
                "payload_hex": self._hex_dump(pkt.payload[:128]) if pkt.payload else "",
                "payload_ascii": self._ascii_dump(pkt.payload[:128]) if pkt.payload else "",
            }
            detailed.append(detail)

        return {
            "flow_id": flow_id,
            "packet_count": len(detailed),
            "total_bytes": sum(d["length"] for d in detailed),
            "packets": detailed,
        }

    def generate_flow_pcap(self, flow_id: str, packets) -> Optional[bytes]:
        """Generate a PCAP file containing only packets from a specific flow."""
        if flow_id not in self.flows:
            return None

        flow_packets = self.flows[flow_id]
        output = bytearray()

        # PCAP global header
        output += struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)

        for fp in flow_packets:
            pkt = packets[fp["index"]]
            ts_sec = int(pkt.timestamp)
            ts_usec = int((pkt.timestamp - ts_sec) * 1_000_000)
            data = pkt.raw_data
            output += struct.pack("<IIII", ts_sec, ts_usec, len(data), len(data))
            output += data

        return bytes(output)

    # ── Helpers ─────────────────────────────────────────────────────────────

    def _get_flow_id(self, pkt) -> str:
        """Create a bidirectional flow ID."""
        a = f"{pkt.src_ip}:{pkt.src_port}"
        b = f"{pkt.dst_ip}:{pkt.dst_port}"
        if a > b:
            a, b = b, a
        return f"{a}<->{b}/{pkt.protocol}"

    @staticmethod
    def _format_tcp_flags(flags: int) -> str:
        parts = []
        if flags & 0x02: parts.append("SYN")
        if flags & 0x10: parts.append("ACK")
        if flags & 0x01: parts.append("FIN")
        if flags & 0x04: parts.append("RST")
        if flags & 0x08: parts.append("PSH")
        if flags & 0x20: parts.append("URG")
        return " ".join(parts) if parts else "---"

    @staticmethod
    def _hex_dump(data: bytes, width: int = 16) -> str:
        """Generate a hex dump string."""
        lines = []
        for i in range(0, len(data), width):
            chunk = data[i:i+width]
            hex_part = " ".join(f"{b:02x}" for b in chunk)
            ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            lines.append(f"{i:04x}  {hex_part:<{width*3}}  {ascii_part}")
        return "\n".join(lines)

    @staticmethod
    def _ascii_dump(data: bytes) -> str:
        """Generate a printable ASCII view."""
        return "".join(chr(b) if 32 <= b < 127 else "." for b in data)
