"""
ml_classifier.py — ML-Based Application Classifier
Uses statistical flow features (packet size distribution, inter-arrival times,
byte entropy) to classify encrypted traffic where SNI is absent.
"""

import math
from collections import defaultdict
from typing import Dict, List, Optional


# ── Feature-based classification profiles ───────────────────────────────
# Each profile defines expected flow characteristics for an app category
APP_PROFILES = {
    "Video Streaming": {
        "avg_pkt_size_range": (800, 1500),
        "pkt_size_stddev_min": 200,
        "typical_ports": {443, 8080, 8443},
        "min_packets": 10,
        "min_bytes": 50000,
        "description": "Large packet sizes with high variance (video chunks)"
    },
    "Audio Streaming": {
        "avg_pkt_size_range": (200, 800),
        "pkt_size_stddev_min": 50,
        "typical_ports": {443, 8080},
        "min_packets": 10,
        "min_bytes": 10000,
        "description": "Medium packet sizes, steady rate (audio chunks)"
    },
    "Web Browsing": {
        "avg_pkt_size_range": (100, 600),
        "pkt_size_stddev_min": 100,
        "typical_ports": {80, 443, 8080},
        "min_packets": 3,
        "min_bytes": 500,
        "description": "Variable sizes, burst patterns (page loads)"
    },
    "Messaging": {
        "avg_pkt_size_range": (60, 300),
        "pkt_size_stddev_min": 30,
        "typical_ports": {443, 5222, 5223},
        "min_packets": 2,
        "min_bytes": 100,
        "description": "Small packets, irregular intervals (chat messages)"
    },
    "File Transfer": {
        "avg_pkt_size_range": (1200, 1500),
        "pkt_size_stddev_min": 10,
        "typical_ports": {443, 22, 21, 990},
        "min_packets": 20,
        "min_bytes": 100000,
        "description": "Consistently large packets (file segments)"
    },
    "DNS/Lookup": {
        "avg_pkt_size_range": (40, 200),
        "pkt_size_stddev_min": 10,
        "typical_ports": {53, 853, 5353},
        "min_packets": 1,
        "min_bytes": 40,
        "description": "Very small packets, single request-response"
    },
    "VPN/Tunnel": {
        "avg_pkt_size_range": (100, 1500),
        "pkt_size_stddev_min": 300,
        "typical_ports": {443, 1194, 1723, 500, 4500},
        "min_packets": 10,
        "min_bytes": 5000,
        "description": "Encapsulated traffic with high entropy"
    },
}


class MLClassifier:
    """
    Statistical/heuristic classifier for encrypted traffic.
    Extracts flow features and scores against known app profiles.
    """

    def __init__(self):
        self.classifications: List[dict] = []

    def classify_flows(self, flows: dict) -> List[dict]:
        """Classify all unclassified flows using flow features."""
        self.classifications = []

        for flow_id, flow in flows.items():
            # Only classify unclassified flows
            if flow.classified and flow.app_type not in ("Unknown", "HTTPS", "HTTP"):
                self.classifications.append({
                    "flow_id": flow_id,
                    "classified_as": flow.app_type,
                    "method": "SNI/Host",
                    "confidence": 0.95,
                    "features": {},
                })
                continue

            features = self._extract_features(flow)
            classification = self._score_against_profiles(features, flow)

            self.classifications.append({
                "flow_id": flow_id,
                "classified_as": classification["app_category"],
                "method": "ML/Heuristic",
                "confidence": classification["confidence"],
                "features": features,
                "scores": classification.get("all_scores", {}),
                "sni": flow.sni,
                "original_app": flow.app_type,
            })

        return self.classifications

    def get_summary(self) -> dict:
        """Get classification summary statistics."""
        method_counts = defaultdict(int)
        category_counts = defaultdict(int)
        confidence_sum = 0
        total = len(self.classifications)

        for c in self.classifications:
            method_counts[c["method"]] += 1
            category_counts[c["classified_as"]] += 1
            confidence_sum += c["confidence"]

        return {
            "total_flows": total,
            "avg_confidence": round(confidence_sum / max(total, 1), 3),
            "by_method": dict(method_counts),
            "by_category": dict(sorted(category_counts.items(), key=lambda x: -x[1])),
            "classifications": self.classifications[:50],  # Top 50
        }

    # ── Feature Extraction ─────────────────────────────────────────────────

    def _extract_features(self, flow) -> dict:
        """Extract statistical features from a flow."""
        pkt_sizes = flow.packet_sizes if flow.packet_sizes else [0]
        iats = flow.inter_arrival_times if flow.inter_arrival_times else [0]

        avg_size = sum(pkt_sizes) / max(len(pkt_sizes), 1)
        size_stddev = self._stddev(pkt_sizes)

        avg_iat = sum(iats) / max(len(iats), 1)
        iat_stddev = self._stddev(iats)

        return {
            "packet_count": flow.packets,
            "total_bytes": flow.bytes_total,
            "avg_packet_size": round(avg_size, 1),
            "packet_size_stddev": round(size_stddev, 1),
            "min_packet_size": min(pkt_sizes) if pkt_sizes else 0,
            "max_packet_size": max(pkt_sizes) if pkt_sizes else 0,
            "avg_inter_arrival_ms": round(avg_iat * 1000, 2),
            "iat_stddev_ms": round(iat_stddev * 1000, 2),
            "duration_sec": round(flow.duration(), 3),
            "bytes_per_sec": round(flow.bytes_total / max(flow.duration(), 0.001), 1),
            "dst_port": flow.key.dst_port if flow.key else 0,
        }

    # ── Profile Scoring ────────────────────────────────────────────────────

    def _score_against_profiles(self, features: dict, flow) -> dict:
        """Score flow features against known app profiles."""
        scores = {}

        for profile_name, profile in APP_PROFILES.items():
            score = 0.0
            max_score = 0.0

            # Average packet size match
            lo, hi = profile["avg_pkt_size_range"]
            max_score += 3.0
            if lo <= features["avg_packet_size"] <= hi:
                score += 3.0
            elif features["avg_packet_size"] < lo:
                score += max(0, 3.0 - (lo - features["avg_packet_size"]) / 200)
            else:
                score += max(0, 3.0 - (features["avg_packet_size"] - hi) / 200)

            # Packet size stddev
            max_score += 2.0
            if features["packet_size_stddev"] >= profile["pkt_size_stddev_min"]:
                score += 2.0
            else:
                score += max(0, 2.0 * features["packet_size_stddev"] / max(profile["pkt_size_stddev_min"], 1))

            # Port match
            max_score += 2.0
            if features["dst_port"] in profile["typical_ports"]:
                score += 2.0

            # Volume requirements
            max_score += 1.5
            if features["packet_count"] >= profile["min_packets"]:
                score += 0.75
            if features["total_bytes"] >= profile["min_bytes"]:
                score += 0.75

            # Normalize
            confidence = round(score / max(max_score, 1), 3)
            scores[profile_name] = confidence

        # Best match
        best = max(scores.items(), key=lambda x: x[1])
        return {
            "app_category": best[0] if best[1] > 0.4 else "Unknown",
            "confidence": best[1],
            "all_scores": scores,
        }

    # ── Helpers ─────────────────────────────────────────────────────────────

    @staticmethod
    def _stddev(values: list) -> float:
        if len(values) < 2:
            return 0.0
        mean = sum(values) / len(values)
        variance = sum((v - mean) ** 2 for v in values) / (len(values) - 1)
        return math.sqrt(variance)

    @staticmethod
    def _entropy(data: bytes) -> float:
        """Calculate Shannon entropy of byte data."""
        if not data:
            return 0.0
        freq = defaultdict(int)
        for byte in data:
            freq[byte] += 1
        length = len(data)
        return -sum((c / length) * math.log2(c / length) for c in freq.values() if c > 0)
