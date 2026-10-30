"""
export_analysis.py — Export authentic analysis of test_dpi.pcap
Traces and records the real pipeline metrics across all components.
"""

import json
import os
import sys
from pathlib import Path

# Paths
DASHBOARD_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = DASHBOARD_DIR.parent
sys.path.insert(0, str(DASHBOARD_DIR))

from pcap_analyzer import PcapAnalyzer
from anomaly_detector import AnomalyDetector
from flow_replayer import FlowReplayer
from ml_classifier import MLClassifier

def main():
    pcap_path = PROJECT_ROOT / "test_dpi.pcap"
    if not pcap_path.exists():
        print(f"Error: {pcap_path} not found")
        sys.exit(1)

    print(f"Analyzing {pcap_path} ({pcap_path.stat().st_size} bytes)...")
    analyzer = PcapAnalyzer()
    stats = analyzer.analyze(str(pcap_path))

    detector = AnomalyDetector()
    anomalies = detector.analyze(analyzer.packets, analyzer.flows)

    replayer = FlowReplayer()
    flow_data = replayer.extract_flows(analyzer.packets)

    classifier = MLClassifier()
    classifier.classify_flows(analyzer.flows)
    ml_summary = classifier.get_summary()

    full_analysis = {
        "filename": "test_dpi.pcap",
        "stats": stats,
        "anomalies": anomalies,
        "flow_replay": flow_data,
        "ml_classification": ml_summary,
        "timestamp": 1700000000.0,
    }

    out_file = DASHBOARD_DIR / "analysis_test_dpi.json"
    with open(out_file, "w") as f:
        json.dump(full_analysis, f, indent=2)

    print("=== SUMMARY OF REAL ANALYSIS ===")
    print(f"Total Packets: {stats['summary']['total_packets']}")
    print(f"Total Bytes: {stats['summary']['total_bytes']}")
    print(f"Total Flows: {stats['summary']['total_flows']}")
    print(f"TCP Packets: {stats['summary']['tcp_packets']}")
    print(f"UDP Packets: {stats['summary']['udp_packets']}")
    print(f"Detected SNIs: {len(stats['detected_snis'])}")
    print(f"Top Talkers: {len(stats['top_talkers'])}")
    print(f"Anomalies Detected: {len(anomalies)}")
    print(f"Flow Replay Records: {len(flow_data.get('flows', []))}")
    print(f"ML Total Classified: {ml_summary.get('total_flows')}")
    print(f"ML Avg Confidence: {ml_summary.get('avg_confidence')}")
    print(f"Exported to {out_file}")

if __name__ == "__main__":
    main()
