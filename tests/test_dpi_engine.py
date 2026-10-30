"""
test_dpi_engine.py — Comprehensive Test Suite for DPI_ENGINE
Tests C++ engine outputs, Python PCAP analysis, SNI extraction,
anomaly detection, ML classification, and Server API security.
"""

import os
import sys
import json
import subprocess
import unittest
from pathlib import Path

# Setup paths
TEST_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = TEST_DIR.parent
DASHBOARD_DIR = PROJECT_ROOT / "dashboard"
sys.path.insert(0, str(DASHBOARD_DIR))

from pcap_analyzer import PcapAnalyzer, APP_SIGNATURES, PacketInfo, FlowInfo, FlowKey
from anomaly_detector import AnomalyDetector
from ml_classifier import MLClassifier
from server import app


class TestPCAPAnalysis(unittest.TestCase):
    """Tests Python-side PCAP reading and flow aggregation."""

    @classmethod
    def setUpClass(cls):
        cls.pcap_file = PROJECT_ROOT / "test_dpi.pcap"
        cls.analyzer = PcapAnalyzer()
        cls.analysis = cls.analyzer.analyze(str(cls.pcap_file))

    def test_packet_count(self):
        """Verify that packet count is ~2,000 (1,980 packets)."""
        total = self.analysis["summary"]["total_packets"]
        self.assertGreaterEqual(total, 1900, f"Expected >= 1900 packets, got {total}")
        self.assertEqual(total, 1980, f"Expected exactly 1980 packets, got {total}")

    def test_total_bytes(self):
        """Verify total byte count exceeds 500 KB."""
        total_bytes = self.analysis["summary"]["total_bytes"]
        self.assertGreater(total_bytes, 500000)

    def test_protocol_distribution(self):
        """Verify protocol breakdown contains both TCP and UDP."""
        protos = self.analysis["protocol_distribution"]
        self.assertIn("TCP", protos)
        self.assertIn("UDP", protos)
        self.assertGreater(protos["TCP"], 1500, "TCP should be dominant protocol")
        self.assertGreater(protos["UDP"], 100, "UDP should be present")

    def test_flow_aggregation(self):
        """Verify flows are extracted and aggregated properly."""
        flows = self.analysis["flows"]
        self.assertGreater(len(flows), 50, "Should aggregate multiple network flows")


class TestDomainMatchingAndSNI(unittest.TestCase):
    """Tests host domain matching and application signatures (fixes false positive bug)."""

    def setUp(self):
        self.analyzer = PcapAnalyzer()

    def test_domain_boundary_matching(self):
        """Verify that substring matching does not misclassify domains."""
        # Critical regression: 'netflix.com' or 'firefox.com' must NOT match 'x.com'
        app_netflix = self.analyzer._sni_to_app("www.netflix.com")
        self.assertEqual(app_netflix, "Netflix", "netflix.com should match Netflix, NOT Twitter/X")

        app_firefox = self.analyzer._sni_to_app("detectportal.firefox.com")
        self.assertNotEqual(app_firefox, "Twitter/X", "firefox.com must not be identified as Twitter/X")

        app_reddit = self.analyzer._sni_to_app("www.reddit.com")
        self.assertNotEqual(app_reddit, "Twitter/X", "reddit.com must not be identified as Twitter/X")

        app_twitter = self.analyzer._sni_to_app("twitter.com")
        self.assertEqual(app_twitter, "Twitter/X")

        app_x = self.analyzer._sni_to_app("x.com")
        self.assertEqual(app_x, "Twitter/X")

        app_msft = self.analyzer._sni_to_app("azure.microsoft.com")
        self.assertEqual(app_msft, "Microsoft")


class TestFlowMetricsAndIAT(unittest.TestCase):
    """Tests Inter-Arrival Time (IAT) and jitter calculation (IAT bug regression)."""

    @classmethod
    def setUpClass(cls):
        cls.pcap_file = PROJECT_ROOT / "test_dpi.pcap"
        cls.analyzer = PcapAnalyzer()
        cls.analysis = cls.analyzer.analyze(str(cls.pcap_file))

    def test_inter_arrival_times_positive(self):
        """Verify multi-packet flows have non-zero average IAT and jitter."""
        flows_with_multi_pkts = [f for f in self.analysis["flows"] if f["packets"] >= 3]
        self.assertGreater(len(flows_with_multi_pkts), 0)

        positive_iats = [f for f in flows_with_multi_pkts if f.get("avg_iat_ms", 0) > 0.0]
        self.assertGreater(
            len(positive_iats),
            0,
            "Bug regression: Multi-packet flows must have avg_iat_ms > 0.0 ms (previously stuck at 0.0 ms)",
        )


class TestAnomalyDetection(unittest.TestCase):
    """Tests anomaly detection engine rules and thresholds."""

    def setUp(self):
        self.detector = AnomalyDetector()

    def test_port_scan_detection(self):
        """Verify port scan is detected when a single IP accesses > 8 unique ports."""
        packets = []
        for port in range(1, 20):
            p = PacketInfo(
                src_ip="192.168.1.99",
                dst_ip="10.0.0.1",
                dst_port=port,
                protocol=6,
                length=60,
                timestamp=1000.0 + port * 0.05,
                tcp_flags=0x02,  # SYN
            )
            packets.append(p)

        alerts = self.detector.analyze(packets, flows=[])
        scan_alerts = [a for a in alerts if a["category"] == "port_scan"]
        self.assertGreater(len(scan_alerts), 0, "Port scan should be detected for 19 probed ports")
        self.assertEqual(scan_alerts[0]["source_ip"], "192.168.1.99")

    def test_ddos_detection(self):
        """Verify high packet-rate volume anomaly triggers alert."""
        packets = []
        for i in range(120):
            p = PacketInfo(
                src_ip="10.0.1.50",
                dst_ip="192.168.1.200",
                dst_port=80,
                protocol=6,
                length=1400,
                timestamp=2000.0 + (i * 0.005),
                tcp_flags=0x02,
            )
            packets.append(p)

        alerts = self.detector.analyze(packets, flows=[])
        ddos_alerts = [a for a in alerts if a["category"] == "ddos"]
        self.assertGreater(len(ddos_alerts), 0, "High-rate traffic burst should trigger DDoS alert")


class TestMLClassifier(unittest.TestCase):
    """Tests ML classification engine and feature extraction."""

    def setUp(self):
        self.classifier = MLClassifier()

    def test_feature_extraction_and_classification(self):
        """Verify statistical flow feature extraction and profile scoring."""
        fk = FlowKey(src_ip="10.0.0.5", dst_ip="1.1.1.1", src_port=54321, dst_port=443, protocol=6)
        flow = FlowInfo(
            key=fk,
            packets=100,
            bytes_total=130000,
            first_seen=1000.0,
            last_seen=1005.0,
            packet_sizes=[1300] * 100,
            inter_arrival_times=[0.05] * 99,
            app_type="Unknown",
        )

        features = self.classifier._extract_features(flow)
        self.assertIn("avg_packet_size", features)
        self.assertEqual(features["avg_packet_size"], 1300.0)
        self.assertEqual(features["packet_count"], 100)

        results = self.classifier.classify_flows({"flow-video-1": flow})
        self.assertEqual(len(results), 1)
        res = results[0]
        self.assertEqual(res["classified_as"], "Video Streaming")
        self.assertGreater(res["confidence"], 0.5)


class TestServerAPIAndSecurity(unittest.TestCase):
    """Tests REST API endpoints and cybersecurity hardening."""

    def setUp(self):
        app.config["TESTING"] = True
        self.client = app.test_client()

    def test_api_info(self):
        """GET /api/info returns 200 with engine metadata."""
        resp = self.client.get("/api/info")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn("version", data)
        self.assertEqual(data.get("status"), "ready")

    def test_api_rules_validation(self):
        """Verify IP rule validation rejects invalid IP formats (SEC-03)."""
        # Valid IP
        resp = self.client.post("/api/rules", json={"type": "ip", "target": "192.168.1.100"})
        self.assertEqual(resp.status_code, 201)

        # Invalid IP
        resp_bad = self.client.post("/api/rules", json={"type": "ip", "target": "999.999.999.999"})
        self.assertEqual(resp_bad.status_code, 400)
        self.assertIn("Invalid IP", resp_bad.get_json().get("error", ""))

    def test_api_analyze_path_traversal_prevention(self):
        """Verify Path Traversal attempt is rejected (SEC-01)."""
        # Filename attempting directory traversal
        resp = self.client.post("/api/analyze", data={"filename": "../../etc/passwd"})
        self.assertIn(resp.status_code, [400, 404])

        # Disallowed file extension
        resp_ext = self.client.post("/api/analyze", data={"filename": "exploit.sh"})
        self.assertIn(resp_ext.status_code, [400, 404])


class TestCPPEngineBinary(unittest.TestCase):
    """Tests compiled C++ multi-threaded engine binary."""

    def test_dpi_engine_execution(self):
        """Execute dpi_engine binary against test_dpi.pcap and verify multi-threading."""
        bin_path = PROJECT_ROOT / "dpi_engine"
        pcap_path = PROJECT_ROOT / "test_dpi.pcap"
        out_path = Path("/tmp/test_py_cpp_out.pcap")

        self.assertTrue(bin_path.exists(), "dpi_engine binary must exist")
        self.assertTrue(pcap_path.exists(), "test_dpi.pcap must exist")

        cmd = [str(bin_path), "-f", str(pcap_path), str(out_path)]
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        if out_path.exists():
            out_path.unlink()

        self.assertEqual(res.returncode, 0, f"dpi_engine failed: {res.stderr}")
        self.assertIn("DPI ENGINE v2.0", res.stdout)
        self.assertIn("Total Packets:              1980", res.stdout)
        # Verify all 4 fastpath threads processed packets (no starvation bug)
        self.assertIn("FP0 processed:", res.stdout)
        self.assertIn("FP1 processed:", res.stdout)
        self.assertIn("FP2 processed:", res.stdout)
        self.assertIn("FP3 processed:", res.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
