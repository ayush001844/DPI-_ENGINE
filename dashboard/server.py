"""
server.py — DPI Engine Web Dashboard Backend
Flask server providing REST API and Server-Sent Events for the real-time dashboard.
"""

import os
import sys
import json
import time
import threading
import queue
import ipaddress
from pathlib import Path

from flask import Flask, request, jsonify, send_from_directory, Response, send_file
from flask_cors import CORS
from werkzeug.utils import secure_filename

from pcap_analyzer import PcapAnalyzer
from anomaly_detector import AnomalyDetector
from flow_replayer import FlowReplayer
from ml_classifier import MLClassifier

# ── App Setup ──────────────────────────────────────────────────────────────
app = Flask(__name__, static_folder="static", static_url_path="/static")
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024  # 50 MB limit
CORS(app)

# Project root (parent of dashboard/)
PROJECT_ROOT = Path(__file__).resolve().parent.parent
UPLOAD_DIR = Path(__file__).resolve().parent / "uploads"
UPLOAD_DIR.mkdir(exist_ok=True)

# Global state
analyzer = PcapAnalyzer()
anomaly_detector = AnomalyDetector()
flow_replayer = FlowReplayer()
ml_classifier = MLClassifier()
current_analysis = None
live_events = queue.Queue(maxsize=500)
live_replay_active = False


def load_default_analysis():
    """Load and analyze default test_dpi.pcap on startup so all endpoints are populated."""
    global current_analysis
    pcap_path = PROJECT_ROOT / "test_dpi.pcap"
    if pcap_path.exists():
        try:
            stats = analyzer.analyze(str(pcap_path))
            anomalies = anomaly_detector.analyze(analyzer.packets, analyzer.flows)
            flow_data = flow_replayer.extract_flows(analyzer.packets)
            ml_classifier.classify_flows(analyzer.flows)
            ml_summary = ml_classifier.get_summary()
            current_analysis = {
                "filename": "test_dpi.pcap",
                "stats": stats,
                "anomalies": anomalies,
                "flow_replay": flow_data,
                "ml_classification": ml_summary,
                "timestamp": time.time(),
            }
            return current_analysis
        except Exception as e:
            print(f"[Server] Failed to load default analysis: {e}", file=sys.stderr)
    return None


# Pre-load default dataset on startup
load_default_analysis()


# ── Static Routes ──────────────────────────────────────────────────────────

@app.route("/")
def index():
    if request.args.get("view") == "sidebar":
        return send_from_directory("static", "index.html")
    if (PROJECT_ROOT / "index.html").exists():
        return send_file(PROJECT_ROOT / "index.html")
    return send_from_directory("static", "index.html")


@app.route("/soc")
@app.route("/dashboard")
def soc_dashboard():
    if (PROJECT_ROOT / "index.html").exists():
        return send_file(PROJECT_ROOT / "index.html")
    return send_from_directory("static", "index.html")


@app.route("/sidebar")
def sidebar_view():
    return send_from_directory("static", "index.html")


@app.route("/static/<path:path>")
def static_files(path):
    return send_from_directory("static", path)


# ── API: PCAP Analysis ────────────────────────────────────────────────────

@app.route("/api/analyze", methods=["POST"])
def analyze_pcap():
    """Analyze an uploaded PCAP file or use existing test file."""
    global current_analysis

    filepath = None

    # Check for uploaded file with path traversal protection
    if "file" in request.files:
        f = request.files["file"]
        if f and f.filename:
            safe_name = secure_filename(f.filename)
            if not safe_name.lower().endswith((".pcap", ".pcapng", ".cap")):
                return jsonify({"error": "Invalid file extension. Only .pcap, .pcapng, and .cap files are permitted."}), 400
            filepath = str(UPLOAD_DIR / safe_name)
            f.save(filepath)

    # Or use specified file from project root or uploads dir
    if not filepath:
        filename = request.form.get("filename", "test_dpi.pcap")
        safe_filename = os.path.basename(filename)
        candidate = PROJECT_ROOT / safe_filename
        if not candidate.exists():
            candidate = UPLOAD_DIR / safe_filename
        filepath = str(candidate)

    if not os.path.exists(filepath):
        return jsonify({"error": f"File not found: {os.path.basename(filepath)}"}), 404

    try:
        # Run analysis
        stats = analyzer.analyze(filepath)

        # Run anomaly detection
        anomalies = anomaly_detector.analyze(analyzer.packets, analyzer.flows)

        # Extract flows for replay
        flow_data = flow_replayer.extract_flows(analyzer.packets)

        # Run ML classification
        ml_results = ml_classifier.classify_flows(analyzer.flows)
        ml_summary = ml_classifier.get_summary()

        current_analysis = {
            "stats": stats,
            "anomalies": anomalies,
            "flow_replay": flow_data,
            "ml_classification": ml_summary,
            "filename": os.path.basename(filepath),
            "timestamp": time.time(),
        }

        return jsonify(current_analysis)

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/analysis")
def get_full_analysis():
    """Get complete analysis object (stats, anomalies, flows, ML) in a single request."""
    if not current_analysis:
        load_default_analysis()
    if current_analysis:
        return jsonify(current_analysis)
    return jsonify({"error": "No analysis loaded"}), 404


@app.route("/api/stats")
def get_stats():
    """Get current analysis stats."""
    if not current_analysis:
        load_default_analysis()
    if current_analysis:
        return jsonify(current_analysis["stats"])
    return jsonify({"error": "No analysis loaded"}), 404


# ── API: Anomaly Detection ─────────────────────────────────────────────────

@app.route("/api/anomalies")
def get_anomalies():
    """Get detected anomalies."""
    if not current_analysis:
        load_default_analysis()
    if current_analysis:
        return jsonify({
            "anomalies": current_analysis["anomalies"],
            "total": len(current_analysis["anomalies"])
        })
    return jsonify({"anomalies": [], "total": 0})


# ── API: Flow Replay ──────────────────────────────────────────────────────

@app.route("/api/flows")
def get_flows():
    """Get flow list for replay."""
    if not current_analysis:
        load_default_analysis()
    if current_analysis:
        return jsonify(current_analysis["flow_replay"])
    return jsonify({"flows": [], "total_flows": 0})


@app.route("/api/flows/<path:flow_id>")
def get_flow_detail(flow_id):
    """Get detailed packet-by-packet view of a flow."""
    detail = flow_replayer.get_flow_detail(flow_id, analyzer.packets)
    if detail:
        return jsonify(detail)
    return jsonify({"error": "Flow not found"}), 404


@app.route("/api/flows/<path:flow_id>/pcap")
def download_flow_pcap(flow_id):
    """Download a single flow as a PCAP file."""
    pcap_data = flow_replayer.generate_flow_pcap(flow_id, analyzer.packets)
    if pcap_data:
        import io
        return send_file(
            io.BytesIO(pcap_data),
            mimetype="application/octet-stream",
            as_attachment=True,
            download_name=f"flow_{flow_id.replace('/', '_').replace('<->', '_')}.pcap"
        )
    return jsonify({"error": "Flow not found"}), 404


# ── API: ML Classification ─────────────────────────────────────────────────

@app.route("/api/ml/classify")
def get_ml_classification():
    """Get ML classification results."""
    if not current_analysis:
        load_default_analysis()
    if current_analysis:
        return jsonify(current_analysis["ml_classification"])
    return jsonify({"total_flows": 0, "classifications": [], "avg_confidence": 0.0})


# ── API: Blocking Rules ───────────────────────────────────────────────────

@app.route("/api/rules", methods=["GET"])
def get_rules():
    """Get current blocking rules."""
    return jsonify({
        "blocked_ips": list(analyzer.blocked_ips),
        "blocked_apps": list(analyzer.blocked_apps),
        "blocked_domains": list(analyzer.blocked_domains),
    })


@app.route("/api/rules", methods=["POST"])
def add_rule():
    """Add a blocking rule."""
    data = request.json or {}
    rule_type = data.get("type")
    value = (data.get("value") or data.get("target") or "").strip()

    if not value:
        return jsonify({"error": "Value required"}), 400

    if rule_type == "ip":
        try:
            ipaddress.ip_address(value)
            analyzer.blocked_ips.add(value)
        except ValueError:
            return jsonify({"error": f"Invalid IP address format: {value}"}), 400
    elif rule_type == "app":
        analyzer.blocked_apps.add(value)
    elif rule_type == "domain":
        clean_dom = value.lower().strip()
        if clean_dom not in analyzer.blocked_domains:
            analyzer.blocked_domains.append(clean_dom)
    else:
        return jsonify({"error": "Invalid rule type"}), 400

    return jsonify({"status": "ok", "message": f"Blocked {rule_type}: {value}"}), 201


@app.route("/api/rules", methods=["DELETE"])
def remove_rule():
    """Remove a blocking rule."""
    data = request.json
    rule_type = data.get("type")
    value = data.get("value", "").strip()

    if rule_type == "ip":
        analyzer.blocked_ips.discard(value)
    elif rule_type == "app":
        analyzer.blocked_apps.discard(value)
    elif rule_type == "domain":
        if value in analyzer.blocked_domains:
            analyzer.blocked_domains.remove(value)

    return jsonify({"status": "ok", "message": f"Unblocked {rule_type}: {value}"})


# ── API: Live Replay (Simulated Live Capture) ─────────────────────────────

@app.route("/api/live/start", methods=["POST"])
def start_live_replay():
    """Start replaying PCAP packets as a simulated live feed."""
    global live_replay_active

    if live_replay_active:
        return jsonify({"status": "already_running"})

    if not analyzer.packets:
        return jsonify({"error": "No PCAP loaded. Analyze a file first."}), 400

    live_replay_active = True

    def replay_thread():
        global live_replay_active
        packets = analyzer.packets
        total = len(packets)

        cumulative_stats = {
            "packets": 0, "bytes": 0, "tcp": 0, "udp": 0,
            "forwarded": 0, "dropped": 0,
            "apps": {},
        }

        for i, pkt in enumerate(packets):
            if not live_replay_active:
                break

            cumulative_stats["packets"] += 1
            cumulative_stats["bytes"] += pkt.length
            if pkt.protocol == 6:
                cumulative_stats["tcp"] += 1
            elif pkt.protocol == 17:
                cumulative_stats["udp"] += 1

            event = {
                "type": "packet",
                "index": i,
                "total": total,
                "progress": round(100 * (i + 1) / total, 1),
                "packet": {
                    "src_ip": pkt.src_ip,
                    "dst_ip": pkt.dst_ip,
                    "src_port": pkt.src_port,
                    "dst_port": pkt.dst_port,
                    "protocol": "TCP" if pkt.protocol == 6 else "UDP" if pkt.protocol == 17 else "Other",
                    "length": pkt.length,
                    "timestamp": pkt.timestamp,
                },
                "cumulative": dict(cumulative_stats),
            }

            try:
                live_events.put_nowait(json.dumps(event))
            except queue.Full:
                try:
                    live_events.get_nowait()
                    live_events.put_nowait(json.dumps(event))
                except queue.Empty:
                    pass

            # Simulate real-time delay (compressed)
            time.sleep(0.05)

        # Send completion event
        try:
            live_events.put_nowait(json.dumps({"type": "complete", "stats": cumulative_stats}))
        except queue.Full:
            pass
        live_replay_active = False

    thread = threading.Thread(target=replay_thread, daemon=True)
    thread.start()

    return jsonify({"status": "started", "total_packets": len(analyzer.packets)})


@app.route("/api/live/stop", methods=["POST"])
def stop_live_replay():
    """Stop the live replay."""
    global live_replay_active
    live_replay_active = False
    return jsonify({"status": "stopped"})


@app.route("/api/live/stream")
def live_stream():
    """Server-Sent Events stream for live packet replay."""
    def event_stream():
        while True:
            try:
                data = live_events.get(timeout=1)
                yield f"data: {data}\n\n"
            except queue.Empty:
                yield f"data: {json.dumps({'type': 'heartbeat'})}\n\n"

    return Response(event_stream(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# ── API: System Info ──────────────────────────────────────────────────────

@app.route("/api/info")
def system_info():
    """Get system information."""
    test_pcap = PROJECT_ROOT / "test_dpi.pcap"
    return jsonify({
        "status": "ready",
        "version": "3.0",
        "engine": "DPI Engine — Advanced Dashboard",
        "features": [
            "Deep Packet Inspection",
            "Anomaly Detection",
            "Flow Replay",
            "ML Classification",
            "Live Capture Simulation",
            "Rule-based Blocking",
        ],
        "test_pcap_available": test_pcap.exists(),
        "test_pcap_size": test_pcap.stat().st_size if test_pcap.exists() else 0,
        "has_analysis": current_analysis is not None,
        "live_active": live_replay_active,
    })


# ── Main ──────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("  DPI Engine — Advanced Web Dashboard v3.0")
    print("=" * 60)
    print(f"  Project root: {PROJECT_ROOT}")
    print(f"  Dashboard: http://localhost:8080")
    print("=" * 60 + "\n")

    debug_mode = os.environ.get("FLASK_ENV") != "production" and os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(host="0.0.0.0", port=8080, debug=debug_mode, threaded=True)
