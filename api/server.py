"""
FastAPI Server & Real-Time Detection Pipeline Orchestrator:
Runs the continuous NIDS analysis loop, manages WebSockets, and hosts the cyber SOC dashboard.
"""
import time
import json
import asyncio
import threading
from pathlib import Path
from typing import List, Dict, Any

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware

from config.settings import (
    DEFAULT_HOST,
    DEFAULT_PORT,
    DEFAULT_INTERFACE,
    FLOW_TIMEOUT_SECONDS,
    FLOW_TICK_INTERVAL,
    BASE_DIR
)
from capture.flow_manager import FlowManager
from capture.packet_capture import PacketCapture
from features.extractor import FeatureExtractor
from detection.signature_engine import SignatureEngine
from detection.anomaly_detector import AnomalyDetector
from detection.classifier import AttackClassifier
from decision.fusion_engine import FusionEngine
from mitigation.qos_controller import QoSController
from alerts.alert_manager import AlertManager
from simulator.traffic_generator import TrafficGenerator
from api.routes import router as api_router, system_context

app = FastAPI(title="Hybrid NIDS & Adaptive QoS Mitigation System", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Active WebSocket connections
connected_websockets: List[WebSocket] = []
ws_lock = asyncio.Lock()

# Subsystem instances
flow_manager = FlowManager(timeout_seconds=FLOW_TIMEOUT_SECONDS)
packet_capture = PacketCapture(flow_manager=flow_manager, interface=DEFAULT_INTERFACE)
signature_engine = SignatureEngine()
anomaly_detector = AnomalyDetector()
attack_classifier = AttackClassifier()
fusion_engine = FusionEngine()
qos_controller = QoSController()
alert_manager = AlertManager()
traffic_generator = TrafficGenerator(packet_capture=packet_capture)

# Share instances with routes
system_context["flow_manager"] = flow_manager
system_context["packet_capture"] = packet_capture
system_context["signature_engine"] = signature_engine
system_context["anomaly_detector"] = anomaly_detector
system_context["attack_classifier"] = attack_classifier
system_context["fusion_engine"] = fusion_engine
system_context["qos_controller"] = qos_controller
system_context["alert_manager"] = alert_manager
system_context["traffic_generator"] = traffic_generator

# Telemetry snapshot for streaming
latest_telemetry = {
    "pps": 0.0,
    "bps": 0.0,
    "total_packets": 0,
    "total_bytes": 0,
    "active_flows": 0,
    "recent_flows": [],
    "recent_alerts": [],
    "active_mitigations": []
}

def analysis_pipeline_loop():
    """
    Continuous background loop:
    Evaluates all active flows through Signature Engine, ML Anomaly Detector, and Fusion Layer,
    applies adaptive QoS mitigation when risk is elevated, and runs the feedback loop.
    """
    prev_packets = 0
    prev_bytes = 0
    prev_time = time.time()

    while True:
        try:
            now = time.time()
            elapsed = max(0.001, now - prev_time)
            prev_time = now

            # 1. Compute instantaneous network rates
            curr_packets = flow_manager.total_packets_processed
            curr_bytes = flow_manager.total_bytes_processed
            delta_pkts = curr_packets - prev_packets
            delta_bytes = curr_bytes - prev_bytes
            prev_packets = curr_packets
            prev_bytes = curr_bytes

            pps = delta_pkts / elapsed
            bps = (delta_bytes * 8) / elapsed  # bits per second

            # 2. Extract and evaluate active flows
            active_flows = flow_manager.get_active_flows()
            analyzed_flows = []

            for flow in active_flows:
                src_ip = flow["src_ip"]
                dst_ip = flow["dst_ip"]
                src_stats = flow_manager.src_stats.get(src_ip, {})

                # Feature extraction
                features = FeatureExtractor.extract_features(flow, src_stats=src_stats)

                # Signature detection
                sig_res = signature_engine.evaluate(flow, features, src_stats=src_stats)

                # ML Anomaly detection (Isolation Forest)
                ml_res = anomaly_detector.score_flow(features)

                # Supervised Classification (Random Forest)
                rf_res = attack_classifier.classify_flow(features)

                # Fusion Layer
                decision = fusion_engine.fuse(sig_res, ml_res, rf_res)

                # If alert-worthy threat detected
                if decision["is_alert_worthy"]:
                    alert = alert_manager.create_alert(
                        source_ip=src_ip,
                        destination_ip=dst_ip,
                        source_port=flow["src_port"],
                        destination_port=flow["dst_port"],
                        protocol=flow["protocol"],
                        attack_type=decision["attack_type"],
                        signature_result=sig_res["rule_id"] or "NO_SIGNATURE",
                        ml_result=f"ANOMALY ({decision['ml_anomaly_score']:.1f})" if ml_res["is_anomaly"] else "NORMAL",
                        risk_score=decision["risk_score"],
                        severity=decision["severity"],
                        action=decision["action"],
                        details=f"{decision['explanation']} | Flow: {flow['packets']} pkts, {features['packets_per_sec']:.1f} PPS"
                    )

                    # Trigger Adaptive QoS Mitigation
                    qos_controller.apply_mitigation(
                        src_ip=src_ip,
                        risk_score=decision["risk_score"],
                        attack_type=decision["attack_type"],
                        severity=decision["severity"],
                        reason=decision["explanation"]
                    )

                analyzed_flows.append({
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "src_port": flow["src_port"],
                    "dst_port": flow["dst_port"],
                    "protocol": flow["protocol"],
                    "packets": flow["packets"],
                    "bytes": flow["bytes"],
                    "pps": round(features["packets_per_sec"], 1),
                    "risk_score": decision["risk_score"],
                    "severity": decision["severity"],
                    "attack_type": decision["attack_type"],
                    "agreement_type": decision["agreement_type"]
                })

            # 3. Dynamic Feedback Loop evaluation
            feedback_actions = qos_controller.process_feedback_loop()

            # 4. Cleanup expired flows
            flow_manager.cleanup_expired_flows()

            # 5. Update global telemetry snapshot
            latest_telemetry["pps"] = round(pps, 1)
            latest_telemetry["bps"] = round(bps, 1)
            latest_telemetry["total_packets"] = curr_packets
            latest_telemetry["total_bytes"] = curr_bytes
            latest_telemetry["active_flows"] = len(active_flows)
            latest_telemetry["recent_flows"] = analyzed_flows[:20]
            latest_telemetry["recent_alerts"] = alert_manager.get_recent_alerts(limit=15)
            latest_telemetry["active_mitigations"] = qos_controller.get_active_mitigations()

        except Exception as e:
            print(f"[Pipeline Loop Error] {e}")

        time.sleep(FLOW_TICK_INTERVAL)

@app.on_event("startup")
async def startup_event():
    # Start analysis loop in background daemon thread
    pipeline_thread = threading.Thread(target=analysis_pipeline_loop, daemon=True)
    pipeline_thread.start()

    # Start benign background traffic simulation by default so dashboard starts alive
    traffic_generator.start_background_benign_traffic(delay_range=(0.4, 0.9))

    # Try starting live sniffing if configured/permitted
    if DEFAULT_INTERFACE != "none":
        try:
            packet_capture.start_live_capture()
        except Exception as e:
            print(f"[Startup] Live capture warning: {e}")

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    connected_websockets.append(websocket)
    try:
        while True:
            # Stream latest telemetry frame every 1 second
            payload = {
                "timestamp": time.time(),
                "telemetry": latest_telemetry,
                "stats": alert_manager.get_alert_stats()
            }
            await websocket.send_text(json.dumps(payload))
            await asyncio.sleep(1.0)
    except (WebSocketDisconnect, asyncio.CancelledError):
        pass
    finally:
        if websocket in connected_websockets:
            connected_websockets.remove(websocket)

# Include API routes
app.include_router(api_router, prefix="/api")

# Static files for dashboard
dashboard_path = BASE_DIR / "dashboard"
if dashboard_path.exists():
    app.mount("/static", StaticFiles(directory=str(dashboard_path)), name="static")

@app.api_route("/", methods=["GET", "HEAD"])
def get_dashboard():
    index_file = BASE_DIR / "dashboard" / "index.html"
    if index_file.exists():
        return FileResponse(index_file)
    return {"message": "Hybrid NIDS API Server Online. Dashboard files not found."}
