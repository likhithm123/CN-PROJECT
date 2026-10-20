"""
API REST Endpoints for Hybrid NIDS and QoS Mitigation.
"""
from fastapi import APIRouter, HTTPException, BackgroundTasks, UploadFile, File
import shutil
from pathlib import Path
from pydantic import BaseModel
from typing import Dict, Any, List, Optional
from capture.pcap_analyzer import PCAPAnalyzer

router = APIRouter()

# Global references injected from server.py
system_context = {}

class AttackRequest(BaseModel):
    attack_type: str  # "port_scan", "syn_flood", "icmp_flood", "udp_flood", "zero_day"
    attacker_ip: Optional[str] = None
    target_ip: Optional[str] = None
    count: Optional[int] = None

class OverrideRequest(BaseModel):
    ip: str
    tier: str  # "NORMAL", "SUSPICIOUS", "HIGH", "CRITICAL"

@router.get("/status")
def get_system_status():
    """Return overall operational status of all NIDS subcomponents."""
    flow_mgr = system_context.get("flow_manager")
    qos_ctrl = system_context.get("qos_controller")
    alert_mgr = system_context.get("alert_manager")
    traffic_gen = system_context.get("traffic_generator")

    stats = alert_mgr.get_alert_stats() if alert_mgr else {}
    active_flows = len(flow_mgr.flows) if flow_mgr else 0
    active_qos = qos_ctrl.get_active_mitigations() if qos_ctrl else []

    return {
        "status": "ONLINE",
        "live_capture_active": system_context.get("packet_capture", {}).is_running,
        "background_traffic_active": traffic_gen.is_background_running if traffic_gen else False,
        "active_flows_count": active_flows,
        "total_packets_processed": flow_mgr.total_packets_processed if flow_mgr else 0,
        "total_bytes_processed": flow_mgr.total_bytes_processed if flow_mgr else 0,
        "alerts_summary": stats,
        "active_mitigations_count": len(active_qos),
        "qos_driver": "Linux tc (Kernel)" if qos_ctrl and qos_ctrl.linux_driver and qos_ctrl.linux_driver.is_initialized else "Cross-Platform Virtual QoS"
    }

@router.get("/alerts")
def get_alerts(limit: int = 50):
    """Fetch latest security alerts recorded by NIDS."""
    alert_mgr = system_context.get("alert_manager")
    if not alert_mgr:
        return []
    return alert_mgr.get_recent_alerts(limit=limit)

@router.get("/qos/policies")
def get_qos_policies():
    """Fetch active QoS mitigation policies and rate limits."""
    qos_ctrl = system_context.get("qos_controller")
    if not qos_ctrl:
        return []
    return qos_ctrl.get_active_mitigations()

@router.post("/qos/override")
def override_qos(req: OverrideRequest):
    """Manually apply or clear a QoS mitigation policy on an IP."""
    qos_ctrl = system_context.get("qos_controller")
    if not qos_ctrl:
        raise HTTPException(status_code=500, detail="QoS Controller uninitialized")
    res = qos_ctrl.manual_override(req.ip, req.tier)
    return {"status": "success", "result": res}

@router.post("/simulation/attack")
def trigger_attack_simulation(req: AttackRequest, background_tasks: BackgroundTasks):
    """Trigger a live attack sequence for demonstrations."""
    traffic_gen = system_context.get("traffic_generator")
    if not traffic_gen:
        raise HTTPException(status_code=500, detail="Traffic generator uninitialized")

    atype = req.attack_type.lower()
    attacker = req.attacker_ip or "10.0.2.15"
    target = req.target_ip or "10.0.2.30"
    count = req.count

    if atype in ["port_scan", "portscan"]:
        background_tasks.add_task(traffic_gen.simulate_port_scan, attacker, target, count or 16)
    elif atype in ["syn_flood", "synflood"]:
        background_tasks.add_task(traffic_gen.simulate_syn_flood, attacker, target, count or 60)
    elif atype in ["icmp_flood", "icmpflood", "ping"]:
        background_tasks.add_task(traffic_gen.simulate_icmp_flood, attacker, target, count or 40)
    elif atype in ["udp_flood", "udpflood"]:
        background_tasks.add_task(traffic_gen.simulate_udp_flood, attacker, target, count or 50)
    elif atype in ["zero_day", "anomaly"]:
        background_tasks.add_task(traffic_gen.simulate_zero_day_anomaly, attacker, target, count or 30)
    else:
        raise HTTPException(status_code=400, detail=f"Unknown attack type: {req.attack_type}")

    return {
        "status": "triggered",
        "attack_type": atype,
        "attacker_ip": attacker,
        "target_ip": target
    }

@router.post("/simulation/toggle_traffic")
def toggle_background_traffic():
    """Toggle normal background benign traffic generator on/off."""
    traffic_gen = system_context.get("traffic_generator")
    if not traffic_gen:
        raise HTTPException(status_code=500, detail="Traffic generator uninitialized")

    if traffic_gen.is_background_running:
        traffic_gen.stop_background_benign_traffic()
        state = "STOPPED"
    else:
        traffic_gen.start_background_benign_traffic()
        state = "STARTED"

    return {"status": "success", "traffic_state": state}

@router.post("/pcap/upload")
async def upload_and_analyze_pcap(file: UploadFile = File(...)):
    """Upload and analyze a Wireshark PCAP or PCAPNG file for offline forensics."""
    filename = file.filename or "uploaded.pcap"
    upload_dir = Path("uploads")
    upload_dir.mkdir(parents=True, exist_ok=True)
    dest_path = upload_dir / filename

    with open(dest_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    analyzer = PCAPAnalyzer(
        sig_engine=system_context.get("signature_engine"),
        anomaly_detector=system_context.get("anomaly_detector"),
        classifier=system_context.get("attack_classifier") or system_context.get("classifier"),
        fusion_engine=system_context.get("fusion_engine"),
        alert_manager=system_context.get("alert_manager")
    )

    try:
        results = analyzer.analyze_file(str(dest_path))
        return results
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"PCAP analysis failed: {str(e)}")

@router.get("/pcap/samples")
def list_sample_pcaps():
    """List bundled Wireshark PCAP/PCAPNG test traces."""
    sample_dir = Path("uploads/sample_pcaps")
    if not sample_dir.exists():
        return []
    samples = []
    for f in sample_dir.glob("*.*"):
        if f.suffix.lower() in [".pcap", ".pcapng"]:
            samples.append({
                "filename": f.name,
                "size_bytes": f.stat().st_size,
                "extension": f.suffix.lower()
            })
    return samples

@router.post("/pcap/analyze-sample")
def analyze_sample_pcap(filename: str):
    """Run full forensics on a pre-loaded sample PCAP file."""
    sample_path = Path("uploads/sample_pcaps") / filename
    if not sample_path.exists():
        raise HTTPException(status_code=404, detail="Sample PCAP file not found")

    analyzer = PCAPAnalyzer(
        sig_engine=system_context.get("signature_engine"),
        anomaly_detector=system_context.get("anomaly_detector"),
        classifier=system_context.get("attack_classifier") or system_context.get("classifier"),
        fusion_engine=system_context.get("fusion_engine"),
        alert_manager=system_context.get("alert_manager")
    )
    try:
        return analyzer.analyze_file(str(sample_path))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to analyze sample PCAP: {str(e)}")

