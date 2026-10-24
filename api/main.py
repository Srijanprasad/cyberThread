"""
FastAPI Backend Application for Unidirectional Threat Intelligence.
Exposes REST APIs for metrics, alerts, scenario triggers, and WebSocket telemetry stream.
"""

import os
import json
import time
import asyncio
from typing import Optional, List
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, UploadFile, File, Query, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse

from ingestion.schema import (
    SystemStatus,
    ThreatAlert,
    NetworkGraphState,
    PacketRecord,
)
from api.pipeline_manager import pipeline_manager
from traffic_simulator.scenario_manager import ScenarioManager
from ingestion.pcap_reader import PassivePCAPReader


app = FastAPI(
    title="CyberThread: AI Threat Intelligence for Unidirectional IP Traffic",
    description="Smart India Hackathon 2026 (Problem Statement 26145 - NTRO)",
    version="1.0.0",
)

# Enable CORS for local Vite dashboard
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

scenario_manager = ScenarioManager()


async def stream_packets_async(packets: List[PacketRecord], delay: float = 0.02):
    """Feeds packets through pipeline with pacing to emulate live tap."""
    for pkt in packets:
        alert = pipeline_manager.process_packet(pkt)
        # Broadcast immediately if alert was generated
        if alert:
            await pipeline_manager.broadcast({
                "type": "NEW_ALERT",
                "alert": alert.model_dump(),
            })
        await asyncio.sleep(delay)


@app.get("/api/status", response_model=SystemStatus)
def get_status():
    """Returns enclave operational status and data diode metrics."""
    return pipeline_manager.get_system_status()


@app.get("/api/alerts", response_model=List[ThreatAlert])
def get_alerts(
    severity: Optional[str] = None,
    threat_type: Optional[str] = None,
    limit: int = 50,
):
    """Returns detected threat alerts with full explainable evidence trails."""
    results = list(pipeline_manager.alerts)
    if severity:
        results = [a for a in results if a.severity.value == severity.upper()]
    if threat_type:
        results = [a for a in results if a.threat_type.value == threat_type.lower()]
    return results[:limit]


@app.get("/api/alerts/{alert_id}")
def get_alert_detail(alert_id: str):
    """Returns deep-dive investigation payload for a specific alert."""
    for alert in pipeline_manager.alerts:
        if alert.alert_id == alert_id:
            return alert.model_dump()
    return JSONResponse(status_code=404, content={"error": "Alert not found"})


@app.get("/api/graph", response_model=NetworkGraphState)
def get_graph():
    """Returns the temporal host relationship graph for visualization."""
    return pipeline_manager.graph.get_graph_state(max_nodes=40)


@app.get("/api/metrics")
def get_evaluation_metrics():
    """Returns model benchmark metrics and validation report."""
    report_path = "models/evaluation_report.json"
    if os.path.exists(report_path):
        with open(report_path, "r") as f:
            return json.load(f)
    return {"status": "Evaluation report not generated yet"}


@app.get("/api/ledger")
def get_ledger_blocks(limit: int = 30):
    """Returns append-only tamper-evident blockchain evidence ledger."""
    return pipeline_manager.ledger.get_recent_blocks(limit=limit)


@app.get("/api/ledger/verify")
def verify_ledger():
    """Validates cryptographic hash chain integrity."""
    return pipeline_manager.ledger.verify_chain_integrity()


@app.get("/api/ablation")
def get_ablation_benchmark():
    """Returns empirical one-way ablation study results."""
    report_path = "models/ablation_report.json"
    if os.path.exists(report_path):
        with open(report_path, "r") as f:
            return json.load(f)
    return {"status": "Ablation report not generated yet"}


@app.post("/api/traffic/simulate")
async def trigger_simulation(
    scenario: str = Query("port_scan", description="Scenario: port_scan, syn_flood, udp_flood, slowloris, dns_tunneling, c2_beaconing, benign, all"),
    intensity: int = Query(25, ge=5, le=150),
    background_tasks: BackgroundTasks = None,
):
    """
    Generates realistic benign + attack traffic and streams it live
    through the unidirectional monitoring pipeline.
    """
    packets = scenario_manager.generate_scenario(
        scenario_name=scenario,
        benign_count=20,
        attack_intensity=intensity,
    )

    # Launch streaming in background task
    asyncio.create_task(stream_packets_async(packets, delay=0.015))

    return {
        "status": "SIMULATION_INITIATED",
        "scenario": scenario,
        "packets_generated": len(packets),
        "message": f"Streaming {len(packets)} packets into unidirectional ingestion tap.",
    }


@app.post("/api/traffic/upload-pcap")
async def upload_pcap(file: UploadFile = File(...)):
    """Uploads and ingests an external PCAP file."""
    save_path = f"data/raw_pcaps/{file.filename}"
    with open(save_path, "wb") as f:
        content = await file.read()
        f.write(content)

    reader = PassivePCAPReader()
    packets = list(reader.read_packets(save_path, max_packets=500))
    asyncio.create_task(stream_packets_async(packets, delay=0.01))

    return {
        "status": "PCAP_INGESTING",
        "filename": file.filename,
        "packets_parsed": len(packets),
    }


@app.websocket("/ws/telemetry")
async def websocket_telemetry(websocket: WebSocket):
    """
    Real-time WebSocket feed streaming live SOC telemetry,
    throughput, recent flows, and graph state updates.
    """
    await pipeline_manager.connect_client(websocket)
    try:
        while True:
            status = pipeline_manager.get_system_status()
            recent_alerts = [a.model_dump() for a in list(pipeline_manager.alerts)[:8]]
            recent_pkts = [
                {
                    "timestamp": p.timestamp,
                    "src": f"{p.src_ip}:{p.src_port}",
                    "dst": f"{p.dst_ip}:{p.dst_port}",
                    "proto": p.protocol,
                    "len": p.length,
                    "flags": p.tcp_flags,
                    "dns": p.dns_query,
                    "info": p.payload_preview or p.protocol,
                }
                for p in list(pipeline_manager.recent_packets)[-10:]
            ]
            graph = pipeline_manager.graph.get_graph_state(max_nodes=25).model_dump()

            payload = {
                "type": "TELEMETRY_UPDATE",
                "status": status.model_dump(),
                "alerts": recent_alerts,
                "recent_packets": recent_pkts,
                "graph": graph,
            }

            await websocket.send_json(payload)
            await asyncio.sleep(1.0)
    except WebSocketDisconnect:
        pipeline_manager.disconnect_client(websocket)
    except Exception:
        pipeline_manager.disconnect_client(websocket)


# Mount static build if dashboard is built
if os.path.exists("dashboard/dist"):
    app.mount("/", StaticFiles(directory="dashboard/dist", html=True), name="static")
