"""
FastAPI Server for Palo Alto Networks (PAN-OS) Firewall Topology Viewer & Q&A Assistant.
"""

import os
from pathlib import Path
from typing import Optional
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from panos_parser import PanOSConfigParser
from panos_log_ingestor import PanOSLogIngestor
from panos_topology_engine import PanOSTopologyEngine
from panos_diff_engine import PanOSDiffEngine
from panos_qa_agent import PanOSQAAgent
from panos_guardrail import ModelArmorGuardrail, AIGatewayRouter

app = FastAPI(title="Palo Alto Networks PAN-OS Topology Viewer API", version="2.0.0")

# Enable CORS for local UI
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DATA_DIR = Path(__file__).resolve().parent.parent / "data"

# Load PAN-OS files
v1_set_raw = (DATA_DIR / "pan_os_v1.set").read_text(encoding="utf-8")
v2_set_raw = (DATA_DIR / "pan_os_v2.set").read_text(encoding="utf-8")
logs_raw = (DATA_DIR / "pan_os_traffic.log").read_text(encoding="utf-8")

# Initialize PAN-OS engines
panos_parser_v1 = PanOSConfigParser(v1_set_raw)
panos_parser_v2 = PanOSConfigParser(v2_set_raw)

panos_ingestor = PanOSLogIngestor(logs_raw)

panos_engine_v1 = PanOSTopologyEngine(panos_parser_v1, panos_ingestor)
panos_engine_v2 = PanOSTopologyEngine(panos_parser_v2, panos_ingestor)

panos_diff_engine = PanOSDiffEngine(panos_engine_v1, panos_engine_v2)
panos_qa_agent = PanOSQAAgent(panos_engine_v1, panos_engine_v2, panos_diff_engine, panos_ingestor)

# Initialize AI Gateway & Model Armor Guardrail
model_armor = ModelArmorGuardrail()
ai_gateway = AIGatewayRouter(guardrail=model_armor)


class SimulateRequest(BaseModel):
    src_ip: str
    dst_ip: str
    port: int = 443
    protocol: str = "TCP"
    app_id: str = "ssl"
    revision: str = "v2"


class ChatRequest(BaseModel):
    question: str


@app.get("/api/health")
def health_check():
    return {
        "status": "ok",
        "app": "Palo Alto Networks PAN-OS Topology Viewer API",
        "device": panos_parser_v2.hostname,
        "model": panos_parser_v2.model,
        "panos_version": panos_parser_v2.panos_version
    }


@app.get("/api/topology")
def get_topology(revision: str = Query("v2", regex="^(v1|v2)$")):
    if revision == "v1":
        return panos_engine_v1.to_dict()
    return panos_engine_v2.to_dict()


@app.get("/api/topology/diff")
def get_topology_diff():
    return panos_diff_engine.to_dict()


@app.get("/api/logs")
def get_logs(limit: int = 50, action: Optional[str] = None):
    events = panos_ingestor.events
    if action:
        events = [e for e in events if e.get("action") == action.upper()]
    return {
        "stats": panos_ingestor.stats,
        "app_stats": panos_ingestor.app_stats,
        "events": events[:limit]
    }


@app.get("/api/config")
def get_raw_config(revision: str = Query("v2", regex="^(v1|v2)$")):
    if revision == "v1":
        return {"raw": v1_set_raw, "parsed": panos_parser_v1.to_dict()}
    return {"raw": v2_set_raw, "parsed": panos_parser_v2.to_dict()}


@app.post("/api/simulate")
def simulate_traffic(req: SimulateRequest):
    engine = panos_engine_v1 if req.revision == "v1" else panos_engine_v2
    return engine.simulate_panos_packet(
        src_ip=req.src_ip,
        dst_ip=req.dst_ip,
        port=req.port,
        protocol=req.protocol,
        app_id=req.app_id
    )


@app.post("/api/chat")
def answer_customer_question(req: ChatRequest):
    if not req.question.strip():
        raise HTTPException(status_code=400, detail="Question cannot be empty")
    return ai_gateway.process_query(req.question, panos_qa_agent.answer)


@app.get("/api/armor/audit")
def get_model_armor_audit():
    return {
        "total_requests": ai_gateway.total_requests,
        "blocked_attacks": ai_gateway.blocked_requests,
        "audit_logs": model_armor.audit_log
    }


from fastapi.staticfiles import StaticFiles

FRONTEND_DIST = Path(__file__).resolve().parent.parent / "frontend" / "dist"
if FRONTEND_DIST.exists():
    app.mount("/", StaticFiles(directory=str(FRONTEND_DIST), html=True), name="static")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
