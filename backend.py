from __future__ import annotations

from dataclasses import asdict
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from src.agent import answer_investigation_question
from src.history import clear_recent_investigations, get_recent_investigations
from src.models import AlertAnalysis
from src.service import analyze_with_context


BASE_DIR = Path(__file__).resolve().parent
FRONTEND_DIST = BASE_DIR / "frontend" / "dist"
DATA_DIR = BASE_DIR / "data"

app = FastAPI(title="AI-Powered SOC Analyst Agent API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def _load_sample(sample_name: str) -> str:
    mapping = {
        "authentication_log": DATA_DIR / "sample_auth_logs.txt",
        "json_alert_bundle": DATA_DIR / "sample_alerts.json",
    }
    path = mapping.get(sample_name)
    if path is None:
        raise HTTPException(status_code=404, detail=f"Unknown sample '{sample_name}'.")
    return path.read_text(encoding="utf-8")


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api/samples")
def list_samples() -> dict[str, list[dict[str, str]]]:
    return {
        "samples": [
            {
                "id": "authentication_log",
                "name": "Sample authentication log",
                "description": "Authentication brute-force style SSH log sample.",
            },
            {
                "id": "json_alert_bundle",
                "name": "Sample JSON alert bundle",
                "description": "Identity, endpoint, lateral movement, and exfiltration style alerts.",
            },
        ]
    }


@app.get("/api/samples/{sample_name}")
def get_sample(sample_name: str) -> dict[str, str]:
    return {"sample": sample_name, "content": _load_sample(sample_name)}


@app.post("/api/analyze")
def analyze_payload(payload: dict[str, str]) -> dict[str, object]:
    raw_text = payload.get("raw_text", "")
    source_label = payload.get("source_label", "")
    analysis = analyze_with_context(raw_text, source_label)
    return asdict(analysis)


@app.post("/api/analyze-file")
async def analyze_file(file: UploadFile = File(...)) -> dict[str, object]:
    content = (await file.read()).decode("utf-8", errors="ignore")
    analysis = analyze_with_context(content, file.filename or "")
    return asdict(analysis)


@app.post("/api/chat")
def chat_about_alert(payload: dict[str, object]) -> dict[str, str]:
    question = str(payload.get("question", ""))
    analysis_data = payload.get("analysis")
    analysis = None
    if isinstance(analysis_data, dict):
        analysis = AlertAnalysis(
            title=str(analysis_data.get("title", "")),
            severity=str(analysis_data.get("severity", "")),
            summary=str(analysis_data.get("summary", "")),
            reasons=list(analysis_data.get("reasons", [])),
            suggested_actions=list(analysis_data.get("suggested_actions", [])),
            confidence=str(analysis_data.get("confidence", "Medium")),
            mitre_attack=list(analysis_data.get("mitre_attack", [])),
            source_type=str(analysis_data.get("source_type", "Unknown")),
            raw_input=str(analysis_data.get("raw_input", "")),
            normalized_context=str(analysis_data.get("normalized_context", "")),
        )
    return {"answer": answer_investigation_question(question, analysis)}


@app.get("/api/history")
def history() -> dict[str, list[dict[str, object]]]:
    return get_recent_investigations()


@app.delete("/api/history")
def clear_history() -> dict[str, str]:
    return clear_recent_investigations()


if FRONTEND_DIST.exists():
    app.mount("/assets", StaticFiles(directory=FRONTEND_DIST / "assets"), name="assets")

    @app.get("/")
    def serve_index() -> FileResponse:
        return FileResponse(FRONTEND_DIST / "index.html")

    @app.get("/{full_path:path}")
    def serve_spa(full_path: str) -> FileResponse:
        candidate = FRONTEND_DIST / full_path
        if candidate.exists() and candidate.is_file():
            return FileResponse(candidate)
        return FileResponse(FRONTEND_DIST / "index.html")
