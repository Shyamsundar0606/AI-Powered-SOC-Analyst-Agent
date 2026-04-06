from __future__ import annotations

from src.agent import analyze_alert
from src.history import record_investigation
from src.models import AlertAnalysis
from src.parsers import parse_input
from src.rag import retrieve_context
from src.reporting import build_incident_report
from src.threat_intel import enrich_alert


def analyze_with_context(raw_text: str, source_label: str = "") -> AlertAnalysis:
    parsed = parse_input(raw_text, filename=source_label or None)
    analysis = analyze_alert(parsed)
    analysis.retrieved_knowledge = retrieve_context(analysis)
    analysis.threat_intelligence = enrich_alert(analysis)
    analysis.incident_report = build_incident_report(analysis)
    record_investigation(analysis)
    return analysis
