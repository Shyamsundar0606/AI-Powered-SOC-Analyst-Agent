from __future__ import annotations

from src.models import AlertAnalysis


def build_incident_report(analysis: AlertAnalysis) -> dict[str, object]:
    return {
        "executive_summary": analysis.summary,
        "severity": analysis.severity,
        "confidence": analysis.confidence,
        "affected_scope": _infer_scope(analysis),
        "analyst_findings": analysis.reasons[:5],
        "mitre_attack": analysis.mitre_attack,
        "recommended_actions": analysis.suggested_actions[:6],
        "containment_priority": "Immediate" if analysis.severity in {"High", "Critical"} else "Monitor and investigate",
        "report_status": "Draft analyst report generated locally",
    }


def _infer_scope(analysis: AlertAnalysis) -> str:
    lowered = analysis.raw_input.lower()
    if "host" in lowered or "workstation" in lowered or "laptop" in lowered:
        return "Endpoint or host activity requires review."
    if "user" in lowered or "login" in lowered or "password" in lowered:
        return "Identity and authentication activity requires review."
    if "s3" in lowered or "download" in lowered or "archive" in lowered:
        return "Potential data-access or exfiltration scope requires review."
    return "Scope should be confirmed with surrounding logs and related assets."
