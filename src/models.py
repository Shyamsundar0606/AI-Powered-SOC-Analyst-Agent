from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class AlertAnalysis:
    title: str
    severity: str
    summary: str
    reasons: list[str] = field(default_factory=list)
    suggested_actions: list[str] = field(default_factory=list)
    confidence: str = "Medium"
    mitre_attack: list[str] = field(default_factory=list)
    source_type: str = "Unknown"
    raw_input: str = ""
    normalized_context: str = ""
    retrieved_knowledge: list[dict[str, str]] = field(default_factory=list)
    threat_intelligence: list[dict[str, str]] = field(default_factory=list)
    incident_report: dict[str, object] = field(default_factory=dict)


@dataclass
class ParsedAlert:
    source_type: str
    raw_text: str
    normalized_text: str
    indicators: dict[str, str | int | list[str]]
    events: list[dict[str, str]]
