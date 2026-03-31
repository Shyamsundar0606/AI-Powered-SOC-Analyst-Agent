from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from src.models import AlertAnalysis


HISTORY_PATH = Path(__file__).resolve().parent.parent / "data" / "recent_investigations.json"


def record_investigation(analysis: AlertAnalysis) -> dict[str, object]:
    history = get_recent_investigations()["investigations"]
    entry = {
        "title": analysis.title,
        "severity": analysis.severity,
        "source_type": analysis.source_type,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M"),
        "summary": analysis.summary,
        "mitre_attack": analysis.mitre_attack,
    }
    updated = [entry, *history][:10]
    _write_history(updated)
    return entry


def get_recent_investigations() -> dict[str, list[dict[str, object]]]:
    if not HISTORY_PATH.exists():
        return {"investigations": []}
    try:
        data = json.loads(HISTORY_PATH.read_text(encoding="utf-8"))
        if isinstance(data, list):
            return {"investigations": data}
    except json.JSONDecodeError:
        pass
    return {"investigations": []}


def clear_recent_investigations() -> dict[str, str]:
    _write_history([])
    return {"status": "success", "message": "Recent investigation history was cleared."}


def _write_history(entries: list[dict[str, object]]) -> None:
    HISTORY_PATH.parent.mkdir(parents=True, exist_ok=True)
    HISTORY_PATH.write_text(json.dumps(entries, indent=2), encoding="utf-8")
