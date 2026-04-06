from __future__ import annotations

import json
import re
from pathlib import Path

from src.models import AlertAnalysis


KNOWLEDGE_PATH = Path(__file__).resolve().parent.parent / "data" / "knowledge_base.json"
TOKEN_PATTERN = re.compile(r"[a-z0-9_.-]+")


def retrieve_context(analysis: AlertAnalysis) -> list[dict[str, str]]:
    docs = _load_knowledge()
    query = " ".join(
        [
            analysis.title,
            analysis.summary,
            " ".join(analysis.reasons),
            " ".join(analysis.mitre_attack),
            analysis.raw_input,
        ]
    ).lower()
    query_tokens = set(TOKEN_PATTERN.findall(query))

    scored: list[tuple[int, dict[str, str]]] = []
    for doc in docs:
        corpus = " ".join([doc["title"], doc["category"], doc["content"], " ".join(doc.get("keywords", []))]).lower()
        score = sum(1 for token in set(TOKEN_PATTERN.findall(corpus)) if token in query_tokens)
        if score > 0:
            scored.append((score, doc))

    scored.sort(key=lambda item: item[0], reverse=True)
    return [
        {
            "title": doc["title"],
            "category": doc["category"],
            "content": doc["content"],
        }
        for _, doc in scored[:4]
    ]


def _load_knowledge() -> list[dict[str, str]]:
    return json.loads(KNOWLEDGE_PATH.read_text(encoding="utf-8"))
