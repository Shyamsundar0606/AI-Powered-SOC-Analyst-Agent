from __future__ import annotations

import json
import re
from typing import Any

from src.models import ParsedAlert


KEY_VALUE_PATTERN = re.compile(r"^\s*([^:]+):\s*(.+?)\s*$")
IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def parse_input(raw_text: str, filename: str | None = None) -> ParsedAlert:
    cleaned = raw_text.strip()
    if not cleaned:
        return ParsedAlert(
            source_type="Empty",
            raw_text=raw_text,
            normalized_text="No input provided.",
            indicators={},
            events=[],
        )

    if _looks_like_json(cleaned):
        return _parse_json_alert(cleaned)

    if filename and filename.lower().endswith((".json", ".jsonl")):
        return _parse_json_alert(cleaned)

    if _looks_like_auth_log(cleaned):
        return _parse_auth_log(cleaned)

    return _parse_key_value_or_free_text(cleaned)


def _looks_like_json(value: str) -> bool:
    return value.startswith("{") or value.startswith("[")


def _looks_like_auth_log(value: str) -> bool:
    auth_markers = [
        "failed password",
        "accepted password",
        "invalid user",
        "sudo:",
        "sshd",
        "authentication failure",
    ]
    lowered = value.lower()
    return any(marker in lowered for marker in auth_markers)


def _parse_json_alert(value: str) -> ParsedAlert:
    try:
        payload = json.loads(value)
    except json.JSONDecodeError:
        return _parse_key_value_or_free_text(value)

    flattened = _flatten_payload(payload)
    indicators = {
        key: str(val)
        for key, val in flattened.items()
        if isinstance(val, (str, int, float)) and str(val).strip()
    }
    normalized = "\n".join(f"{key}: {val}" for key, val in indicators.items())
    events = []
    if isinstance(payload, list):
        for item in payload[:10]:
            if isinstance(item, dict):
                events.append({str(k): str(v) for k, v in item.items()})
    elif isinstance(payload, dict):
        events.append({str(k): str(v) for k, v in payload.items()})

    return ParsedAlert(
        source_type="JSON Alert",
        raw_text=value,
        normalized_text=normalized or value,
        indicators=indicators,
        events=events,
    )


def _flatten_payload(payload: Any, prefix: str = "") -> dict[str, Any]:
    output: dict[str, Any] = {}
    if isinstance(payload, dict):
        for key, value in payload.items():
            compound = f"{prefix}.{key}" if prefix else str(key)
            output.update(_flatten_payload(value, compound))
    elif isinstance(payload, list):
        joined = ", ".join(str(item) for item in payload[:5])
        output[prefix or "items"] = joined
    else:
        output[prefix or "value"] = payload
    return output


def _parse_auth_log(value: str) -> ParsedAlert:
    lines = [line.strip() for line in value.splitlines() if line.strip()]
    failed_count = sum(1 for line in lines if "failed" in line.lower())
    accepted_count = sum(1 for line in lines if "accepted" in line.lower())
    ips = IP_PATTERN.findall(value)
    indicators: dict[str, str | int | list[str]] = {
        "failed_attempts": failed_count,
        "successful_attempts": accepted_count,
    }
    if ips:
        indicators["ips"] = sorted(set(ips))
        indicators["source_ip"] = ips[-1]

    usernames = sorted(set(re.findall(r"(?:for|user)\s+([A-Za-z0-9_.-]+)", value, flags=re.IGNORECASE)))
    if usernames:
        indicators["users"] = usernames
        indicators["user"] = usernames[0]

    normalized = "\n".join(
        [
            "Auth log summary:",
            f"Failed attempts: {failed_count}",
            f"Successful attempts: {accepted_count}",
            f"Users: {', '.join(usernames) if usernames else 'Unknown'}",
            f"IPs: {', '.join(sorted(set(ips))) if ips else 'Unknown'}",
        ]
    )

    events = [{"line": line} for line in lines[:20]]
    return ParsedAlert(
        source_type="Auth Log",
        raw_text=value,
        normalized_text=normalized,
        indicators=indicators,
        events=events,
    )


def _parse_key_value_or_free_text(value: str) -> ParsedAlert:
    indicators: dict[str, str | int | list[str]] = {}
    lines = [line.strip() for line in value.splitlines() if line.strip()]
    for line in lines:
        match = KEY_VALUE_PATTERN.match(line)
        if match:
            key = match.group(1).strip().lower().replace(" ", "_")
            raw_value = match.group(2).strip()
            indicators[key] = _coerce_value(raw_value)

    ips = IP_PATTERN.findall(value)
    if ips and "ip" not in indicators and "source_ip" not in indicators:
        indicators["source_ip"] = ips[0]

    normalized = "\n".join(f"{key}: {val}" for key, val in indicators.items()) if indicators else value
    return ParsedAlert(
        source_type="Structured Text" if indicators else "Free Text",
        raw_text=value,
        normalized_text=normalized,
        indicators=indicators,
        events=[{"line": line} for line in lines[:20]],
    )


def _coerce_value(value: str) -> str | int:
    number = value.replace(",", "")
    return int(number) if number.isdigit() else value
