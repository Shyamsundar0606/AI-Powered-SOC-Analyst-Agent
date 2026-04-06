from __future__ import annotations

import re

from src.models import AlertAnalysis


IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

KNOWN_IP_INTEL = {
    "45.12.88.19": {
        "indicator": "45.12.88.19",
        "type": "IP Reputation",
        "severity": "High",
        "note": "Mock threat-intel entry: repeated brute-force style authentication activity seen against internet-facing services.",
    },
    "103.77.201.9": {
        "indicator": "103.77.201.9",
        "type": "Geo / Identity Risk",
        "severity": "Medium",
        "note": "Mock threat-intel entry: login source observed in anomalous identity-access scenarios.",
    },
}

KNOWN_TOOL_INTEL = {
    "powershell": {
        "indicator": "powershell",
        "type": "Tooling",
        "severity": "High",
        "note": "PowerShell with encoded commands is commonly investigated as suspicious execution behavior.",
    },
    "rclone": {
        "indicator": "rclone",
        "type": "Exfiltration Tool",
        "severity": "Critical",
        "note": "Rclone is often reviewed in data staging or cloud exfiltration investigations.",
    },
    "wmic": {
        "indicator": "wmic",
        "type": "Lateral Movement Tool",
        "severity": "High",
        "note": "WMIC can indicate remote execution or lateral movement in enterprise environments.",
    },
}


def enrich_alert(analysis: AlertAnalysis) -> list[dict[str, str]]:
    items: list[dict[str, str]] = []
    for ip in sorted(set(IP_PATTERN.findall(analysis.raw_input))):
        intel = KNOWN_IP_INTEL.get(ip)
        if intel:
            items.append(intel)

    lowered = analysis.raw_input.lower()
    for term, intel in KNOWN_TOOL_INTEL.items():
        if term in lowered:
            items.append(intel)

    if not items:
        items.append(
            {
                "indicator": "No strong local intel match",
                "type": "Mock Enrichment",
                "severity": "Informational",
                "note": "No preloaded threat-intel entry matched this alert. In a production SOC, this step would query IP, domain, hash, or tooling reputation sources.",
            }
        )
    return items
