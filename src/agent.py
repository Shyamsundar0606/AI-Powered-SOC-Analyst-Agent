from __future__ import annotations

from typing import Any

from src.models import AlertAnalysis, ParsedAlert


def analyze_alert(parsed: ParsedAlert) -> AlertAnalysis:
    return _heuristic_analysis(parsed)


def answer_investigation_question(question: str, analysis: AlertAnalysis | None) -> str:
    if analysis is None:
        return (
            "Load and analyze an alert first. Then I can explain the severity, suspicious indicators, likely attack path, "
            "and the next SOC investigation steps using the local rule engine."
        )

    prompt = question.lower()
    if any(term in prompt for term in ["why", "suspicious", "reason"]):
        return "This alert stands out because:\n- " + "\n- ".join(analysis.reasons)
    if any(term in prompt for term in ["first", "next", "action", "respond"]):
        return "Recommended next actions:\n- " + "\n- ".join(analysis.suggested_actions[:5])
    if "severity" in prompt or "risk" in prompt:
        return (
            f"Severity is {analysis.severity} with {analysis.confidence.lower()} confidence.\n\n"
            f"Why: {analysis.summary}"
        )
    if "mitre" in prompt or "attack" in prompt:
        if analysis.mitre_attack:
            return "Possible MITRE ATT&CK mappings:\n- " + "\n- ".join(analysis.mitre_attack)
        return "There is not enough strong evidence to map this alert confidently to MITRE ATT&CK yet."
    if any(term in prompt for term in ["evidence", "context", "log"]):
        return f"Normalized investigation context:\n\n{analysis.normalized_context}"
    return (
        f"Current alert: {analysis.title}\n\n"
        f"Severity: {analysis.severity}\n"
        f"Summary: {analysis.summary}\n"
        f"Top analyst action: {analysis.suggested_actions[0] if analysis.suggested_actions else 'Review the surrounding logs.'}"
    )


def _heuristic_analysis(parsed: ParsedAlert) -> AlertAnalysis:
    indicators = {key.lower(): value for key, value in parsed.indicators.items()}
    reasons: list[str] = []
    actions: list[str] = []
    mitre: list[str] = []
    severity_score = 0
    alert_text = parsed.raw_text.lower()

    failed_attempts = _number(indicators.get("failed_attempts")) or _number(indicators.get("failed_attempts_count"))
    if failed_attempts and failed_attempts >= 10:
        severity_score += 2
        reasons.append(f"Multiple failed authentication attempts were observed ({failed_attempts}).")
        actions.append("Temporarily block or rate-limit the source IP and review authentication controls.")
        mitre.append("Credential Access - T1110 Brute Force")
    elif failed_attempts and failed_attempts >= 5:
        severity_score += 1
        reasons.append(f"Repeated failed logins were detected ({failed_attempts}).")
        actions.append("Review whether the user account is under password spraying or brute-force pressure.")
        mitre.append("Credential Access - T1110.003 Password Spraying")

    user = _text(indicators.get("user")) or _first_from_list(indicators.get("users"))
    if user and user.lower() in {"admin", "administrator", "root"}:
        severity_score += 1
        reasons.append(f"A privileged account was involved ({user}).")
        actions.append("Verify the account owner, recent password changes, and privileged activity.")

    source_ip = _text(indicators.get("source_ip")) or _text(indicators.get("ip"))
    if source_ip:
        reasons.append(f"Activity originated from source IP {source_ip}.")
        if not _is_private_ip(source_ip):
            severity_score += 1
            actions.append("Check whether the source IP is known, approved, or associated with prior alerts.")

    time_value = _text(indicators.get("time")) or _text(indicators.get("timestamp"))
    if time_value and any(token in time_value.lower() for token in ["am", "00:", "01:", "02:", "03:", "04:", "05:"]):
        severity_score += 1
        reasons.append("The activity occurred during off-hours, which can be suspicious for administrative access.")
        actions.append("Correlate the event with user working hours, VPN activity, and change windows.")

    if "accepted password" in alert_text or "login success" in alert_text or "status: success" in alert_text:
        severity_score += 2
        reasons.append("Successful access was observed, which increases the chance of actual account compromise.")
        actions.append("Review post-login activity to determine whether the session was legitimate or malicious.")
        mitre.append("Defense Evasion / Persistence - T1078 Valid Accounts")

    if any(term in alert_text for term in ["mfa_result: not_prompted", "mfa_result\": \"not_prompted", "mfa bypass", "push fatigue"]):
        severity_score += 2
        reasons.append("Authentication controls appear to have been bypassed or not enforced.")
        actions.append("Validate MFA policy enforcement and review identity-provider conditional access rules.")
        mitre.append("Credential Access - T1621 Multi-Factor Authentication Request Generation")

    if any(term in alert_text for term in ["powershell", "encodedcommand", "mimikatz", "rundll32", "mshta"]):
        severity_score += 2
        reasons.append("Execution artifacts match common attacker tooling or living-off-the-land behavior.")
        actions.append("Inspect process lineage, command history, and endpoint telemetry for follow-on activity.")
        mitre.append("Execution - T1059 Command and Scripting Interpreter")

    if any(term in alert_text for term in ["rundll32", "regsvr32", "mshta"]):
        severity_score += 1
        reasons.append("A signed binary proxy execution pattern was detected.")
        actions.append("Check whether the binary execution was legitimate or part of defense evasion.")
        mitre.append("Defense Evasion - T1218 Signed Binary Proxy Execution")

    if "impossible travel" in alert_text or "geo" in alert_text:
        severity_score += 1
        reasons.append("The login pattern suggests anomalous geography or impossible travel.")
        actions.append("Review identity provider sign-in history and MFA enforcement.")
        mitre.append("Initial Access - T1078 Valid Accounts")

    if any(term in alert_text for term in ["service_account", "svc_", "lateral movement", "psexec", "wmic"]):
        severity_score += 2
        reasons.append("The evidence suggests service account abuse or lateral movement behavior.")
        actions.append("Inspect related hosts for remote execution, credential reuse, and privilege escalation.")
        mitre.append("Lateral Movement - T1021 Remote Services")

    if any(term in alert_text for term in ["download", "archive", "s3", "exfil", "megasync", "rclone"]):
        severity_score += 2
        reasons.append("Potential data staging or exfiltration activity appears in the alert context.")
        actions.append("Review outbound transfers, archive creation, and data access scope immediately.")
        mitre.append("Exfiltration - T1567 Exfiltration Over Web Service")

    if any(term in alert_text for term in ["disabled antivirus", "tamper", "defender disabled", "sensor stopped"]):
        severity_score += 2
        reasons.append("Security tooling appears to have been tampered with or disabled.")
        actions.append("Verify endpoint protection health and isolate the host if tampering is confirmed.")
        mitre.append("Defense Evasion - T1562 Impair Defenses")

    severity_hint = _text(indicators.get("severity_hint"))
    if severity_hint:
        severity_score += {"low": 0, "medium": 1, "high": 2, "critical": 3}.get(severity_hint.lower(), 0)

    if not reasons:
        reasons.append("The alert contains limited evidence, so severity should be validated with additional telemetry.")
        actions.append("Collect more context from authentication, endpoint, and network logs.")

    severity = _score_to_severity(severity_score)
    title = _generate_title(parsed, severity)
    summary = _build_summary(parsed, severity, reasons)
    confidence = "High" if severity_score >= 5 or len(reasons) >= 4 else "Medium"
    mitre = sorted(set(mitre))
    actions = _dedupe(actions + _default_actions(severity))

    return AlertAnalysis(
        title=title,
        severity=severity,
        summary=summary,
        reasons=reasons,
        suggested_actions=actions,
        confidence=confidence,
        mitre_attack=mitre,
        source_type=parsed.source_type,
        raw_input=parsed.raw_text,
        normalized_context=parsed.normalized_text,
    )


def _generate_title(parsed: ParsedAlert, severity: str) -> str:
    if parsed.source_type == "Auth Log":
        return "Suspicious Authentication Activity"
    lowered = parsed.raw_text.lower()
    if any(term in lowered for term in ["powershell", "encodedcommand", "rundll32", "mshta"]):
        return "Suspicious Endpoint Execution Activity"
    if any(term in lowered for term in ["impossible travel", "mfa_result", "identity-provider"]):
        return "Identity Threat Alert"
    if any(term in lowered for term in ["exfil", "archive", "download", "rclone"]):
        return "Potential Data Exfiltration Activity"
    if severity in {"High", "Critical"}:
        return "High-Risk Security Alert"
    return "SOC Alert Triage Result"


def _build_summary(parsed: ParsedAlert, severity: str, reasons: list[str]) -> str:
    reason_text = " ".join(reasons[:3])
    return (
        f"This {parsed.source_type.lower()} was classified as {severity.lower()} severity. "
        f"The strongest indicators are: {reason_text}"
    )


def _default_actions(severity: str) -> list[str]:
    base = [
        "Review related logs around the same timeframe to confirm whether the activity spread to other systems.",
        "Document the incident context and preserve evidence for follow-up investigation.",
    ]
    if severity in {"High", "Critical"}:
        base.insert(0, "Contain the affected user, host, or IP quickly if the activity is still ongoing.")
    if severity == "Critical":
        base.insert(1, "Escalate to incident response and preserve volatile evidence before remediation changes the host state.")
    return base


def _score_to_severity(score: int) -> str:
    if score >= 7:
        return "Critical"
    if score >= 4:
        return "High"
    if score >= 2:
        return "Medium"
    return "Low"


def _number(value: Any) -> int | None:
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return None


def _text(value: Any) -> str | None:
    return value if isinstance(value, str) and value.strip() else None


def _first_from_list(value: Any) -> str | None:
    if isinstance(value, list) and value:
        first = value[0]
        return str(first)
    return None


def _is_private_ip(ip: str) -> bool:
    return ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172.16.") or ip.startswith("127.")


def _dedupe(items: list[str]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            ordered.append(item)
    return ordered
