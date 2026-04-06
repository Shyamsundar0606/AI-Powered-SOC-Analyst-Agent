# AI-Powered SOC Analyst Agent

AI-Powered SOC Analyst Agent is a full-stack cybersecurity project that simulates how a SOC analyst triages suspicious activity. The platform ingests raw logs or alerts, classifies severity, explains why the activity is suspicious, maps findings to MITRE ATT&CK, enriches indicators with local threat-intelligence context, retrieves supporting knowledge through a local RAG layer, and generates a draft incident report for analyst review.

This version is built to be practical, portfolio-ready, and fully local-first.

## What this project does

- Analyzes pasted logs, uploaded files, JSON alerts, and authentication telemetry
- Classifies alerts as Low, Medium, High, or Critical
- Explains the strongest suspicious indicators behind each decision
- Maps behavior to MITRE ATT&CK techniques
- Retrieves relevant MITRE, Sigma-style, and SOC playbook knowledge through a lightweight local RAG workflow
- Adds local threat-intelligence enrichment for suspicious IPs and tools
- Generates a structured incident report for each investigation
- Tracks recent investigations directly in the dashboard

## Why this version is stronger

- Modern React frontend instead of a low-code dashboard framework
- FastAPI backend with a cleaner API-first architecture
- Better separation between UI, parsing, analysis, enrichment, and reporting
- Stronger AI + cybersecurity story through local RAG and threat enrichment
- Fully free to run locally without paid APIs
- Easier to extend into a larger SOC, SIEM, or incident-response platform

## Tech stack

- React
- HTML/CSS
- FastAPI
- Python
- Vite
- Local heuristic SOC analysis engine
- Local RAG knowledge base
- Local mock threat-intelligence enrichment

## Core capabilities

### 1. Alert triage
The system accepts security evidence and converts it into structured analysis. It supports:

- manual text paste
- `.txt`, `.log`, and `.json` uploads
- sample authentication logs
- sample JSON alert bundles

### 2. Severity classification
The backend uses SOC-style scoring logic to classify events as:

- Low
- Medium
- High
- Critical

Severity is influenced by signals such as repeated failed authentication, privileged account usage, suspicious tooling, anomalous geography, remote service abuse, and exfiltration-style behavior.

### 3. MITRE ATT&CK mapping
The project maps suspicious behavior to ATT&CK techniques such as:

- T1110 Brute Force
- T1059 Command and Scripting Interpreter
- T1021 Remote Services
- T1567 Exfiltration Over Web Service

### 4. Local RAG knowledge retrieval
After analysis, the app retrieves matching cybersecurity context from a local knowledge base containing:

- MITRE ATT&CK notes
- Sigma-style detection guidance
- SOC investigation playbooks

This gives the analyst grounded context instead of only a raw rule hit.

### 5. Threat-intelligence enrichment
The app enriches known suspicious indicators using local mock intel entries. This currently includes:

- suspicious IP reputation
- suspicious tool context
- investigation-ready enrichment notes

### 6. Incident report generation
For every analyzed alert, the platform generates a structured draft report including:

- executive summary
- affected scope
- containment priority
- report status

## Architecture

```text
Raw Logs / Alerts
        |
        v
  Parsing Layer
        |
        v
 SOC Analysis Engine
        |
        +--> MITRE ATT&CK Mapping
        |
        +--> Local RAG Retrieval
        |
        +--> Threat-Intel Enrichment
        |
        v
 Incident Report Generation
        |
        v
 React Dashboard + Investigation Chat
```

## Project structure

```text
AI-Powered-SOC-Analyst-Agent/
|-- backend.py
|-- requirements.txt
|-- frontend/
|   |-- package.json
|   |-- vite.config.js
|   |-- index.html
|   |-- src/
|       |-- App.jsx
|       |-- main.jsx
|       |-- styles.css
|-- data/
|   |-- knowledge_base.json
|   |-- sample_alerts.json
|   |-- sample_auth_logs.txt
|   |-- recent_investigations.json
|-- src/
|   |-- agent.py
|   |-- history.py
|   |-- models.py
|   |-- parsers.py
|   |-- rag.py
|   |-- reporting.py
|   |-- service.py
|   |-- threat_intel.py
```

## How to run the project

### Backend

```bash
cd C:\Users\User\Desktop\Shyam\projects\AI-Powered-SOC-Analyst-Agent
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn backend:app --reload
```

Backend URL:

```text
http://127.0.0.1:8000
```

### Frontend

Open a second terminal:

```bash
cd C:\Users\User\Desktop\Shyam\projects\AI-Powered-SOC-Analyst-Agent\frontend
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
npm install
npm run dev
```

Frontend URL:

```text
http://localhost:5173
```

## Demo flow

1. Load the sample authentication log and analyze the brute-force style alert.
2. Review the severity, explanation, and MITRE ATT&CK mapping.
3. Inspect the RAG knowledge context section for MITRE, Sigma, and playbook guidance.
4. Review the threat-intelligence enrichment section for suspicious IP or tooling context.
5. Read the generated incident report.
6. Ask follow-up chat questions such as:
   - Why is this suspicious?
   - What should the analyst do first?
   - What evidence should be checked next?

## Current AI + cybersecurity value

This project demonstrates:

- SOC workflow understanding
- security alert triage
- MITRE ATT&CK alignment
- local RAG implementation
- threat-intelligence enrichment
- incident-response reporting
- full-stack cybersecurity product development

## Future upgrade ideas

- connect to real threat-intel APIs
- add Sigma or detection-rule generation
- support more telemetry sources such as Zeek, Sysmon, or Suricata
- add analyst feedback loops for better scoring
- extend the report into a full case-management workflow

## Resume title

**AI-Powered SOC Analyst Agent for Automated Threat Detection and Incident Response**
