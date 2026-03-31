# AI-Powered SOC Analyst Agent

AI-Powered SOC Analyst Agent is a web-based cybersecurity dashboard built with **React** and **FastAPI** that simulates how a SOC analyst triages alerts, explains suspicious activity, classifies incident severity, maps behavior to **MITRE ATT&CK**, and recommends next response steps.

This version replaces Streamlit with a custom frontend and API backend so the project feels more like a real product while keeping the same free local SOC analysis engine.

## Why this version is stronger

- Modern React frontend instead of Streamlit
- FastAPI backend around the SOC analysis engine
- Better separation between UI and analysis logic
- Stronger portfolio value for frontend + backend work
- Still fully free to run locally

## Features

- Analyze pasted logs, uploaded files, JSON alerts, and authentication logs
- Classify severity as Low, Medium, High, or Critical
- Explain why the activity appears suspicious
- Suggest concrete incident response actions
- Ask follow-up investigation questions in a chat panel
- Map detections to MITRE ATT&CK techniques
- Track recent investigations directly in the dashboard

## Tech stack

- React
- HTML/CSS
- FastAPI
- Python
- Local heuristic SOC analysis engine

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
|   |-- sample_alerts.json
|   |-- sample_auth_logs.txt
|   |-- recent_investigations.json
|-- src/
|   |-- agent.py
|   |-- history.py
|   |-- models.py
|   |-- parsers.py
```

## Backend setup

1. Create and activate a virtual environment
2. Install Python dependencies

```bash
pip install -r requirements.txt
```

3. Run the backend API

```bash
uvicorn backend:app --reload
```

The backend will run on `http://127.0.0.1:8000`.

## Frontend setup

1. Open a second terminal
2. Go into the frontend folder

```bash
cd frontend
```

3. Install frontend dependencies

```bash
npm install
```

4. Start the React app

```bash
npm run dev
```

The frontend will run on `http://127.0.0.1:5173`.

## Demo flow

- Load the sample authentication log and analyze a brute-force style alert
- Load the sample JSON alert bundle and compare identity, endpoint, and exfiltration-style cases
- Ask chat questions like:
  - `Why is this suspicious?`
  - `What should the analyst do first?`
  - `What evidence should be checked next?`

## Resume title

**AI-Powered SOC Analyst Agent for Automated Threat Detection and Incident Response**
