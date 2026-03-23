from __future__ import annotations

from datetime import datetime
from pathlib import Path

import streamlit as st

from src.agent import analyze_alert, answer_investigation_question
from src.parsers import parse_input


st.set_page_config(
    page_title="AI-Powered SOC Analyst Agent",
    page_icon="🚨",
    layout="wide",
)


def bootstrap_state() -> None:
    if "analysis" not in st.session_state:
        st.session_state.analysis = None
    if "raw_input" not in st.session_state:
        st.session_state.raw_input = ""
    if "chat_history" not in st.session_state:
        st.session_state.chat_history = []
    if "case_history" not in st.session_state:
        st.session_state.case_history = []


def render_header() -> None:
    st.markdown(
        """
        <style>
        :root {
            --bg: #f4f7fb;
            --panel: #ffffff;
            --panel-alt: linear-gradient(135deg, #ffffff 0%, #f8fbff 100%);
            --line: #d9e3f0;
            --text: #17324d;
            --muted: #5b718a;
            --accent: #0f9d8a;
            --accent-2: #0b5fff;
            --danger: #e45353;
            --warning: #f2a93b;
            --shadow: 0 18px 40px rgba(18, 45, 76, 0.08);
            --radius: 20px;
        }

        .stApp {
            background:
                radial-gradient(circle at top left, rgba(15, 157, 138, 0.08), transparent 28%),
                radial-gradient(circle at top right, rgba(11, 95, 255, 0.08), transparent 24%),
                linear-gradient(180deg, #f7f9fc 0%, #eef4fb 100%);
        }

        [data-testid="stSidebar"] {
            background: linear-gradient(180deg, #eef3f8 0%, #e8eef6 100%);
            border-right: 1px solid rgba(121, 142, 165, 0.18);
        }

        header[data-testid="stHeader"] {
            display: none;
        }

        [data-testid="stToolbar"] {
            display: none;
        }

        .stApp > div:first-child {
            padding-top: 0;
        }

        .hero-shell {
            background: linear-gradient(135deg, rgba(9, 22, 40, 0.96), rgba(23, 50, 77, 0.92));
            border: 1px solid rgba(123, 174, 255, 0.12);
            border-radius: 28px;
            box-shadow: 0 20px 44px rgba(7, 20, 34, 0.22);
            color: #f4f8fc;
            margin-bottom: 1.5rem;
            overflow: hidden;
            padding: 1.5rem 1.6rem;
            position: relative;
        }

        .hero-shell::after {
            background: radial-gradient(circle, rgba(24, 184, 163, 0.35) 0%, transparent 58%);
            content: "";
            height: 220px;
            position: absolute;
            right: -40px;
            top: -40px;
            width: 220px;
        }

        .hero-eyebrow {
            color: #8bc5ff;
            font-size: 0.78rem;
            font-weight: 700;
            letter-spacing: 0.14em;
            margin-bottom: 0.75rem;
            text-transform: uppercase;
        }

        .hero-grid {
            display: grid;
            gap: 1rem;
            grid-template-columns: 1.7fr 1fr;
            position: relative;
            z-index: 1;
        }

        .hero-title {
            font-size: 3rem;
            font-weight: 800;
            line-height: 1.03;
            margin: 0;
            max-width: 780px;
        }

        .hero-copy {
            color: rgba(235, 243, 251, 0.82);
            font-size: 1rem;
            line-height: 1.65;
            margin-top: 1rem;
            max-width: 720px;
        }

        .hero-kpis {
            display: grid;
            gap: 0.8rem;
            grid-template-columns: 1fr;
        }

        .hero-kpi {
            background: rgba(255, 255, 255, 0.08);
            backdrop-filter: blur(6px);
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-radius: 18px;
            padding: 0.95rem 1rem;
        }

        .hero-kpi-label {
            color: rgba(214, 228, 241, 0.8);
            font-size: 0.78rem;
            letter-spacing: 0.06em;
            margin-bottom: 0.35rem;
            text-transform: uppercase;
        }

        .hero-kpi-value {
            color: #ffffff;
            font-size: 1.4rem;
            font-weight: 800;
        }

        .section-card {
            background: var(--panel-alt);
            border: 1px solid rgba(84, 108, 135, 0.12);
            border-radius: var(--radius);
            box-shadow: var(--shadow);
            padding: 1.2rem 1.2rem 0.8rem 1.2rem;
        }

        .section-heading {
            color: var(--text);
            font-size: 1.55rem;
            font-weight: 800;
            margin-bottom: 0.25rem;
        }

        .section-copy {
            color: var(--muted);
            font-size: 0.96rem;
            margin-bottom: 1rem;
        }

        .mini-grid {
            display: grid;
            gap: 0.8rem;
            grid-template-columns: repeat(3, minmax(0, 1fr));
            margin: 0.8rem 0 0.35rem 0;
        }

        .mini-card {
            background: #f7fbff;
            border: 1px solid rgba(112, 144, 178, 0.2);
            border-radius: 16px;
            padding: 0.9rem 1rem;
        }

        .mini-label {
            color: var(--muted);
            font-size: 0.78rem;
            font-weight: 700;
            letter-spacing: 0.08em;
            margin-bottom: 0.35rem;
            text-transform: uppercase;
        }

        .mini-value {
            color: var(--text);
            font-size: 1.05rem;
            font-weight: 800;
            line-height: 1.4;
        }

        .severity-banner {
            align-items: center;
            background: linear-gradient(135deg, #fff7f7 0%, #fffdf6 100%);
            border: 1px solid rgba(212, 89, 89, 0.12);
            border-radius: 22px;
            display: flex;
            gap: 1.1rem;
            justify-content: space-between;
            margin: 0.4rem 0 1rem 0;
            padding: 1.1rem 1.2rem;
        }

        .severity-meta {
            display: flex;
            flex-direction: column;
            gap: 0.35rem;
        }

        .severity-chip {
            border-radius: 999px;
            color: #fff;
            display: inline-flex;
            font-size: 0.86rem;
            font-weight: 800;
            letter-spacing: 0.05em;
            padding: 0.45rem 0.8rem;
            text-transform: uppercase;
            width: fit-content;
        }

        .severity-low { background: #2d9d78; }
        .severity-medium { background: #e2a93f; }
        .severity-high { background: #e56a47; }
        .severity-critical { background: #c93c54; }

        .summary-card {
            background: #f7fbff;
            border: 1px solid rgba(112, 144, 178, 0.2);
            border-radius: 18px;
            margin-bottom: 1rem;
            padding: 1rem 1.1rem;
        }

        .panel-title {
            color: var(--text);
            font-size: 1.05rem;
            font-weight: 800;
            margin-bottom: 0.6rem;
        }

        .list-panel {
            background: #fbfdff;
            border: 1px solid rgba(112, 144, 178, 0.18);
            border-radius: 18px;
            height: 100%;
            padding: 1rem 1.05rem;
        }

        .list-panel ul {
            margin: 0;
            padding-left: 1.15rem;
        }

        .list-panel li {
            color: var(--text);
            line-height: 1.55;
            margin-bottom: 0.7rem;
        }

        .list-panel li::marker {
            color: var(--accent-2);
        }

        .history-card {
            background: linear-gradient(135deg, #ffffff 0%, #f6faff 100%);
            border: 1px solid rgba(112, 144, 178, 0.22);
            border-radius: 18px;
            box-shadow: var(--shadow);
            margin-top: 1rem;
            padding: 1rem 1.05rem;
        }

        .history-item {
            background: #fbfdff;
            border: 1px solid rgba(112, 144, 178, 0.18);
            border-radius: 14px;
            margin-top: 0.8rem;
            padding: 0.8rem 0.9rem;
        }

        .empty-chat {
            background: linear-gradient(135deg, #f7fbff 0%, #f3f8ff 100%);
            border: 1px dashed rgba(112, 144, 178, 0.35);
            border-radius: 18px;
            margin-top: 0.9rem;
            padding: 1rem 1.05rem;
        }

        .empty-chat-title {
            color: var(--text);
            font-size: 1rem;
            font-weight: 800;
            margin-bottom: 0.45rem;
        }

        .empty-chat ul {
            color: var(--muted);
            margin: 0;
            padding-left: 1.1rem;
        }

        .stButton > button {
            background: linear-gradient(135deg, #ff635f 0%, #f6495f 100%);
            border: none;
            border-radius: 14px;
            box-shadow: 0 14px 28px rgba(246, 73, 95, 0.24);
            color: white;
            font-weight: 700;
        }

        .stButton > button:hover {
            background: linear-gradient(135deg, #ef5a56 0%, #e94259 100%);
        }

        @media (max-width: 980px) {
            .hero-grid, .mini-grid {
                grid-template-columns: 1fr;
            }
        }
        </style>
        """,
        unsafe_allow_html=True,
    )
    st.markdown(
        """
        <div class="hero-shell">
            <div class="hero-eyebrow">SOC Operations Console</div>
            <div class="hero-grid">
                <div>
                    <h1 class="hero-title">AI-Powered SOC Analyst Agent</h1>
                    <div class="hero-copy">
                        Ingest alerts, triage suspicious activity, explain analyst reasoning, and recommend
                        the next investigation steps through a recruiter-ready security dashboard.
                    </div>
                </div>
                <div class="hero-kpis">
                    <div class="hero-kpi">
                        <div class="hero-kpi-label">Primary Mission</div>
                        <div class="hero-kpi-value">Threat Triage</div>
                    </div>
                    <div class="hero-kpi">
                        <div class="hero-kpi-label">Cost Model</div>
                        <div class="hero-kpi-value">100% Free Local Engine</div>
                    </div>
                    <div class="hero-kpi">
                        <div class="hero-kpi-label">Target Audience</div>
                        <div class="hero-kpi-value">SOC Teams and Recruiters</div>
                    </div>
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def load_sample_input(sample_name: str) -> str:
    base = Path(__file__).parent / "data"
    if sample_name == "Sample JSON alert bundle":
        return (base / "sample_alerts.json").read_text(encoding="utf-8")
    if sample_name == "Sample authentication log":
        return (base / "sample_auth_logs.txt").read_text(encoding="utf-8")
    return ""


def render_sidebar() -> None:
    st.sidebar.header("Project Controls")
    sample_name = st.sidebar.selectbox(
        "Load a sample dataset",
        ["None", "Sample JSON alert bundle", "Sample authentication log"],
    )
    if st.sidebar.button("Load sample", use_container_width=True) and sample_name != "None":
        st.session_state.raw_input = load_sample_input(sample_name)

    if st.session_state.case_history and st.sidebar.button("Clear history", use_container_width=True):
        st.session_state.case_history = []


def render_input_panel() -> None:
    col1, col2 = st.columns([1.1, 0.9], gap="large")

    with col1:
        st.markdown(
            """
            <div class="section-card">
                <div class="section-heading">Alert Intake</div>
                <div class="section-copy">Load sample telemetry, upload alerts, or paste raw evidence for triage.</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        uploaded = st.file_uploader(
            "Upload a `.txt`, `.log`, or `.json` alert file",
            type=["txt", "log", "json"],
        )
        if uploaded is not None:
            st.session_state.raw_input = uploaded.read().decode("utf-8", errors="ignore")

        st.session_state.raw_input = st.text_area(
            "Paste logs or alerts",
            value=st.session_state.raw_input,
            height=320,
            placeholder="Paste auth logs, suspicious alerts, JSON events, or free-text case notes here...",
        )

        if st.button("Analyze alert", type="primary", use_container_width=True):
            parsed = parse_input(
                st.session_state.raw_input,
                filename=uploaded.name if uploaded is not None else None,
            )
            st.session_state.analysis = analyze_alert(parsed)
            st.session_state.chat_history = []
            st.session_state.case_history = [
                {
                    "title": st.session_state.analysis.title,
                    "severity": st.session_state.analysis.severity,
                    "source_type": st.session_state.analysis.source_type,
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M"),
                    "summary": st.session_state.analysis.summary,
                },
                *st.session_state.case_history,
            ][:6]

    with col2:
        st.markdown(
            """
            <div class="section-card">
                <div class="section-heading">Investigation Chat</div>
                <div class="section-copy">Ask for severity justification, evidence, MITRE hints, or next response steps.</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        for item in st.session_state.chat_history:
            with st.chat_message(item["role"]):
                st.markdown(item["content"])

        if not st.session_state.chat_history:
            st.markdown(
                """
                <div class="empty-chat">
                    <div class="empty-chat-title">Suggested questions</div>
                    <ul>
                        <li>Why is this alert suspicious?</li>
                        <li>What should the analyst do first?</li>
                        <li>What evidence should be checked next?</li>
                    </ul>
                </div>
                """,
                unsafe_allow_html=True,
            )

        question = st.chat_input("Ask about the current alert, severity, or next actions")
        if question:
            st.session_state.chat_history.append({"role": "user", "content": question})
            reply = answer_investigation_question(question, st.session_state.analysis)
            st.session_state.chat_history.append({"role": "assistant", "content": reply})
            st.rerun()


def render_analysis() -> None:
    analysis = st.session_state.analysis
    if analysis is None:
        return

    st.divider()
    st.subheader("Triage Result")
    metric_col1, metric_col2, metric_col3 = st.columns(3)
    metric_col1.metric("Severity", analysis.severity)
    metric_col2.metric("Confidence", analysis.confidence)
    metric_col3.metric("Source Type", analysis.source_type)

    severity_class = f"severity-{analysis.severity.lower()}"
    st.markdown(
        f"""
        <div class="severity-banner">
            <div class="severity-meta">
                <div class="severity-chip {severity_class}">{analysis.severity} Severity</div>
                <div style="font-size: 1.7rem; font-weight: 800; color: #17324d;">{analysis.title}</div>
                <div style="color: #5b718a;">Confidence: {analysis.confidence} | Source: {analysis.source_type}</div>
            </div>
            <div style="max-width: 320px; color: #5b718a; line-height: 1.6;">
                SOC-ready output designed to explain what happened and what the analyst should do next.
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    st.markdown(
        f"""
        <div class="summary-card">
            <div class="panel-title">Executive Summary</div>
            <div style="color: #17324d; line-height: 1.75;">{analysis.summary}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    reason_col, action_col = st.columns(2, gap="large")
    with reason_col:
        reasons_html = "".join(f"<li>{reason}</li>" for reason in analysis.reasons)
        st.markdown(
            f"""
            <div class="list-panel">
                <div class="panel-title">Why it is suspicious</div>
                <ul>{reasons_html}</ul>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with action_col:
        actions_html = "".join(f"<li>{action}</li>" for action in analysis.suggested_actions)
        st.markdown(
            f"""
            <div class="list-panel">
                <div class="panel-title">Suggested next actions</div>
                <ul>{actions_html}</ul>
            </div>
            """,
            unsafe_allow_html=True,
        )

    extra_col1, extra_col2 = st.columns(2, gap="large")
    with extra_col1:
        st.markdown("#### MITRE ATT&CK hints")
        if analysis.mitre_attack:
            for item in analysis.mitre_attack:
                st.write(f"- {item}")
        else:
            st.write("No strong MITRE mapping was inferred from the current evidence.")

    with extra_col2:
        st.markdown("#### Normalized evidence")
        st.code(analysis.normalized_context, language="text")

    if st.session_state.case_history:
        history_html = "".join(
            f"""
            <div class="history-item">
                <div style="display:flex; justify-content:space-between; gap:1rem; align-items:center;">
                    <div style="font-weight:800; color:#17324d;">{item['title']}</div>
                    <div class="severity-chip severity-{item['severity'].lower()}">{item['severity']}</div>
                </div>
                <div style="color:#5b718a; margin-top:0.35rem;">{item['source_type']} | {item['timestamp']}</div>
                <div style="color:#17324d; margin-top:0.45rem; line-height:1.6;">{item['summary']}</div>
            </div>
            """
            for item in st.session_state.case_history
        )
        st.markdown(
            f"""
            <div class="history-card">
                <div class="panel-title">Recent Investigations</div>
                <div style="color:#5b718a;">Local case tracking for your latest alert triage sessions.</div>
                {history_html}
            </div>
            """,
            unsafe_allow_html=True,
        )

    with st.expander("View raw input"):
        st.code(analysis.raw_input, language="text")


bootstrap_state()
render_header()
render_sidebar()
render_input_panel()
render_analysis()
