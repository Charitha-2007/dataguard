"""DataGuard - Intelligent Data Pipeline Observability & Automated Recovery Platform.

Premium Dark-Mode Command Center:
- Luxury Glassmorphism + Neon Glow Design System
- Animated gradient header & sidebar branding
- Rich KPI cards with colored accent bars
- Plotly dark charts with custom color palettes
- Responsive grid layouts with HTML/CSS components
"""

import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime

from config.settings import DEFAULT_NULL_THRESHOLD_PCT, DEFAULT_PSI_DRIFT_THRESHOLD
from src.database.models import init_db
from src.database.repository import DataGuardRepository
from src.core.simulator import PipelineSimulator
from src.core.quality_engine import DataQualityEngine
from src.core.drift_detector import DriftAnomalyDetector
from src.core.rca_engine import RootCauseAnalysisEngine
from src.core.impact_analyzer import DependencyImpactAnalyzer
from src.core.sla_monitor import SLAMonitor
from src.services.notifier import NotificationDispatcher
from src.services.incident_manager import IncidentManager
from src.services.audit_service import AuditService
from src.services.knowledge_base import KnowledgeBaseService
from src.services.auth import AuthService, UserSession
from src.recovery.recommendation import RecoveryRecommendationEngine
from src.recovery.approval_workflow import ApprovalWorkflowManager
from src.recovery.recovery_executor import RecoveryExecutor
from src.recovery.verifier import RecoveryVerifier

# ── Page config ────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="DataGuard | Observability Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ══════════════════════════════════════════════════════════════════════════════
#  PREMIUM DESIGN SYSTEM — CSS
# ══════════════════════════════════════════════════════════════════════════════
PREMIUM_CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500;600&display=swap');

/* ── Global Reset ─────────────────────────────────────────────────────── */
:root {
    --bg:          #060b18;
    --bg2:         #0d1526;
    --surface:     rgba(15, 23, 42, 0.80);
    --surface2:    rgba(22, 33, 62, 0.65);
    --border:      rgba(99, 179, 255, 0.10);
    --border2:     rgba(99, 179, 255, 0.20);
    --cyan:        #22d3ee;
    --blue:        #60a5fa;
    --indigo:      #818cf8;
    --violet:      #a78bfa;
    --emerald:     #34d399;
    --amber:       #fbbf24;
    --rose:        #f87171;
    --txt:         #e2e8f0;
    --txt2:        #94a3b8;
    --txt3:        #64748b;
    --glow-cyan:   0 0 24px rgba(34, 211, 238, 0.35);
    --glow-blue:   0 0 24px rgba(96, 165, 250, 0.35);
    --glow-rose:   0 0 24px rgba(248, 113, 113, 0.35);
    --glow-emerald:0 0 24px rgba(52, 211, 153, 0.35);
    --radius:      16px;
    --radius-sm:   10px;
}

html, body, [class*="css"] {
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif !important;
    color: var(--txt);
}

/* ── App Background ───────────────────────────────────────────────────── */
.stApp {
    background:
        radial-gradient(ellipse 80% 50% at 10% -10%, rgba(34,211,238,0.07) 0%, transparent 60%),
        radial-gradient(ellipse 60% 40% at 90% 110%, rgba(96,165,250,0.07) 0%, transparent 60%),
        linear-gradient(180deg, #060b18 0%, #07101f 100%);
    min-height: 100vh;
}

/* ── Sidebar ──────────────────────────────────────────────────────────── */
[data-testid="stSidebar"] {
    background: linear-gradient(180deg, #09112a 0%, #060e22 100%) !important;
    border-right: 1px solid var(--border2) !important;
}
[data-testid="stSidebar"] > div:first-child { padding-top: 0 !important; }

/* ── Metric Cards ─────────────────────────────────────────────────────── */
div[data-testid="metric-container"] {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 20px 22px 18px !important;
    backdrop-filter: blur(20px);
    box-shadow: 0 4px 32px rgba(0,0,0,0.5), inset 0 1px 0 rgba(255,255,255,0.05);
    transition: transform 0.25s ease, border-color 0.25s ease, box-shadow 0.25s ease;
    position: relative;
    overflow: hidden;
}
div[data-testid="metric-container"]::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 2px;
    background: linear-gradient(90deg, var(--cyan), var(--blue));
    border-radius: var(--radius) var(--radius) 0 0;
}
div[data-testid="metric-container"]:hover {
    transform: translateY(-3px);
    border-color: rgba(34,211,238,0.3);
    box-shadow: 0 8px 40px rgba(0,0,0,0.6), var(--glow-cyan);
}
div[data-testid="metric-container"] [data-testid="stMetricLabel"] {
    font-size: 11px !important;
    font-weight: 600 !important;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: var(--txt2) !important;
}
div[data-testid="metric-container"] [data-testid="stMetricValue"] {
    font-size: 28px !important;
    font-weight: 800 !important;
    color: var(--txt) !important;
    line-height: 1.1;
}
div[data-testid="metric-container"] [data-testid="stMetricDelta"] {
    font-size: 12px !important;
    font-weight: 500;
}

/* ── Buttons ──────────────────────────────────────────────────────────── */
.stButton > button {
    border-radius: var(--radius-sm) !important;
    font-family: 'Inter', sans-serif !important;
    font-weight: 600 !important;
    font-size: 13px !important;
    padding: 9px 20px !important;
    transition: all 0.2s ease !important;
    border: 1px solid var(--border2) !important;
    background: var(--surface2) !important;
    color: var(--txt) !important;
}
.stButton > button:hover {
    border-color: var(--cyan) !important;
    box-shadow: var(--glow-cyan) !important;
    transform: translateY(-1px) !important;
}
.stButton > button[kind="primary"] {
    background: linear-gradient(135deg, #0ea5e9 0%, #6366f1 100%) !important;
    border: none !important;
    color: #fff !important;
    box-shadow: 0 4px 20px rgba(14,165,233,0.4) !important;
}
.stButton > button[kind="primary"]:hover {
    box-shadow: 0 6px 30px rgba(14,165,233,0.65) !important;
    transform: translateY(-2px) !important;
}

/* ── Selectbox / Inputs ───────────────────────────────────────────────── */
.stSelectbox > div > div,
.stTextInput > div > div > input,
.stSlider > div {
    background: var(--surface) !important;
    border: 1px solid var(--border) !important;
    border-radius: var(--radius-sm) !important;
    color: var(--txt) !important;
}
.stSelectbox > div > div:focus-within,
.stTextInput > div > div > input:focus {
    border-color: var(--cyan) !important;
    box-shadow: 0 0 0 2px rgba(34,211,238,0.15) !important;
}

/* ── Tabs ─────────────────────────────────────────────────────────────── */
.stTabs [data-baseweb="tab-list"] {
    background: var(--surface) !important;
    border-radius: var(--radius-sm) !important;
    padding: 4px !important;
    border: 1px solid var(--border) !important;
    gap: 2px !important;
}
.stTabs [data-baseweb="tab"] {
    border-radius: 8px !important;
    padding: 8px 20px !important;
    font-weight: 600 !important;
    font-size: 13px !important;
    color: var(--txt2) !important;
    transition: all 0.2s !important;
}
.stTabs [aria-selected="true"] {
    background: linear-gradient(135deg, rgba(14,165,233,0.25), rgba(99,102,241,0.25)) !important;
    color: var(--cyan) !important;
    border: 1px solid rgba(34,211,238,0.3) !important;
}

/* ── DataFrames ───────────────────────────────────────────────────────── */
div[data-testid="stDataFrame"] {
    border: 1px solid var(--border) !important;
    border-radius: var(--radius) !important;
    overflow: hidden !important;
    background: var(--surface) !important;
}

/* ── Alerts ───────────────────────────────────────────────────────────── */
.stSuccess, .stError, .stWarning, .stInfo {
    border-radius: var(--radius-sm) !important;
    border: none !important;
}

/* ── Headings ─────────────────────────────────────────────────────────── */
h1, h2, h3, h4, h5 {
    color: var(--txt) !important;
    font-weight: 700 !important;
    letter-spacing: -0.025em !important;
}
hr { border-color: var(--border) !important; margin: 20px 0 !important; }

/* ── Spinner ──────────────────────────────────────────────────────────── */
.stSpinner > div { border-top-color: var(--cyan) !important; }

/* ── Expanders ────────────────────────────────────────────────────────── */
details[data-testid="stExpander"] {
    background: var(--surface) !important;
    border: 1px solid var(--border) !important;
    border-radius: var(--radius-sm) !important;
    margin-bottom: 8px !important;
}
details[data-testid="stExpander"] summary {
    font-weight: 600 !important;
    color: var(--txt) !important;
    padding: 12px 16px !important;
}

/* ── Radio Navigation ─────────────────────────────────────────────────── */
[data-testid="stRadio"] > div { gap: 4px !important; }
[data-testid="stRadio"] label {
    background: transparent !important;
    border-radius: 8px !important;
    padding: 8px 12px !important;
    transition: background 0.15s !important;
    color: var(--txt2) !important;
    font-weight: 500 !important;
}
[data-testid="stRadio"] label:hover {
    background: rgba(34,211,238,0.07) !important;
    color: var(--txt) !important;
}

/* ── Custom HTML Components ───────────────────────────────────────────── */

/* Page header banner */
.dg-page-header {
    background: linear-gradient(135deg, rgba(14,165,233,0.12) 0%, rgba(99,102,241,0.12) 100%);
    border: 1px solid rgba(99,179,255,0.15);
    border-radius: var(--radius);
    padding: 24px 28px;
    margin-bottom: 24px;
    position: relative;
    overflow: hidden;
}
.dg-page-header::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 1px;
    background: linear-gradient(90deg, transparent, var(--cyan), var(--indigo), transparent);
}
.dg-page-header h1 {
    margin: 0 0 6px 0 !important;
    font-size: 26px !important;
    font-weight: 800 !important;
    background: linear-gradient(90deg, #e2e8f0 30%, #94a3b8);
    -webkit-background-clip: text; -webkit-text-fill-color: transparent;
}
.dg-page-header p {
    margin: 0 !important;
    color: var(--txt2) !important;
    font-size: 14px !important;
    line-height: 1.6 !important;
}

/* KPI card with colored left bar */
.dg-kpi {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 18px 20px;
    backdrop-filter: blur(20px);
    box-shadow: 0 4px 32px rgba(0,0,0,0.4);
    border-left: 3px solid var(--accent, var(--cyan));
    transition: transform 0.2s, box-shadow 0.2s;
    margin-bottom: 12px;
}
.dg-kpi:hover { transform: translateY(-2px); box-shadow: 0 8px 40px rgba(0,0,0,0.5); }
.dg-kpi-label { font-size: 11px; font-weight: 700; text-transform: uppercase;
    letter-spacing: 0.08em; color: var(--txt3); margin-bottom: 6px; }
.dg-kpi-value { font-size: 30px; font-weight: 800; color: var(--txt); line-height: 1; margin-bottom: 4px; }
.dg-kpi-sub { font-size: 12px; color: var(--txt2); }

/* Pipeline health card */
.dg-pipeline-card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 18px 20px;
    backdrop-filter: blur(16px);
    box-shadow: 0 4px 24px rgba(0,0,0,0.35);
    transition: transform 0.2s, border-color 0.2s;
    height: 100%;
}
.dg-pipeline-card:hover { transform: translateY(-3px); border-color: var(--border2); }
.dg-pipeline-tag {
    font-size: 10px; font-weight: 700; text-transform: uppercase;
    letter-spacing: 0.08em; color: var(--cyan); margin-bottom: 8px;
}
.dg-pipeline-name { font-size: 15px; font-weight: 700; color: var(--txt); margin-bottom: 4px; }
.dg-pipeline-sla { font-size: 12px; color: var(--txt2); margin-bottom: 12px; }
.dg-compliance-num { font-size: 32px; font-weight: 900; line-height: 1; }
.dg-compliance-label { font-size: 11px; color: var(--txt3); margin-left: 6px; }

/* Badge pills */
.badge {
    display: inline-flex; align-items: center; gap: 4px;
    padding: 3px 10px; border-radius: 9999px;
    font-size: 11px; font-weight: 700;
    letter-spacing: 0.04em; text-transform: uppercase;
}
.badge-green  { background: rgba(52,211,153,0.12); color: #34d399; border: 1px solid rgba(52,211,153,0.3); }
.badge-amber  { background: rgba(251,191,36,0.12);  color: #fbbf24; border: 1px solid rgba(251,191,36,0.3); }
.badge-red    { background: rgba(248,113,113,0.12); color: #f87171; border: 1px solid rgba(248,113,113,0.3); }
.badge-cyan   { background: rgba(34,211,238,0.12);  color: #22d3ee; border: 1px solid rgba(34,211,238,0.3); }
.badge-indigo { background: rgba(129,140,248,0.12); color: #818cf8; border: 1px solid rgba(129,140,248,0.3); }

/* Section divider with label */
.dg-section-label {
    display: flex; align-items: center; gap: 10px;
    margin: 24px 0 16px 0;
}
.dg-section-label span {
    font-size: 13px; font-weight: 700; text-transform: uppercase;
    letter-spacing: 0.08em; color: var(--txt2);
    white-space: nowrap;
}
.dg-section-label::after {
    content: ''; flex: 1;
    height: 1px; background: var(--border);
}

/* Stat row in incident card */
.dg-stat-row { display: flex; gap: 16px; flex-wrap: wrap; margin: 12px 0; }
.dg-stat { background: var(--surface2); border: 1px solid var(--border);
    border-radius: 8px; padding: 10px 16px; flex: 1; min-width: 110px; }
.dg-stat-k { font-size: 10px; font-weight: 700; text-transform: uppercase;
    letter-spacing: 0.06em; color: var(--txt3); margin-bottom: 4px; }
.dg-stat-v { font-size: 16px; font-weight: 700; color: var(--txt); font-family: 'JetBrains Mono', monospace; }

/* Code / mono text */
.mono { font-family: 'JetBrains Mono', monospace; font-size: 12px;
    background: rgba(0,0,0,0.3); padding: 2px 8px; border-radius: 4px;
    color: var(--cyan); }

/* Sidebar brand block */
.dg-brand {
    background: linear-gradient(135deg, rgba(14,165,233,0.15), rgba(99,102,241,0.15));
    border: 1px solid rgba(34,211,238,0.2);
    border-radius: 14px;
    padding: 20px 18px;
    margin: 16px 0 20px 0;
    text-align: center;
}
.dg-brand-logo { font-size: 40px; margin-bottom: 8px; }
.dg-brand-name {
    font-size: 22px; font-weight: 900;
    background: linear-gradient(90deg, #22d3ee, #818cf8);
    -webkit-background-clip: text; -webkit-text-fill-color: transparent;
    letter-spacing: -0.03em;
}
.dg-brand-sub {
    font-size: 10px; font-weight: 600; text-transform: uppercase;
    letter-spacing: 0.1em; color: var(--txt3); margin-top: 2px;
}

/* Live dot indicator */
.live-dot {
    display: inline-block; width: 7px; height: 7px;
    border-radius: 50%; background: #34d399;
    box-shadow: 0 0 8px #34d399;
    animation: pulse 2s infinite;
    margin-right: 5px;
}
@keyframes pulse {
    0%, 100% { opacity: 1; transform: scale(1); }
    50%       { opacity: 0.5; transform: scale(0.85); }
}

/* Scrollbar */
::-webkit-scrollbar { width: 6px; height: 6px; }
::-webkit-scrollbar-track { background: transparent; }
::-webkit-scrollbar-thumb { background: rgba(99,179,255,0.2); border-radius: 3px; }
::-webkit-scrollbar-thumb:hover { background: rgba(99,179,255,0.4); }
</style>
"""
st.markdown(PREMIUM_CSS, unsafe_allow_html=True)


# ── Chart theme helper ─────────────────────────────────────────────────────────
def chart_theme(fig, height=380):
    fig.update_layout(
        template="plotly_dark",
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(13,21,38,0.6)",
        font=dict(family="Inter", size=12, color="#94a3b8"),
        margin=dict(l=16, r=16, t=36, b=16),
        height=height,
        xaxis=dict(gridcolor="rgba(99,179,255,0.06)", zeroline=False, linecolor="rgba(99,179,255,0.1)"),
        yaxis=dict(gridcolor="rgba(99,179,255,0.06)", zeroline=False, linecolor="rgba(99,179,255,0.1)"),
        legend=dict(bgcolor="rgba(0,0,0,0)", bordercolor="rgba(99,179,255,0.15)", borderwidth=1),
    )
    return fig


def badge(text, color="cyan"):
    return f'<span class="badge badge-{color}">{text}</span>'

def section(label):
    st.markdown(f'<div class="dg-section-label"><span>{label}</span></div>', unsafe_allow_html=True)


# ── Init ───────────────────────────────────────────────────────────────────────
init_db()
repo             = DataGuardRepository()
simulator        = PipelineSimulator(repo=repo)
quality_engine   = DataQualityEngine()
drift_detector   = DriftAnomalyDetector()
rca_engine       = RootCauseAnalysisEngine()
impact_analyzer  = DependencyImpactAnalyzer(repo=repo)
sla_monitor      = SLAMonitor(repo=repo)
notifier         = NotificationDispatcher()
incident_manager = IncidentManager(repo=repo, notifier=notifier)
audit_service    = AuditService(repo=repo)
kb_service       = KnowledgeBaseService(repo=repo)
auth_service     = AuthService()
recommender      = RecoveryRecommendationEngine(repo=repo)
workflow         = ApprovalWorkflowManager(repo=repo)
executor         = RecoveryExecutor(repo=repo, simulator=simulator)
verifier         = RecoveryVerifier(repo=repo, quality_engine=quality_engine)


# ══════════════════════════════════════════════════════════════════════════════
#  SIDEBAR
# ══════════════════════════════════════════════════════════════════════════════
with st.sidebar:
    st.markdown("""
    <div class="dg-brand">
        <div class="dg-brand-logo">🛡️</div>
        <div class="dg-brand-name">DataGuard</div>
        <div class="dg-brand-sub">Observability Platform</div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("**👤 Active Profile**")
    user_choice = st.selectbox(
        "Select Role",
        ["admin — Full Control", "engineer_alice — Operations", "viewer_bob — Read-Only"],
        label_visibility="collapsed",
    )

    if "admin" in user_choice:
        current_user = UserSession(username="admin", role="admin", email="admin@dataguard.local")
        st.markdown(badge("🔑 Admin · Full Access", "green"), unsafe_allow_html=True)
    elif "engineer" in user_choice:
        current_user = UserSession(username="engineer_alice", role="engineer", email="alice@dataguard.local")
        st.markdown(badge("⚙️ Engineer · Operations", "cyan"), unsafe_allow_html=True)
    else:
        current_user = UserSession(username="viewer_bob", role="viewer", email="bob@dataguard.local")
        st.markdown(badge("👁️ Viewer · Read-Only", "amber"), unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    menu = st.radio(
        "Navigation",
        [
            "📊  Observability",
            "🧪  Simulator Lab",
            "🚨  Incidents & Recovery",
            "📈  Drift & Anomalies",
            "🛡️  Audit & Knowledge Base",
        ],
        label_visibility="collapsed",
    )

    st.markdown("<br>", unsafe_allow_html=True)
    # Quick live status dot
    open_count = len(repo.get_all_incidents(status="OPEN"))
    color = "#34d399" if open_count == 0 else "#f87171"
    st.markdown(
        f'<div style="font-size:12px;color:#64748b;padding:0 4px;">'
        f'<span style="display:inline-block;width:7px;height:7px;border-radius:50%;'
        f'background:{color};box-shadow:0 0 8px {color};margin-right:6px;"></span>'
        f'{"All Systems Operational" if open_count == 0 else f"{open_count} Open Incident(s)"}'
        f'</div>',
        unsafe_allow_html=True,
    )


# ══════════════════════════════════════════════════════════════════════════════
#  VIEW 1 — OBSERVABILITY DASHBOARD
# ══════════════════════════════════════════════════════════════════════════════
if "Observability" in menu:
    st.markdown("""
    <div class="dg-page-header">
        <h1>📊 Pipeline Observability Command Center</h1>
        <p>Live health metrics, SLA compliance tracking, and execution telemetry across all data warehouse ingestion pipelines.</p>
    </div>
    """, unsafe_allow_html=True)

    pipelines     = repo.get_all_pipelines()
    open_incidents = repo.get_all_incidents(status="OPEN")
    recent_runs   = repo.get_recent_runs(limit=50)
    audit_check   = audit_service.verify_integrity()

    # ── KPI Row ───────────────────────────────────────────────────────────────
    k1, k2, k3, k4 = st.columns(4)
    with k1:
        st.metric("🗂️ Monitored Pipelines", len(pipelines), "Active Catalogs")
    with k2:
        st.metric("⚡ Total Runs", len(recent_runs), "Historical Batches")
    with k3:
        delta = "✅ All Healthy" if len(open_incidents) == 0 else f"+{len(open_incidents)} Issues"
        st.metric("🚨 Open Incidents", len(open_incidents), delta, delta_color="inverse")
    with k4:
        status_text = "✅ Chain Valid" if audit_check["is_valid"] else "🔴 Tampered!"
        st.metric("🔒 Audit Integrity", "SHA-256", status_text)

    # ── SLA Pipeline Cards ────────────────────────────────────────────────────
    section("Pipeline Health & SLA Compliance")

    sla_data = []
    sla_cols = st.columns(len(pipelines))
    for idx, p in enumerate(pipelines):
        rpt = sla_monitor.get_pipeline_compliance(p["id"])
        sla_data.append({
            "Pipeline": p["name"],
            "Target SLA (s)": p["sla_seconds"],
            "Avg Duration (s)": rpt.average_duration_seconds,
            "P95 Latency (s)": rpt.p95_duration_seconds,
            "Compliance %": rpt.compliance_percentage,
            "Grade": rpt.health_grade,
        })
        with sla_cols[idx]:
            good    = rpt.health_grade in ("A", "B")
            clr     = "#34d399" if good else "#f87171"
            bdg     = "green" if good else "red"
            border  = "rgba(52,211,153,0.3)" if good else "rgba(248,113,113,0.3)"
            glow    = "rgba(52,211,153,0.15)" if good else "rgba(248,113,113,0.15)"
            st.markdown(f"""
            <div class="dg-pipeline-card" style="border-color:{border};box-shadow:0 4px 24px {glow};">
                <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:10px;">
                    <div class="dg-pipeline-tag">{p['source_type']} pipeline</div>
                    <span class="badge badge-{bdg}">Grade {rpt.health_grade}</span>
                </div>
                <div class="dg-pipeline-name">{p['name']}</div>
                <div class="dg-pipeline-sla">SLA Budget: <b style="color:#e2e8f0;">{p['sla_seconds']}s</b></div>
                <div style="display:flex;align-items:baseline;gap:6px;margin-top:8px;">
                    <span class="dg-compliance-num" style="color:{clr};">{rpt.compliance_percentage}%</span>
                    <span class="dg-compliance-label">compliance</span>
                </div>
                <div style="margin-top:10px;font-size:12px;color:#64748b;">
                    Avg <b style="color:#94a3b8;">{rpt.average_duration_seconds}s</b> &nbsp;·&nbsp;
                    P95 <b style="color:#94a3b8;">{rpt.p95_duration_seconds}s</b>
                </div>
            </div>
            """, unsafe_allow_html=True)

    # ── SLA Chart ─────────────────────────────────────────────────────────────
    section("Latency vs SLA Budget")
    df_sla = pd.DataFrame(sla_data)
    fig_sla = go.Figure()
    fig_sla.add_trace(go.Bar(
        name="Avg Duration (s)", x=df_sla["Pipeline"], y=df_sla["Avg Duration (s)"],
        marker=dict(color="#22d3ee", opacity=0.85),
    ))
    fig_sla.add_trace(go.Bar(
        name="P95 Latency (s)", x=df_sla["Pipeline"], y=df_sla["P95 Latency (s)"],
        marker=dict(color="#818cf8", opacity=0.85),
    ))
    fig_sla.add_trace(go.Scatter(
        name="SLA Budget (s)", x=df_sla["Pipeline"], y=df_sla["Target SLA (s)"],
        mode="lines+markers",
        line=dict(color="#f87171", width=2.5, dash="dash"),
        marker=dict(size=8, color="#f87171"),
    ))
    fig_sla.update_layout(barmode="group")
    chart_theme(fig_sla, 360)
    st.plotly_chart(fig_sla, use_container_width=True)

    # ── Run Feed ──────────────────────────────────────────────────────────────
    section("Recent Pipeline Execution Runs")
    if recent_runs:
        df_runs = pd.DataFrame(recent_runs)[[
            "run_id", "pipeline_name", "status", "started_at",
            "duration_seconds", "row_count", "error_message",
        ]]
        st.dataframe(df_runs, use_container_width=True, hide_index=True)
    else:
        st.info("No runs yet. Head to **Simulator Lab** to trigger test runs!")


# ══════════════════════════════════════════════════════════════════════════════
#  VIEW 2 — PIPELINE SIMULATOR & FAULT LAB
# ══════════════════════════════════════════════════════════════════════════════
elif "Simulator" in menu:
    st.markdown("""
    <div class="dg-page-header">
        <h1>🧪 Pipeline Simulator & Chaos Fault Lab</h1>
        <p>Simulate production data batches and inject controlled failures to validate DataGuard's detection, root-cause analysis, and self-healing recovery capabilities.</p>
    </div>
    """, unsafe_allow_html=True)

    col_cfg, col_out = st.columns([1, 1], gap="large")

    with col_cfg:
        section("1 · Configure Pipeline Run")
        selected_pipeline_id = st.selectbox(
            "Target Pipeline",
            ["crm_customers_etl", "billing_transactions_sync"],
            format_func=lambda x: "🗄️ CRM Customer Profiles ETL" if x == "crm_customers_etl" else "💳 Billing Transactions Sync",
        )
        selected_fault = st.selectbox(
            "Fault Injection Mode",
            [
                "None — Clean Healthy Run",
                "NULL_SPIKE — 35% Missing Values",
                "SCHEMA_MISMATCH — API Breaking Column Rename",
                "ANOMALY_VALUES — Negative Balances & Outliers",
                "SLA_BREACH — Database Lock / Latency Hang",
                "VOLUME_DROP — Premature Connection Drop (5 rows)",
            ],
        )
        fault_key = None
        for fk in ["NULL_SPIKE", "SCHEMA_MISMATCH", "ANOMALY_VALUES", "SLA_BREACH", "VOLUME_DROP"]:
            if fk in selected_fault:
                fault_key = fk
                break

        if not current_user.can_trigger_pipeline:
            st.error("⛔ Viewers cannot trigger pipeline runs. Switch to Admin or Engineer.")
            st.button("🚀 Trigger Pipeline Run", disabled=True)
            trigger_button = False
        else:
            trigger_button = st.button("🚀 Trigger Pipeline Run", type="primary")

    with col_out:
        section("2 · Real-Time Telemetry & Diagnosis")

        if trigger_button:
            with st.spinner("Executing pipeline & evaluating data contracts..."):
                pipeline_meta = repo.get_pipeline(selected_pipeline_id)
                run, df       = simulator.run_pipeline(pipeline_id=selected_pipeline_id, fault_type=fault_key)
                quality_report = quality_engine.evaluate(selected_pipeline_id, df)

                ref_df     = simulator.generate_crm_data(250) if selected_pipeline_id == "crm_customers_etl" else simulator.generate_billing_data(250)
                numeric_col = "account_balance" if selected_pipeline_id == "crm_customers_etl" else "amount"
                drift_report = drift_detector.evaluate(selected_pipeline_id, ref_df, df, [numeric_col])

                diagnosis = rca_engine.diagnose(
                    pipeline_id=selected_pipeline_id,
                    sla_seconds=pipeline_meta["sla_seconds"],
                    duration_seconds=run.duration_seconds,
                    row_count=run.row_count,
                    quality_report=quality_report,
                    drift_report=drift_report,
                )
                impact_report = impact_analyzer.analyze_impact(selected_pipeline_id)
                run_status    = "FAILED" if diagnosis else "SUCCESS"

                repo.update_run(
                    run_id=run.run_id,
                    status=run_status,
                    completed_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    duration_seconds=run.duration_seconds,
                    row_count=run.row_count,
                    error_message=diagnosis.root_cause_summary if diagnosis else None,
                    metrics_json=quality_report.to_dict(),
                    processed_data_path=run.raw_data_path if run_status == "SUCCESS" else None,
                )

                if diagnosis:
                    incident = incident_manager.create_incident(
                        run_id=run.run_id,
                        pipeline_id=selected_pipeline_id,
                        diagnosis=diagnosis,
                        impact_report=impact_report,
                    )
                    plan = recommender.generate_plan(
                        incident_type=diagnosis.incident_type,
                        pipeline_id=selected_pipeline_id,
                        corrupted_indices=quality_report.corrupted_indices,
                        raw_data_path=run.raw_data_path,
                    )
                    workflow.submit_recovery_request(incident.incident_code, selected_pipeline_id, plan)

            if run_status == "SUCCESS":
                st.success(f"✅ Pipeline executed cleanly! Run ID: `{run.run_id}`")
                m1, m2 = st.columns(2)
                m1.metric("Quality Score", f"{quality_report.quality_score}%", "100% Passed")
                m2.metric("Rows Processed", run.row_count, "No Issues")
            else:
                sev_color = {"P1": "🔴", "P2": "🟠", "P3": "🟡"}.get(diagnosis.severity, "⚪")
                st.error(f"{sev_color} Failure: **{diagnosis.incident_type}** (Severity: {diagnosis.severity})")
                st.warning(f"**Root Cause:** {diagnosis.root_cause_summary}")
                st.info(f"**Blast Radius:** {impact_report.impact_summary}")
                st.markdown(
                    f'📋 Incident <span class="mono">{incident.incident_code}</span> queued in '
                    f'**Incidents & Recovery** tab.',
                    unsafe_allow_html=True,
                )

            section("Data Sample Preview (First 5 Rows)")
            st.dataframe(df.head(), use_container_width=True)
        else:
            st.markdown("""
            <div style="text-align:center;padding:60px 20px;color:#334155;">
                <div style="font-size:48px;margin-bottom:16px;">⚗️</div>
                <div style="font-size:15px;font-weight:600;color:#475569;">Configure & trigger a pipeline run</div>
                <div style="font-size:13px;margin-top:6px;">Results and telemetry will appear here</div>
            </div>
            """, unsafe_allow_html=True)


# ══════════════════════════════════════════════════════════════════════════════
#  VIEW 3 — INCIDENTS & RECOVERY
# ══════════════════════════════════════════════════════════════════════════════
elif "Incidents" in menu:
    st.markdown("""
    <div class="dg-page-header">
        <h1>🚨 Incident Triage & Approval-Gated Recovery</h1>
        <p>Diagnose active pipeline failures, inspect downstream blast radius graphs, and authorize self-healing recovery actions with RBAC enforcement.</p>
    </div>
    """, unsafe_allow_html=True)

    all_incidents = repo.get_all_incidents()

    if not all_incidents:
        st.markdown("""
        <div style="text-align:center;padding:80px 20px;">
            <div style="font-size:56px;margin-bottom:16px;">🎉</div>
            <div style="font-size:18px;font-weight:700;color:#34d399;">All Clear — No Incidents Detected</div>
            <div style="font-size:13px;color:#64748b;margin-top:8px;">All pipelines are running within healthy SLA bounds.</div>
        </div>
        """, unsafe_allow_html=True)
    else:
        severity_icon = {"P1": "🔴", "P2": "🟠", "P3": "🟡", "P4": "🔵"}
        status_badge  = {
            "OPEN": "red", "IN_REVIEW": "amber",
            "RECOVERED": "green", "CLOSED": "indigo",
        }

        incident_options = {
            f"{severity_icon.get(inc['severity'],'⚪')} {inc['incident_code']} — {inc['pipeline_name']} [{inc['status']}]": inc
            for inc in all_incidents
        }
        selected_label = st.selectbox("Select Incident to Triage", list(incident_options.keys()))
        selected_inc   = incident_options[selected_label]

        st.markdown("<br>", unsafe_allow_html=True)
        left, right = st.columns([1, 1], gap="large")

        # ── LEFT: Details + DAG ───────────────────────────────────────────────
        with left:
            section("Incident Details")
            sbdg = status_badge.get(selected_inc["status"], "cyan")
            st.markdown(f"""
            <div class="dg-kpi" style="--accent:#818cf8;">
                <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;">
                    <span style="font-size:18px;font-weight:800;color:#e2e8f0;">{selected_inc['incident_code']}</span>
                    {badge(selected_inc['status'], sbdg)}
                </div>
                <div class="dg-stat-row">
                    <div class="dg-stat"><div class="dg-stat-k">Pipeline</div><div class="dg-stat-v" style="font-size:12px;">{selected_inc['pipeline_id']}</div></div>
                    <div class="dg-stat"><div class="dg-stat-k">Severity</div><div class="dg-stat-v">{selected_inc['severity']}</div></div>
                    <div class="dg-stat"><div class="dg-stat-k">Type</div><div class="dg-stat-v" style="font-size:11px;">{selected_inc['incident_type']}</div></div>
                </div>
                <div style="margin-top:12px;font-size:13px;color:#94a3b8;line-height:1.6;">
                    <b style="color:#cbd5e1;">Root Cause:</b> {selected_inc['root_cause_summary']}
                </div>
                <div style="margin-top:8px;font-size:12px;color:#64748b;">
                    Assigned to: <span class="mono">{selected_inc['assigned_to']}</span>
                </div>
            </div>
            """, unsafe_allow_html=True)

            section("Downstream DAG Blast Radius")
            impact = impact_analyzer.analyze_impact(selected_inc["pipeline_id"])
            st.info(impact.impact_summary)

            nodes  = impact.graph_nodes
            x_pos  = [0 if n["id"] == selected_inc["pipeline_id"] else 2 for n in nodes]
            y_pos  = list(range(len(nodes)))
            colors = ["#f87171" if n["status"] == "FAILED" else "#fbbf24" for n in nodes]

            fig_dag = go.Figure()
            fig_dag.add_trace(go.Scatter(
                x=x_pos, y=y_pos,
                mode="markers+text",
                text=[n["label"] for n in nodes],
                textposition="bottom center",
                textfont=dict(size=11, color="#94a3b8"),
                marker=dict(size=36, color=colors,
                            line=dict(width=2, color="rgba(255,255,255,0.15)"),
                            symbol="circle"),
                hoverinfo="text",
            ))
            fig_dag.update_layout(
                showlegend=False,
                xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            )
            chart_theme(fig_dag, 260)
            st.plotly_chart(fig_dag, use_container_width=True)

        # ── RIGHT: Recovery ───────────────────────────────────────────────────
        with right:
            section("Approval-Gated Self-Healing Recovery")
            recovery_actions = repo.get_recovery_actions_for_incident(selected_inc["incident_code"])

            if not recovery_actions:
                st.markdown("""
                <div style="text-align:center;padding:40px 20px;color:#475569;">
                    <div style="font-size:36px;">📭</div>
                    <div style="font-size:14px;margin-top:10px;">No recovery action proposed yet.</div>
                </div>
                """, unsafe_allow_html=True)
            else:
                action     = recovery_actions[0]
                action_id  = action["id"]
                action_status = action["status"]

                st.markdown(f"""
                <div class="dg-kpi" style="--accent:#22d3ee;">
                    <div class="dg-stat-row">
                        <div class="dg-stat"><div class="dg-stat-k">Action ID</div><div class="dg-stat-v">#{action_id}</div></div>
                        <div class="dg-stat"><div class="dg-stat-k">Type</div><div class="dg-stat-v" style="font-size:11px;">{action['action_type']}</div></div>
                        <div class="dg-stat"><div class="dg-stat-k">Status</div><div class="dg-stat-v" style="font-size:12px;">{action_status}</div></div>
                    </div>
                    <div style="margin-top:10px;font-size:12px;color:#64748b;">
                        Requested by: <span class="mono">{action['requested_by']}</span>
                    </div>
                </div>
                """, unsafe_allow_html=True)

                if action_status == "PENDING_APPROVAL":
                    st.warning("⚠️ This action requires human approval before execution.")
                    if not current_user.can_approve_recovery:
                        st.error("⛔ Viewers cannot approve recovery. Switch to Admin or Engineer.")
                        st.button("✅ Authorize & Execute Recovery", disabled=True)
                    else:
                        if st.button("✅ Authorize & Execute Recovery", type="primary"):
                            with st.spinner("Authorizing and executing recovery operation..."):
                                workflow.approve_recovery(action_id, approved_by=current_user.username, user_role=current_user.role)
                                success, exec_log, recovered_df = executor.execute(action_id)
                                if success and recovered_df is not None:
                                    is_verified, v_rep = verifier.verify(
                                        action_id=action_id,
                                        pipeline_id=selected_inc["pipeline_id"],
                                        recovered_df=recovered_df,
                                        execution_log=exec_log,
                                        actor=current_user.username,
                                    )
                                    if is_verified:
                                        st.success(f"🎉 Recovery Verified! Quality Score: {v_rep.quality_score}%")
                                        st.rerun()
                                    else:
                                        st.error(f"❌ Verification Failed. Quality Score: {v_rep.quality_score}%")
                                else:
                                    st.error(f"Execution Error: {exec_log}")

                elif action_status in ("COMPLETED", "APPROVED"):
                    st.success("🛡️ Recovery executed and verified!")
                    st.markdown(f"""
                    <div style="font-size:13px;color:#94a3b8;line-height:2;">
                        <b>Approved by:</b> <span class="mono">{action['approved_by']}</span>
                        at <span class="mono">{action['approved_at']}</span><br>
                        <b>Execution Log:</b> {action['execution_log']}<br>
                        <b>Verification:</b> {'✅ Healthy' if action['is_verified'] else '❌ Unverified'}
                    </div>
                    """, unsafe_allow_html=True)


# ══════════════════════════════════════════════════════════════════════════════
#  VIEW 4 — DRIFT & ANOMALIES
# ══════════════════════════════════════════════════════════════════════════════
elif "Drift" in menu:
    st.markdown("""
    <div class="dg-page-header">
        <h1>📈 Statistical Drift & ML Anomaly Detection</h1>
        <p>Detect distribution shifts using Population Stability Index (PSI), Kolmogorov-Smirnov test, and Isolation Forest ML anomaly detection.</p>
    </div>
    """, unsafe_allow_html=True)

    left_d, right_d = st.columns([1, 1], gap="large")

    with left_d:
        section("Simulation Controls")
        drift_pipeline = st.selectbox(
            "Pipeline",
            ["crm_customers_etl", "billing_transactions_sync"],
            format_func=lambda x: "CRM Customer Profiles ETL" if x == "crm_customers_etl" else "Billing Transactions Sync",
        )
        shift_multiplier = st.slider(
            "Distribution Shift Multiplier",
            1.0, 8.0, 2.5, 0.5,
            help="1.0 = Baseline · 3.0+ = Moderate Drift · 6.0+ = Extreme Drift",
        )
        st.markdown(f"""
        <div style="font-size:12px;color:#64748b;padding:8px 12px;background:rgba(0,0,0,0.2);
            border-radius:8px;border-left:3px solid #22d3ee;margin-top:8px;">
            🔍 Simulating a <b style="color:#e2e8f0;">{shift_multiplier}×</b> shift in
            <span class="mono">{'account_balance' if drift_pipeline == 'crm_customers_etl' else 'amount'}</span>
            distribution.
        </div>
        """, unsafe_allow_html=True)

    np.random.seed(42)
    if drift_pipeline == "crm_customers_etl":
        ref_df     = simulator.generate_crm_data(300)
        cur_df     = simulator.generate_crm_data(300)
        target_col = "account_balance"
    else:
        ref_df     = simulator.generate_billing_data(300)
        cur_df     = simulator.generate_billing_data(300)
        target_col = "amount"
    cur_df[target_col] = cur_df[target_col] * shift_multiplier

    report   = drift_detector.evaluate(drift_pipeline, ref_df, cur_df, [target_col])
    drift_res = report.column_drifts[target_col]
    psi_val  = drift_res.psi_score
    ks_p     = drift_res.ks_pvalue
    sev      = drift_res.drift_severity

    with right_d:
        section("Statistical Diagnostics")
        d1, d2, d3 = st.columns(3)
        d1.metric("PSI Score", psi_val, f"Threshold >{DEFAULT_PSI_DRIFT_THRESHOLD}")
        d2.metric("KS p-value", f"{ks_p:.4f}", "< 0.05 = Drift")
        d3.metric("Severity", sev)

        if sev == "CRITICAL":
            st.error(f"🚨 {drift_res.message}")
        elif sev == "MODERATE":
            st.warning(f"⚠️ {drift_res.message}")
        else:
            st.success(f"✅ {drift_res.message}")

    # ── Overlay Histogram ─────────────────────────────────────────────────────
    section(f"Distribution Curves — Baseline vs Current · '{target_col}'")
    fig_dist = go.Figure()
    fig_dist.add_trace(go.Histogram(
        x=ref_df[target_col], name="Baseline (Reference)",
        opacity=0.65, marker_color="#22d3ee",
        nbinsx=40,
    ))
    fig_dist.add_trace(go.Histogram(
        x=cur_df[target_col], name="Current Batch",
        opacity=0.65, marker_color="#f87171",
        nbinsx=40,
    ))
    fig_dist.update_layout(barmode="overlay")
    chart_theme(fig_dist, 380)
    st.plotly_chart(fig_dist, use_container_width=True)

    # ── PSI Gauge ─────────────────────────────────────────────────────────────
    section("PSI Risk Gauge")
    fig_gauge = go.Figure(go.Indicator(
        mode="gauge+number+delta",
        value=float(psi_val),
        delta={"reference": float(DEFAULT_PSI_DRIFT_THRESHOLD), "valueformat": ".3f"},
        title={"text": "Population Stability Index", "font": {"size": 14, "color": "#94a3b8"}},
        number={"font": {"size": 32, "color": "#e2e8f0"}, "valueformat": ".3f"},
        gauge={
            "axis": {"range": [0, 0.5], "tickcolor": "#64748b", "tickfont": {"size": 10}},
            "bar": {"color": "#22d3ee", "thickness": 0.25},
            "bgcolor": "rgba(0,0,0,0)",
            "bordercolor": "rgba(99,179,255,0.15)",
            "steps": [
                {"range": [0, 0.1],  "color": "rgba(52,211,153,0.15)"},
                {"range": [0.1, 0.2],"color": "rgba(251,191,36,0.15)"},
                {"range": [0.2, 0.5],"color": "rgba(248,113,113,0.15)"},
            ],
            "threshold": {"line": {"color": "#f87171","width": 2},"thickness": 0.75,"value": DEFAULT_PSI_DRIFT_THRESHOLD},
        },
    ))
    fig_gauge.update_layout(paper_bgcolor="rgba(0,0,0,0)", font_color="#94a3b8", height=280, margin=dict(l=30,r=30,t=50,b=10))
    st.plotly_chart(fig_gauge, use_container_width=True)


# ══════════════════════════════════════════════════════════════════════════════
#  VIEW 5 — AUDIT & KNOWLEDGE BASE
# ══════════════════════════════════════════════════════════════════════════════
elif "Audit" in menu:
    st.markdown("""
    <div class="dg-page-header">
        <h1>🛡️ Cryptographic Audit Ledger & Knowledge Base</h1>
        <p>Tamper-evident append-only audit chain secured with SHA-256 hashing, plus a searchable institutional knowledge repository of proven failure resolutions.</p>
    </div>
    """, unsafe_allow_html=True)

    tab_audit, tab_kb = st.tabs(["🔒  Audit Ledger", "📚  Knowledge Base"])

    # ── TAB 1: Audit ──────────────────────────────────────────────────────────
    with tab_audit:
        integrity = audit_service.verify_integrity()
        if integrity["is_valid"]:
            st.markdown(f"""
            <div style="background:rgba(52,211,153,0.08);border:1px solid rgba(52,211,153,0.3);
                border-radius:12px;padding:16px 20px;margin-bottom:20px;display:flex;align-items:center;gap:14px;">
                <span style="font-size:28px;">✅</span>
                <div>
                    <div style="font-size:14px;font-weight:700;color:#34d399;">Audit Integrity Verified</div>
                    <div style="font-size:12px;color:#64748b;margin-top:2px;">
                        {integrity['total_checked']} records form an unbroken SHA-256 hash chain. Zero tampering detected.
                    </div>
                </div>
            </div>
            """, unsafe_allow_html=True)
        else:
            st.markdown(f"""
            <div style="background:rgba(248,113,113,0.08);border:1px solid rgba(248,113,113,0.35);
                border-radius:12px;padding:16px 20px;margin-bottom:20px;display:flex;align-items:center;gap:14px;">
                <span style="font-size:28px;">🔴</span>
                <div>
                    <div style="font-size:14px;font-weight:700;color:#f87171;">Tampering Detected!</div>
                    <div style="font-size:12px;color:#64748b;margin-top:2px;">{integrity.get('reason','Unknown error')}</div>
                </div>
            </div>
            """, unsafe_allow_html=True)

        section("Audit Log Explorer")
        filter_actor = st.text_input("Filter by Actor", placeholder="e.g. admin, simulator_engine, engineer_alice")
        audit_records = audit_service.get_audit_trail(limit=100, actor=filter_actor or None)

        if audit_records:
            df_audit = pd.DataFrame(audit_records)[[
                "id", "timestamp", "actor", "action", "entity_type", "entity_id", "record_hash"
            ]]
            st.dataframe(df_audit, use_container_width=True, hide_index=True)
            csv = df_audit.to_csv(index=False).encode("utf-8")
            st.download_button(
                "📥 Export Audit Trail as CSV",
                data=csv,
                file_name="dataguard_audit_trail.csv",
                mime="text/csv",
            )
        else:
            st.info("No audit logs match the current filter.")

    # ── TAB 2: Knowledge Base ─────────────────────────────────────────────────
    with tab_kb:
        section("Institutional Knowledge Base")
        search_q  = st.text_input("🔍 Search Solutions", placeholder="e.g. schema, null, timeout, SLA, drift")
        solutions = kb_service.search_solutions(search_q) if search_q else kb_service.get_all_solutions()

        if not solutions:
            st.info("No solutions found. Try a different keyword.")
        else:
            for s in solutions:
                times_color = "#34d399" if s["times_used"] >= 3 else "#fbbf24"
                with st.expander(f"📌  {s['incident_type']}"):
                    st.markdown(f"""
                    <div style="display:flex;gap:10px;margin-bottom:14px;flex-wrap:wrap;">
                        <span class="badge badge-indigo">Applied {s['times_used']} times</span>
                        <span class="badge badge-cyan">{s['incident_type']}</span>
                    </div>
                    <table style="width:100%;border-collapse:collapse;font-size:13px;">
                        <tr>
                            <td style="color:#64748b;padding:5px 0;width:160px;font-weight:600;">Error Pattern</td>
                            <td><span class="mono">{s['error_pattern']}</span></td>
                        </tr>
                        <tr>
                            <td style="color:#64748b;padding:5px 0;font-weight:600;">Root Cause</td>
                            <td style="color:#94a3b8;">{s['root_cause']}</td>
                        </tr>
                        <tr>
                            <td style="color:#64748b;padding:5px 0;font-weight:600;">Recommended Action</td>
                            <td><span class="mono">{s['recommended_action']}</span></td>
                        </tr>
                    </table>
                    <div style="margin-top:14px;padding:12px 14px;background:rgba(0,0,0,0.25);
                        border-radius:8px;border-left:3px solid #818cf8;">
                        <div style="font-size:11px;font-weight:700;text-transform:uppercase;
                            letter-spacing:0.07em;color:#64748b;margin-bottom:6px;">Resolution Steps</div>
                        <div style="font-size:13px;color:#94a3b8;line-height:1.7;">{s['resolution_steps']}</div>
                    </div>
                    """, unsafe_allow_html=True)
