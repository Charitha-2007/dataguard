"""
DataGuard ─ Intelligent Pipeline Reliability & Recovery Platform
Pure Streamlit command center — native components, custom theme, rich Plotly charts.
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
from plotly.subplots import make_subplots
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

# ─────────────────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="DataGuard Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Minimal CSS: only what Streamlit's theme can't do natively ───────────────
st.markdown("""
<style>
/* Smooth animated gradient on the very top bar */
header[data-testid="stHeader"] {
    background: linear-gradient(90deg,#0A0F1E,#0d1b40,#0A0F1E) !important;
    border-bottom: 1px solid rgba(0,201,255,0.12) !important;
}
/* Metric card lift on hover */
div[data-testid="metric-container"] {
    border-radius: 14px !important;
    padding: 18px !important;
    border: 1px solid rgba(0,201,255,0.14) !important;
    transition: transform .2s, box-shadow .2s;
}
div[data-testid="metric-container"]:hover {
    transform: translateY(-3px);
    box-shadow: 0 8px 32px rgba(0,201,255,.18);
}
/* Progress bar color */
.stProgress > div > div { background: linear-gradient(90deg,#00C9FF,#7C3AED) !important; }
/* Sidebar top padding */
[data-testid="stSidebar"] > div:first-child { padding-top: 1rem !important; }
/* Tab active color */
button[data-baseweb="tab"][aria-selected="true"] {
    color: #00C9FF !important;
    border-bottom: 2px solid #00C9FF !important;
}
/* Cleaner expander */
details summary { font-weight: 600 !important; }
/* Hide default streamlit footer */
footer { visibility: hidden; }
</style>
""", unsafe_allow_html=True)


# ── Plotly chart defaults ─────────────────────────────────────────────────────
CHART_COLORS = ["#00C9FF", "#7C3AED", "#10B981", "#F59E0B", "#F43F5E", "#8B5CF6"]

def styled_chart(fig, height=380, title=""):
    fig.update_layout(
        template="plotly_dark",
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(255,255,255,0.03)",
        height=height,
        title=dict(text=title, font=dict(size=14, color="#94A3B8"), x=0, pad=dict(l=4)),
        margin=dict(l=20, r=20, t=44 if title else 20, b=20),
        font=dict(family="Inter, sans-serif", size=12, color="#94A3B8"),
        xaxis=dict(gridcolor="rgba(255,255,255,0.05)", zeroline=False),
        yaxis=dict(gridcolor="rgba(255,255,255,0.05)", zeroline=False),
        legend=dict(bgcolor="rgba(0,0,0,0)", borderwidth=0),
        colorway=CHART_COLORS,
    )
    return fig


def grade_color(grade):
    return {"A": "🟢", "B": "🟢", "C": "🟡", "D": "🟠", "F": "🔴"}.get(grade, "⚪")


def severity_color(sev):
    return {"P1": "🔴", "P2": "🟠", "P3": "🟡", "P4": "🔵"}.get(sev, "⚪")


def status_icon(status):
    return {
        "OPEN": "🔥", "IN_REVIEW": "🔍",
        "RECOVERED": "✅", "CLOSED": "🔒",
        "SUCCESS": "✅", "FAILED": "❌", "RUNNING": "⚡",
    }.get(status, "❓")


# ─────────────────────────────────────────────────────────────────────────────
#  INIT
# ─────────────────────────────────────────────────────────────────────────────
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
recommender      = RecoveryRecommendationEngine(repo=repo)
workflow         = ApprovalWorkflowManager(repo=repo)
executor         = RecoveryExecutor(repo=repo, simulator=simulator)
verifier         = RecoveryVerifier(repo=repo, quality_engine=quality_engine)


# ─────────────────────────────────────────────────────────────────────────────
#  SIDEBAR
# ─────────────────────────────────────────────────────────────────────────────
with st.sidebar:
    # Brand
    st.markdown("## 🛡️ DataGuard")
    st.caption("Intelligent Pipeline Observability")
    st.divider()

    # Role selector
    st.markdown("**Active Profile**")
    role_map = {
        "🔑 Admin — Full Control":        ("admin",          "admin",    "admin@dataguard.local"),
        "⚙️ Engineer — Operations":        ("engineer_alice", "engineer", "alice@dataguard.local"),
        "👁️ Viewer — Read Only":           ("viewer_bob",     "viewer",   "bob@dataguard.local"),
    }
    chosen = st.selectbox("Role", list(role_map.keys()), label_visibility="collapsed")
    uname, urole, uemail = role_map[chosen]
    current_user = UserSession(username=uname, role=urole, email=uemail)

    role_colors = {"admin": "🟢 Full Access", "engineer": "🔵 Operations", "viewer": "🟡 Read-Only"}
    st.caption(role_colors[urole])
    st.divider()

    # Navigation
    st.markdown("**Navigation**")
    page = st.radio(
        "Go to",
        [
            "📊  Overview",
            "🧪  Simulator Lab",
            "🚨  Incidents & Recovery",
            "📈  Drift Explorer",
            "🛡️  Audit & Knowledge",
        ],
        label_visibility="collapsed",
    )
    st.divider()

    # Live status chip
    open_inc = repo.get_all_incidents(status="OPEN")
    if len(open_inc) == 0:
        st.success("✅ All Systems Healthy")
    else:
        st.error(f"🔥 {len(open_inc)} Active Incident(s)")

    st.caption(f"🕐 {datetime.now().strftime('%H:%M:%S')}  ·  DataGuard v1.0")


# ═════════════════════════════════════════════════════════════════════════════
#  PAGE 1 — OVERVIEW DASHBOARD
# ═════════════════════════════════════════════════════════════════════════════
if "Overview" in page:

    # Header
    st.title("📊 Pipeline Observability Dashboard")
    st.caption("Real-time SLA compliance, pipeline health scores, and execution telemetry across all data warehouse ingestion pipelines.")
    st.divider()

    # Pull data
    pipelines      = repo.get_all_pipelines()
    open_incidents = repo.get_all_incidents(status="OPEN")
    recent_runs    = repo.get_recent_runs(limit=60)
    audit_check    = audit_service.verify_integrity()

    # ── KPI Row ──────────────────────────────────────────────────────────────
    k1, k2, k3, k4, k5 = st.columns(5)
    k1.metric("🗂️ Pipelines", len(pipelines),     "Monitored")
    k2.metric("⚡ Total Runs", len(recent_runs),   "All Time")
    k3.metric("🔥 Open Incidents", len(open_incidents),
              "✅ Clear" if len(open_incidents) == 0 else f"⚠️ {len(open_incidents)} active",
              delta_color="inverse")

    successful = sum(1 for r in recent_runs if r.get("status") == "SUCCESS")
    success_rate = round(successful / len(recent_runs) * 100, 1) if recent_runs else 0
    k4.metric("✅ Success Rate", f"{success_rate}%", f"{successful}/{len(recent_runs)} runs")
    k5.metric("🔒 Audit Chain", "SHA-256",
              "✅ Verified" if audit_check["is_valid"] else "🔴 Tampered")

    st.divider()

    # ── Pipeline SLA Cards (native st.container + progress) ──────────────────
    st.subheader("⚡ Pipeline Health & SLA Compliance")

    sla_data = []
    p_cols = st.columns(len(pipelines))
    for i, p in enumerate(pipelines):
        rpt = sla_monitor.get_pipeline_compliance(p["id"])
        sla_data.append({
            "Pipeline": p["name"].replace("_", " ").title(),
            "Avg (s)":   rpt.average_duration_seconds,
            "P95 (s)":   rpt.p95_duration_seconds,
            "SLA (s)":   p["sla_seconds"],
            "Compliance": rpt.compliance_percentage,
        })
        with p_cols[i]:
            with st.container(border=True):
                g_icon = grade_color(rpt.health_grade)
                st.markdown(f"**{p['name'].replace('_',' ').title()}**")
                st.caption(f"{p['source_type'].upper()} · SLA {p['sla_seconds']}s")
                st.metric(
                    f"{g_icon} Grade {rpt.health_grade}",
                    f"{rpt.compliance_percentage}%",
                    f"P95: {rpt.p95_duration_seconds}s",
                    delta_color="normal" if rpt.health_grade in ("A","B") else "inverse",
                )
                score = int(rpt.compliance_percentage)
                st.progress(min(score, 100) / 100)

    st.divider()

    # ── Two-column charts ─────────────────────────────────────────────────────
    chart_left, chart_right = st.columns([3, 2], gap="medium")

    with chart_left:
        df_sla = pd.DataFrame(sla_data)
        fig_bar = go.Figure()
        fig_bar.add_trace(go.Bar(
            name="Avg Duration", x=df_sla["Pipeline"], y=df_sla["Avg (s)"],
            marker_color="#00C9FF", marker_opacity=0.85,
        ))
        fig_bar.add_trace(go.Bar(
            name="P95 Latency", x=df_sla["Pipeline"], y=df_sla["P95 (s)"],
            marker_color="#7C3AED", marker_opacity=0.85,
        ))
        fig_bar.add_trace(go.Scatter(
            name="SLA Budget", x=df_sla["Pipeline"], y=df_sla["SLA (s)"],
            mode="lines+markers",
            line=dict(color="#F43F5E", width=2.5, dash="dot"),
            marker=dict(size=8),
        ))
        fig_bar.update_layout(barmode="group")
        styled_chart(fig_bar, 340, "⏱️ Latency vs SLA Budget")
        st.plotly_chart(fig_bar, use_container_width=True)

    with chart_right:
        # Run status donut
        if recent_runs:
            status_counts = pd.Series([r["status"] for r in recent_runs]).value_counts()
            color_map = {"SUCCESS": "#10B981", "FAILED": "#F43F5E", "RUNNING": "#F59E0B"}
            colors = [color_map.get(s, "#64748B") for s in status_counts.index]
            fig_donut = go.Figure(go.Pie(
                labels=status_counts.index,
                values=status_counts.values,
                hole=0.62,
                marker=dict(colors=colors, line=dict(color="#0A0F1E", width=3)),
                textinfo="percent",
                textfont=dict(size=12),
                hovertemplate="%{label}: %{value} runs<extra></extra>",
            ))
            fig_donut.add_annotation(
                text=f"<b>{len(recent_runs)}</b><br><span style='font-size:11px'>Runs</span>",
                showarrow=False, font=dict(size=16, color="#E2E8F0"), x=0.5, y=0.5,
            )
            styled_chart(fig_donut, 340, "🍩 Run Status Distribution")
            st.plotly_chart(fig_donut, use_container_width=True)
        else:
            st.info("No run data yet.")

    # ── Recent Runs Table ─────────────────────────────────────────────────────
    st.subheader("📜 Recent Execution Runs")
    if recent_runs:
        df_runs = pd.DataFrame(recent_runs)
        display_cols = [c for c in ["run_id","pipeline_name","status","started_at","duration_seconds","row_count","error_message"] if c in df_runs.columns]
        df_runs = df_runs[display_cols].copy()
        df_runs.insert(0, "⚡", df_runs["status"].map(status_icon))
        st.dataframe(
            df_runs.drop(columns=["status"]),
            use_container_width=True,
            hide_index=True,
            column_config={
                "⚡":               st.column_config.TextColumn("", width="small"),
                "run_id":           st.column_config.TextColumn("Run ID"),
                "pipeline_name":    st.column_config.TextColumn("Pipeline"),
                "started_at":       st.column_config.TextColumn("Started"),
                "duration_seconds": st.column_config.NumberColumn("Duration (s)", format="%.1f"),
                "row_count":        st.column_config.NumberColumn("Rows"),
                "error_message":    st.column_config.TextColumn("Error"),
            },
        )
    else:
        st.info("No runs yet — go to **Simulator Lab** to trigger your first run!")


# ═════════════════════════════════════════════════════════════════════════════
#  PAGE 2 — SIMULATOR LAB
# ═════════════════════════════════════════════════════════════════════════════
elif "Simulator" in page:

    st.title("🧪 Pipeline Simulator & Chaos Fault Lab")
    st.caption("Inject controlled failures into your pipelines to test DataGuard's detection, root-cause analysis, and self-healing recovery.")
    st.divider()

    cfg_col, out_col = st.columns([1, 1], gap="large")

    with cfg_col:
        st.subheader("⚙️ Configure Run")

        with st.container(border=True):
            pipeline_choice = st.selectbox(
                "🗄️ Target Pipeline",
                ["crm_customers_etl", "billing_transactions_sync"],
                format_func=lambda x: "CRM Customer Profiles ETL" if x == "crm_customers_etl" else "Billing Transactions Sync",
            )

            fault_choice = st.selectbox(
                "💥 Fault Injection Mode",
                [
                    "None — Clean Healthy Run",
                    "NULL_SPIKE — 35 % Missing Values",
                    "SCHEMA_MISMATCH — API Breaking Column Rename",
                    "ANOMALY_VALUES — Negative Balances & Outliers",
                    "SLA_BREACH — Latency / Lock Hang",
                    "VOLUME_DROP — Premature Drop (5 rows)",
                ],
            )

            fault_key = None
            for fk in ["NULL_SPIKE","SCHEMA_MISMATCH","ANOMALY_VALUES","SLA_BREACH","VOLUME_DROP"]:
                if fk in fault_choice:
                    fault_key = fk
                    break

            # Fault info card
            fault_info = {
                None:              ("✅", "Clean run — no faults injected."),
                "NULL_SPIKE":      ("🕳️", "35 % of key fields will be set to NULL, triggering data quality alerts."),
                "SCHEMA_MISMATCH": ("🔀", "A column will be renamed, breaking downstream schema contracts."),
                "ANOMALY_VALUES":  ("📉", "Extreme outliers and negative values injected into numeric fields."),
                "SLA_BREACH":      ("⏰", "Pipeline runtime will exceed the configured SLA budget."),
                "VOLUME_DROP":     ("📦", "Output truncated to 5 rows, triggering volume anomaly detection."),
            }
            icon, desc = fault_info.get(fault_key, ("ℹ️", ""))
            st.info(f"{icon} **{fault_key or 'No Fault'}** — {desc}")

            if not current_user.can_trigger_pipeline:
                st.error("⛔ Viewer role cannot trigger runs. Switch to Admin or Engineer.")
                trigger = st.button("🚀 Trigger Pipeline Run", disabled=True)
                trigger = False
            else:
                trigger = st.button("🚀 Trigger Pipeline Run", type="primary", use_container_width=True)

    with out_col:
        st.subheader("📡 Real-Time Telemetry")

        if trigger:
            with st.status("⚡ Executing pipeline...", expanded=True) as exec_status:
                st.write("🔄 Loading pipeline metadata...")
                pipeline_meta = repo.get_pipeline(pipeline_choice)

                st.write("⚙️ Generating data batch with fault injection...")
                run, df = simulator.run_pipeline(pipeline_id=pipeline_choice, fault_type=fault_key)

                st.write("🔍 Evaluating data contracts & quality rules...")
                quality_report = quality_engine.evaluate(pipeline_choice, df)

                st.write("📊 Computing statistical drift...")
                ref_df = simulator.generate_crm_data(250) if pipeline_choice == "crm_customers_etl" else simulator.generate_billing_data(250)
                num_col = "account_balance" if pipeline_choice == "crm_customers_etl" else "amount"
                drift_report = drift_detector.evaluate(pipeline_choice, ref_df, df, [num_col])

                st.write("🧠 Running Root Cause Analysis (RCA)...")
                diagnosis = rca_engine.diagnose(
                    pipeline_id=pipeline_choice,
                    sla_seconds=pipeline_meta["sla_seconds"],
                    duration_seconds=run.duration_seconds,
                    row_count=run.row_count,
                    quality_report=quality_report,
                    drift_report=drift_report,
                )
                impact_report = impact_analyzer.analyze_impact(pipeline_choice)
                run_status = "FAILED" if diagnosis else "SUCCESS"

                st.write("💾 Persisting run record to database...")
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
                    st.write("🚨 Creating incident & recovery plan...")
                    incident = incident_manager.create_incident(
                        run_id=run.run_id,
                        pipeline_id=pipeline_choice,
                        diagnosis=diagnosis,
                        impact_report=impact_report,
                    )
                    plan = recommender.generate_plan(
                        incident_type=diagnosis.incident_type,
                        pipeline_id=pipeline_choice,
                        corrupted_indices=quality_report.corrupted_indices,
                        raw_data_path=run.raw_data_path,
                    )
                    workflow.submit_recovery_request(incident.incident_code, pipeline_choice, plan)

                exec_status.update(
                    label="✅ Pipeline Complete" if run_status == "SUCCESS" else "❌ Failure Detected",
                    state="complete" if run_status == "SUCCESS" else "error",
                )

            # ── Results ───────────────────────────────────────────────────────
            st.divider()
            if run_status == "SUCCESS":
                st.success(f"✅ **Pipeline ran cleanly!** Run ID: `{run.run_id}`")
                r1, r2, r3 = st.columns(3)
                r1.metric("Quality Score",   f"{quality_report.quality_score}%", "All Checks Passed")
                r2.metric("Rows Processed",  run.row_count,                     "No Issues")
                r3.metric("Duration",         f"{run.duration_seconds}s",        f"SLA: {pipeline_meta['sla_seconds']}s")
            else:
                sev_icon = severity_color(diagnosis.severity)
                st.error(f"{sev_icon} **{diagnosis.incident_type}** detected — Severity **{diagnosis.severity}**")

                with st.container(border=True):
                    c1, c2 = st.columns(2)
                    c1.metric("Quality Score",    f"{quality_report.quality_score}%", delta_color="inverse")
                    c2.metric("Severity",          diagnosis.severity)
                    st.markdown(f"**🧠 Root Cause:**  {diagnosis.root_cause_summary}")
                    st.markdown(f"**💥 Blast Radius:** {impact_report.impact_summary}")
                    st.markdown(f"**📋 Incident:** `{incident.incident_code}` → go to **Incidents & Recovery**")

            # ── Data Preview ──────────────────────────────────────────────────
            with st.expander("🔎 Data Sample Preview (first 10 rows)", expanded=False):
                st.dataframe(df.head(10), use_container_width=True, hide_index=True)

            # ── Quality Radar ─────────────────────────────────────────────────
            with st.expander("📊 Quality Metrics Breakdown", expanded=True):
                qd = quality_report.to_dict()
                if "checks" in qd:
                    checks = qd["checks"]
                    cats   = list(checks.keys())
                    vals   = [100 if v else 0 for v in checks.values()]
                    fig_r  = go.Figure(go.Scatterpolar(
                        r=vals + [vals[0]], theta=cats + [cats[0]],
                        fill="toself",
                        line=dict(color="#00C9FF", width=2),
                        fillcolor="rgba(0,201,255,0.12)",
                    ))
                    fig_r.update_layout(
                        polar=dict(
                            radialaxis=dict(visible=True, range=[0,100], gridcolor="rgba(255,255,255,0.08)"),
                            angularaxis=dict(gridcolor="rgba(255,255,255,0.08)"),
                            bgcolor="rgba(0,0,0,0)",
                        )
                    )
                    styled_chart(fig_r, 300, "Quality Check Results")
                    st.plotly_chart(fig_r, use_container_width=True)
                else:
                    st.metric("Overall Quality Score", f"{quality_report.quality_score}%")

        else:
            with st.container(border=True):
                st.markdown("""
                ### 👈 Configure your run on the left

                **What this lab does:**
                - Generates a synthetic data batch from your selected pipeline
                - Optionally injects a controlled fault to simulate real-world failures
                - Runs the full DataGuard analysis stack:
                  - 📋 **Data Quality Engine** — schema, null, range, category checks
                  - 📊 **Drift Detector** — PSI + KS-Test statistical analysis
                  - 🧠 **RCA Engine** — multi-criteria root cause diagnosis
                  - 💥 **Impact Analyzer** — downstream DAG blast radius
                  - 🚨 **Incident Manager** — auto-creates tickets for failures
                  - 🛠️ **Recovery Engine** — proposes and queues remediation actions
                """)


# ═════════════════════════════════════════════════════════════════════════════
#  PAGE 3 — INCIDENTS & RECOVERY
# ═════════════════════════════════════════════════════════════════════════════
elif "Incidents" in page:

    st.title("🚨 Incident Triage & Self-Healing Recovery")
    st.caption("Inspect active pipeline failures, trace downstream blast radius, and authorize RBAC-gated recovery actions.")
    st.divider()

    all_incidents = repo.get_all_incidents()

    if not all_incidents:
        st.success("🎉 **All Clear!** No incidents detected. All pipelines are operating within healthy SLA bounds.")
        st.balloons()
    else:
        # ── Summary row ───────────────────────────────────────────────────────
        status_counts = {}
        severity_counts = {}
        for inc in all_incidents:
            status_counts[inc["status"]] = status_counts.get(inc["status"], 0) + 1
            severity_counts[inc["severity"]] = severity_counts.get(inc["severity"], 0) + 1

        s1, s2, s3, s4 = st.columns(4)
        s1.metric("🔥 Open",       status_counts.get("OPEN", 0))
        s2.metric("🔍 In Review",  status_counts.get("IN_REVIEW", 0))
        s3.metric("✅ Recovered",  status_counts.get("RECOVERED", 0))
        s4.metric("🔒 Closed",     status_counts.get("CLOSED", 0))
        st.divider()

        # ── Incident selector ─────────────────────────────────────────────────
        inc_options = {
            f"{severity_color(i['severity'])} {i['incident_code']}  ·  {i['pipeline_id']}  [{i['status']}]": i
            for i in all_incidents
        }
        chosen_label = st.selectbox("🔎 Select Incident", list(inc_options.keys()))
        inc = inc_options[chosen_label]

        st.divider()
        left, right = st.columns([1, 1], gap="large")

        # ── LEFT: Details + DAG ───────────────────────────────────────────────
        with left:
            st.subheader(f"📋 {inc['incident_code']}")

            with st.container(border=True):
                d1, d2 = st.columns(2)
                d1.metric("Severity",  inc["severity"])
                d2.metric("Status",    f"{status_icon(inc['status'])} {inc['status']}")

                st.markdown(f"**Pipeline:** `{inc['pipeline_id']}`")
                st.markdown(f"**Failure Type:** `{inc['incident_type']}`")
                st.markdown(f"**Assigned To:** `{inc['assigned_to']}`")
                st.info(f"🧠 **Root Cause:** {inc['root_cause_summary']}")

            # DAG chart
            st.subheader("🌐 Blast Radius — Downstream DAG")
            impact = impact_analyzer.analyze_impact(inc["pipeline_id"])
            st.caption(impact.impact_summary)

            nodes  = impact.graph_nodes
            x_pos  = [0.2 if n["id"] == inc["pipeline_id"] else 0.8 for n in nodes]
            y_pos  = list(range(len(nodes)))
            colors = ["#F43F5E" if n["status"] == "FAILED" else "#F59E0B" for n in nodes]
            labels = [n["label"] for n in nodes]

            fig_dag = go.Figure()
            # Draw edges from source to downstream nodes
            for idx, n in enumerate(nodes):
                if n["id"] != inc["pipeline_id"]:
                    src_idx = next((j for j, m in enumerate(nodes) if m["id"] == inc["pipeline_id"]), 0)
                    fig_dag.add_trace(go.Scatter(
                        x=[x_pos[src_idx], x_pos[idx]], y=[y_pos[src_idx], y_pos[idx]],
                        mode="lines",
                        line=dict(color="rgba(248,113,113,0.3)", width=2, dash="dot"),
                        showlegend=False,
                    ))
            fig_dag.add_trace(go.Scatter(
                x=x_pos, y=y_pos,
                mode="markers+text",
                text=labels,
                textposition="middle right",
                textfont=dict(size=11, color="#94A3B8"),
                marker=dict(size=28, color=colors,
                            line=dict(color="rgba(255,255,255,0.2)", width=2)),
                showlegend=False,
                hovertemplate="%{text}<extra></extra>",
            ))
            fig_dag.update_layout(
                xaxis=dict(showgrid=False, zeroline=False, showticklabels=False, range=[-0.1, 1.5]),
                yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            )
            styled_chart(fig_dag, 220)
            st.plotly_chart(fig_dag, use_container_width=True)

        # ── RIGHT: Recovery ───────────────────────────────────────────────────
        with right:
            st.subheader("🛠️ Recovery Actions")
            actions = repo.get_recovery_actions_for_incident(inc["incident_code"])

            if not actions:
                st.info("📭 No recovery action has been proposed for this incident yet.")
                st.caption("Run the pipeline in **Simulator Lab** to auto-generate a recovery plan.")
            else:
                action        = actions[0]
                action_id     = action["id"]
                action_status = action["status"]

                with st.container(border=True):
                    a1, a2 = st.columns(2)
                    a1.metric("Action ID",   f"#{action_id}")
                    a2.metric("Status",      action_status)
                    st.markdown(f"**Type:** `{action['action_type']}`")
                    st.markdown(f"**Requested By:** `{action['requested_by']}`")

                st.divider()

                if action_status == "PENDING_APPROVAL":
                    st.warning("⚠️ This action is awaiting human approval before it can execute.")

                    if not current_user.can_approve_recovery:
                        st.error("⛔ Your role (**Viewer**) cannot approve recovery actions.")
                        st.button("✅ Authorize & Execute", disabled=True, use_container_width=True)
                    else:
                        st.markdown(f"**Approver:** `{current_user.username}` ({current_user.role})")
                        if st.button("✅ Authorize & Execute Recovery", type="primary", use_container_width=True):
                            with st.status("⚡ Executing recovery...", expanded=True) as rec_status:
                                st.write("✅ Approval recorded...")
                                workflow.approve_recovery(action_id, approved_by=current_user.username, user_role=current_user.role)
                                st.write("🛠️ Executing remediation action...")
                                success, exec_log, recovered_df = executor.execute(action_id)
                                if success and recovered_df is not None:
                                    st.write("🔍 Verifying recovered data quality...")
                                    is_verified, v_rep = verifier.verify(
                                        action_id=action_id,
                                        pipeline_id=inc["pipeline_id"],
                                        recovered_df=recovered_df,
                                        execution_log=exec_log,
                                        actor=current_user.username,
                                    )
                                    if is_verified:
                                        rec_status.update(label="✅ Recovery Verified!", state="complete")
                                        st.success(f"🎉 Recovery complete! Quality: **{v_rep.quality_score}%**")
                                        st.metric("Post-Recovery Quality", f"{v_rep.quality_score}%", "Verified Healthy")
                                        st.progress(v_rep.quality_score / 100)
                                        st.rerun()
                                    else:
                                        rec_status.update(label="❌ Verification Failed", state="error")
                                        st.error(f"Quality too low: {v_rep.quality_score}%")
                                else:
                                    rec_status.update(label="❌ Execution Failed", state="error")
                                    st.error(f"Error: {exec_log}")

                elif action_status in ("COMPLETED", "APPROVED"):
                    st.success("🛡️ Recovery has been executed and verified!")
                    with st.container(border=True):
                        st.markdown(f"**Approved By:** `{action['approved_by']}`")
                        st.markdown(f"**Approved At:** `{action['approved_at']}`")
                        st.markdown(f"**Verification:** {'✅ Verified Healthy' if action['is_verified'] else '❌ Unverified'}")
                        with st.expander("📋 Execution Log"):
                            st.code(action["execution_log"])


# ═════════════════════════════════════════════════════════════════════════════
#  PAGE 4 — DRIFT EXPLORER
# ═════════════════════════════════════════════════════════════════════════════
elif "Drift" in page:

    st.title("📈 Statistical Drift & ML Anomaly Explorer")
    st.caption("Detect distribution shifts using PSI, Kolmogorov-Smirnov test, and Isolation Forest anomaly detection.")
    st.divider()

    # Controls row
    ctrl1, ctrl2, ctrl3 = st.columns([2, 2, 1])
    with ctrl1:
        drift_pipeline = st.selectbox(
            "🗄️ Pipeline",
            ["crm_customers_etl", "billing_transactions_sync"],
            format_func=lambda x: "CRM Customer Profiles ETL" if x == "crm_customers_etl" else "Billing Transactions Sync",
        )
    with ctrl2:
        shift = st.slider("📉 Shift Multiplier", 1.0, 8.0, 2.5, 0.25,
                          help="1.0 = Baseline · 3-4 = Moderate · 6+ = Extreme Drift")
    with ctrl3:
        st.markdown("<br>", unsafe_allow_html=True)
        run_drift = st.button("🔍 Analyse", type="primary", use_container_width=True)

    st.divider()

    # Generate data
    np.random.seed(42)
    if drift_pipeline == "crm_customers_etl":
        ref_df, cur_df, col = simulator.generate_crm_data(400), simulator.generate_crm_data(400), "account_balance"
    else:
        ref_df, cur_df, col = simulator.generate_billing_data(400), simulator.generate_billing_data(400), "amount"
    cur_df[col] = cur_df[col] * shift

    report    = drift_detector.evaluate(drift_pipeline, ref_df, cur_df, [col])
    drift_res = report.column_drifts[col]
    psi       = drift_res.psi_score
    ks_p      = drift_res.ks_pvalue
    sev       = drift_res.drift_severity

    # ── Results KPIs ──────────────────────────────────────────────────────────
    r1, r2, r3, r4 = st.columns(4)
    r1.metric("📊 PSI Score",     f"{psi:.4f}",    f"Threshold >{DEFAULT_PSI_DRIFT_THRESHOLD}")
    r2.metric("📐 KS p-value",    f"{ks_p:.4f}",   "< 0.05 = Drift Detected")
    r3.metric("🌡️ Severity",      sev)
    r4.metric("🔀 Shift Applied", f"{shift}×",     f"Column: {col}")

    if sev == "CRITICAL":
        st.error(f"🚨 {drift_res.message}")
    elif sev == "MODERATE":
        st.warning(f"⚠️ {drift_res.message}")
    else:
        st.success(f"✅ {drift_res.message}")

    st.divider()

    # ── Charts row ────────────────────────────────────────────────────────────
    ch1, ch2 = st.columns([3, 2], gap="medium")

    with ch1:
        # Overlay histogram
        fig_hist = go.Figure()
        fig_hist.add_trace(go.Histogram(
            x=ref_df[col], name="Baseline (Reference)",
            nbinsx=50, marker_color="#00C9FF", opacity=0.6,
        ))
        fig_hist.add_trace(go.Histogram(
            x=cur_df[col], name="Current Batch",
            nbinsx=50, marker_color="#F43F5E", opacity=0.6,
        ))
        fig_hist.update_layout(barmode="overlay")
        styled_chart(fig_hist, 360, f"📊 Distribution Overlay — '{col}'")
        st.plotly_chart(fig_hist, use_container_width=True)

    with ch2:
        # PSI Gauge
        gauge_color = "#10B981" if psi < 0.1 else ("#F59E0B" if psi < 0.2 else "#F43F5E")
        fig_gauge = go.Figure(go.Indicator(
            mode="gauge+number",
            value=float(psi),
            number=dict(font=dict(size=36, color="#E2E8F0"), valueformat=".4f"),
            title=dict(text="PSI Score", font=dict(size=13, color="#94A3B8")),
            gauge=dict(
                axis=dict(range=[0, 0.5], tickformat=".2f", tickcolor="#64748B"),
                bar=dict(color=gauge_color, thickness=0.3),
                bgcolor="rgba(0,0,0,0)",
                bordercolor="rgba(255,255,255,0.08)",
                steps=[
                    dict(range=[0, 0.1],  color="rgba(16,185,129,0.1)"),
                    dict(range=[0.1, 0.2],color="rgba(245,158,11,0.1)"),
                    dict(range=[0.2, 0.5],color="rgba(244,63,94,0.1)"),
                ],
                threshold=dict(
                    line=dict(color="#F43F5E", width=2),
                    value=DEFAULT_PSI_DRIFT_THRESHOLD,
                    thickness=0.8,
                ),
            ),
        ))
        fig_gauge.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            font_color="#94A3B8",
            height=360,
            margin=dict(l=30, r=30, t=50, b=20),
        )
        st.plotly_chart(fig_gauge, use_container_width=True)

    # ── Box plots side by side ────────────────────────────────────────────────
    with st.expander("📦 Statistical Box Plot Comparison", expanded=True):
        df_box = pd.concat([
            ref_df[[col]].assign(Source="Baseline"),
            cur_df[[col]].assign(Source="Current"),
        ])
        fig_box = px.box(
            df_box, x="Source", y=col, color="Source",
            color_discrete_map={"Baseline": "#00C9FF", "Current": "#F43F5E"},
            points="outliers",
        )
        styled_chart(fig_box, 300, "Distribution Spread & Outliers")
        st.plotly_chart(fig_box, use_container_width=True)


# ═════════════════════════════════════════════════════════════════════════════
#  PAGE 5 — AUDIT & KNOWLEDGE BASE
# ═════════════════════════════════════════════════════════════════════════════
elif "Audit" in page:

    st.title("🛡️ Audit Ledger & Knowledge Base")
    st.caption("Tamper-evident SHA-256 hash chain audit log and searchable institutional knowledge repository.")
    st.divider()

    tab_audit, tab_kb, tab_integrity = st.tabs([
        "🔒  Audit Log",
        "📚  Knowledge Base",
        "🔑  Chain Integrity",
    ])

    # ── TAB 1: Audit Log ──────────────────────────────────────────────────────
    with tab_audit:
        st.subheader("📋 Audit Trail Explorer")
        col_f1, col_f2 = st.columns([2, 1])
        with col_f1:
            actor_filter = st.text_input("🔍 Filter by Actor", placeholder="admin · simulator_engine · engineer_alice")
        with col_f2:
            limit_filter = st.number_input("Max Rows", min_value=10, max_value=500, value=100, step=10)

        records = audit_service.get_audit_trail(limit=int(limit_filter), actor=actor_filter or None)

        if records:
            df_audit = pd.DataFrame(records)[["id","timestamp","actor","action","entity_type","entity_id","record_hash"]]
            st.dataframe(
                df_audit, use_container_width=True, hide_index=True,
                column_config={
                    "id":          st.column_config.NumberColumn("#", width="small"),
                    "timestamp":   st.column_config.TextColumn("Timestamp"),
                    "actor":       st.column_config.TextColumn("Actor"),
                    "action":      st.column_config.TextColumn("Action"),
                    "entity_type": st.column_config.TextColumn("Entity"),
                    "entity_id":   st.column_config.TextColumn("Entity ID"),
                    "record_hash": st.column_config.TextColumn("SHA-256 Hash"),
                },
            )
            csv = df_audit.to_csv(index=False).encode("utf-8")
            st.download_button("📥 Export as CSV", data=csv,
                               file_name="dataguard_audit.csv", mime="text/csv")

            # Action distribution chart
            with st.expander("📊 Action Distribution Chart"):
                action_counts = df_audit["action"].value_counts().reset_index()
                action_counts.columns = ["action", "count"]
                fig_actions = px.bar(
                    action_counts, x="count", y="action", orientation="h",
                    color="count",
                    color_continuous_scale=["#1e3a5f", "#00C9FF"],
                )
                styled_chart(fig_actions, 280, "Events by Action Type")
                st.plotly_chart(fig_actions, use_container_width=True)
        else:
            st.info("No records found with the current filter.")

    # ── TAB 2: Knowledge Base ─────────────────────────────────────────────────
    with tab_kb:
        st.subheader("📚 Failure Resolution Knowledge Base")
        search = st.text_input("🔍 Search Solutions", placeholder="schema · null · timeout · SLA · drift · volume")
        solutions = kb_service.search_solutions(search) if search else kb_service.get_all_solutions()

        if not solutions:
            st.warning("No solutions found. Try a different keyword.")
        else:
            st.caption(f"Found **{len(solutions)}** solution(s)")
            for s in solutions:
                with st.expander(f"📌  {s['incident_type']}  ·  Applied {s['times_used']}× successfully"):
                    col_a, col_b = st.columns([1, 1])
                    with col_a:
                        st.markdown("**Error Pattern**")
                        st.code(s["error_pattern"], language="text")
                        st.markdown("**Recommended Action**")
                        st.code(s["recommended_action"], language="text")
                    with col_b:
                        st.markdown("**Root Cause**")
                        st.info(s["root_cause"])
                        st.markdown("**Resolution Steps**")
                        st.markdown(s["resolution_steps"])
                    st.metric("Times Successfully Applied", s["times_used"])
                    st.progress(min(s["times_used"] / 10, 1.0))

    # ── TAB 3: Chain Integrity ────────────────────────────────────────────────
    with tab_integrity:
        st.subheader("🔑 SHA-256 Hash Chain Integrity Verification")
        st.caption("Every audit log entry is cryptographically chained. Any tampering breaks the chain.")

        with st.spinner("Verifying hash chain..."):
            integrity = audit_service.verify_integrity()

        if integrity["is_valid"]:
            st.success(f"✅ **CHAIN VERIFIED** — {integrity['total_checked']} records checked. Zero tampering detected.")
            st.metric("Records Verified", integrity["total_checked"], "Unbroken Chain")
            st.progress(1.0)
        else:
            st.error(f"🔴 **TAMPERING DETECTED** — {integrity.get('reason', 'Unknown error')}")
            st.metric("Integrity Status", "COMPROMISED", delta_color="inverse")

        with st.expander("ℹ️ How the Hash Chain Works"):
            st.markdown("""
            Each audit log record contains:
            1. **Its own data** (action, actor, entity, timestamp)
            2. **A SHA-256 hash** computed from its data + the previous record's hash

            This creates a **tamper-evident chain** — if any record is modified:
            - Its hash no longer matches
            - Every subsequent record's hash also breaks
            - The verification scan immediately detects the breach

            This is the same principle used by **Bitcoin's blockchain** and **certificate transparency logs**.
            """)
