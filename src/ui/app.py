"""DataGuard - Intelligent Data Pipeline Observability & Automated Recovery Platform.

Streamlit Interactive Command Center with Figma-Grade Design System:
- Luxury Dark-Mode Glassmorphism UI
- Real-Time Pipeline Telemetry & SLA Tracking
- Interactive Chaos Simulator & Fault Lab
- Incident Triage, Root Cause Analysis (RCA), and Plotly DAG Blast Radius
- Approval-Gated Self-Healing Recovery with Post-Verification
- Statistical Data Drift (PSI, KS-Test, Isolation Forest)
- Cryptographically Verified Audit Ledger & Knowledge Repository
"""

import sys
from pathlib import Path

# Ensure project root is in sys.path for Docker and standalone executions
ROOT_DIR = Path(__file__).resolve().parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
import json
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

# Set Page Config
st.set_page_config(
    page_title="DataGuard | Observability & Self-Healing",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# =====================================================================
# FIGMA-GRADE DESIGN SYSTEM & CUSTOM CSS
# =====================================================================

FIGMA_CSS = """
<style>
    @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap');

    :root {
        --bg-main: #0B0F19;
        --card-bg: rgba(17, 24, 39, 0.75);
        --card-border: rgba(255, 255, 255, 0.08);
        --accent-cyan: #06B6D4;
        --accent-blue: #3B82F6;
        --accent-emerald: #10B981;
        --accent-amber: #F59E0B;
        --accent-rose: #EF4444;
        --text-primary: #F9FAFB;
        --text-muted: #9CA3AF;
    }

    html, body, [class*="st-"] {
        font-family: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, sans-serif;
    }

    /* Main background with subtle radial mesh */
    .stApp {
        background: radial-gradient(circle at 10% 20%, rgba(14, 23, 42, 0.85) 0%, rgba(11, 15, 25, 1) 90%);
        color: var(--text-primary);
    }

    /* Sidebar Styling */
    [data-testid="stSidebar"] {
        background-color: #0d121f !important;
        border-right: 1px solid rgba(255, 255, 255, 0.06);
    }

    /* Figma Metric Cards */
    div[data-testid="metric-container"] {
        background: var(--card-bg);
        border: 1px solid var(--card-border);
        border-radius: 14px;
        padding: 16px 20px;
        backdrop-filter: blur(16px);
        box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.35);
        transition: transform 0.2s ease, border-color 0.2s ease;
    }
    div[data-testid="metric-container"]:hover {
        transform: translateY(-2px);
        border-color: rgba(6, 182, 212, 0.4);
    }

    /* Glassmorphism Card Container */
    .figma-card {
        background: var(--card-bg);
        border: 1px solid var(--card-border);
        border-radius: 14px;
        padding: 20px;
        backdrop-filter: blur(16px);
        box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.35);
        margin-bottom: 16px;
    }

    /* Pill Badges */
    .badge-pill {
        display: inline-block;
        padding: 3px 10px;
        border-radius: 9999px;
        font-size: 11px;
        font-weight: 700;
        letter-spacing: 0.04em;
        text-transform: uppercase;
    }
    .badge-emerald { background: rgba(16, 185, 129, 0.15); color: #10B981; border: 1px solid rgba(16, 185, 129, 0.3); }
    .badge-amber { background: rgba(245, 158, 11, 0.15); color: #F59E0B; border: 1px solid rgba(245, 158, 11, 0.3); }
    .badge-rose { background: rgba(239, 68, 68, 0.15); color: #EF4444; border: 1px solid rgba(239, 68, 68, 0.3); }
    .badge-cyan { background: rgba(6, 182, 212, 0.15); color: #06B6D4; border: 1px solid rgba(6, 182, 212, 0.3); }

    /* Modern Primary & Action Buttons */
    .stButton > button {
        border-radius: 10px;
        font-weight: 600;
        padding: 8px 18px;
        transition: all 0.2s ease;
    }
    .stButton > button[kind="primary"] {
        background: linear-gradient(135deg, #06B6D4 0%, #3B82F6 100%) !important;
        border: none !important;
        color: white !important;
        box-shadow: 0 4px 16px 0 rgba(6, 182, 212, 0.4);
    }
    .stButton > button[kind="primary"]:hover {
        box-shadow: 0 6px 24px rgba(6, 182, 212, 0.65);
        transform: translateY(-1px);
    }

    /* Sleek Tables */
    div[data-testid="stDataFrame"] {
        background: var(--card-bg);
        border: 1px solid var(--card-border);
        border-radius: 14px;
        overflow: hidden;
    }

    /* Headings & Dividers */
    h1, h2, h3, h4 {
        color: #F9FAFB !important;
        font-weight: 700 !important;
        letter-spacing: -0.02em;
    }
    hr {
        border-color: rgba(255, 255, 255, 0.08) !important;
    }
</style>
"""
st.markdown(FIGMA_CSS, unsafe_allow_html=True)


def apply_figma_chart_theme(fig):
    """Applies Figma dark-mode aesthetics to Plotly charts."""
    fig.update_layout(
        template="plotly_dark",
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(17, 24, 39, 0.4)",
        font=dict(family="Plus Jakarta Sans", color="#9CA3AF"),
        margin=dict(l=20, r=20, t=35, b=20),
        xaxis=dict(gridcolor="rgba(255, 255, 255, 0.05)", zeroline=False),
        yaxis=dict(gridcolor="rgba(255, 255, 255, 0.05)", zeroline=False),
    )
    return fig


# Initialize database schema if first launch
init_db()

# Initialize Core Services
repo = DataGuardRepository()
simulator = PipelineSimulator(repo=repo)
quality_engine = DataQualityEngine()
drift_detector = DriftAnomalyDetector()
rca_engine = RootCauseAnalysisEngine()
impact_analyzer = DependencyImpactAnalyzer(repo=repo)
sla_monitor = SLAMonitor(repo=repo)
notifier = NotificationDispatcher()
incident_manager = IncidentManager(repo=repo, notifier=notifier)
audit_service = AuditService(repo=repo)
kb_service = KnowledgeBaseService(repo=repo)
auth_service = AuthService()
recommender = RecoveryRecommendationEngine(repo=repo)
workflow = ApprovalWorkflowManager(repo=repo)
executor = RecoveryExecutor(repo=repo, simulator=simulator)
verifier = RecoveryVerifier(repo=repo, quality_engine=quality_engine)


# =====================================================================
# SIDEBAR: USER AUTHENTICATION & ROLE SWITCHER (RBAC)
# =====================================================================

st.sidebar.markdown(
    """
    <div style="display:flex; align-items:center; gap:12px; margin-bottom:12px;">
        <span style="font-size:32px;">🛡️</span>
        <div>
            <h2 style="margin:0; font-size:20px; font-weight:800; background:linear-gradient(135deg, #06B6D4, #3B82F6); -webkit-background-clip:text; -webkit-text-fill-color:transparent;">DataGuard</h2>
            <p style="margin:0; font-size:11px; color:#9CA3AF; text-transform:uppercase; letter-spacing:0.06em;">Data Observability Platform</p>
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)
st.sidebar.markdown("---")

st.sidebar.subheader("👤 Role-Based Access Control")
user_choice = st.sidebar.selectbox(
    "Active Profile",
    options=["admin (Full Control)", "engineer_alice (Operations)", "viewer_bob (Read-Only)"],
    index=0,
)

if "admin" in user_choice:
    current_user = UserSession(username="admin", role="admin", email="admin@dataguard.local")
elif "engineer" in user_choice:
    current_user = UserSession(username="engineer_alice", role="engineer", email="alice@dataguard.local")
else:
    current_user = UserSession(username="viewer_bob", role="viewer", email="bob@dataguard.local")

# Display RBAC badge chip
if current_user.role == "admin":
    st.sidebar.markdown('<span class="badge-pill badge-emerald">🔑 Role: Admin (Full Access)</span>', unsafe_allow_html=True)
elif current_user.role == "engineer":
    st.sidebar.markdown('<span class="badge-pill badge-cyan">⚙️ Role: Engineer (Operations)</span>', unsafe_allow_html=True)
else:
    st.sidebar.markdown('<span class="badge-pill badge-amber">👁️ Role: Viewer (Read-Only)</span>', unsafe_allow_html=True)

st.sidebar.markdown("---")

menu = st.sidebar.radio(
    "Navigation Menu",
    [
        "📊 Observability Dashboard",
        "🧪 Pipeline Simulator & Fault Lab",
        "🚨 Incidents & Recovery Approvals",
        "📈 Statistical Drift & Anomalies",
        "🛡️ Audit Ledger & Knowledge Base",
    ],
)


# =====================================================================
# VIEW 1: OBSERVABILITY DASHBOARD
# =====================================================================

if menu == "📊 Observability Dashboard":
    st.markdown(
        """
        <div style="margin-bottom:20px;">
            <h1 style="margin:0 0 6px 0; font-size:28px;">📊 Pipeline Observability & SLA Command Center</h1>
            <p style="margin:0; color:#9CA3AF; font-size:14px;">Live health metrics, SLA burn-downs, and telemetry across warehouse ingestion pipelines.</p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    pipelines = repo.get_all_pipelines()
    open_incidents = repo.get_all_incidents(status="OPEN")
    recent_runs = repo.get_recent_runs(limit=50)

    # Top Metric Banner (Figma-styled glassmorphic KPI cards)
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Monitored Pipelines", len(pipelines), "Active Catalogs")
    with col2:
        st.metric("Total Execution Runs", len(recent_runs), "Historical Batches")
    with col3:
        st.metric(
            "Active Incidents",
            len(open_incidents),
            delta="Healthy" if len(open_incidents) == 0 else f"+{len(open_incidents)} Issues",
            delta_color="inverse",
        )
    with col4:
        audit_check = audit_service.verify_integrity()
        status_text = "Verified Authentic" if audit_check["is_valid"] else "Tampering Detected"
        st.metric("Audit Security", "SHA-256", status_text)

    st.markdown("<br>", unsafe_allow_html=True)

    # Pipeline SLA Compliance Cards (Figma Card Component)
    st.subheader("⚡ Pipeline Reliability & SLA Compliance")
    sla_cols = st.columns(len(pipelines))

    sla_data = []
    for idx, p in enumerate(pipelines):
        report = sla_monitor.get_pipeline_compliance(p["id"])
        sla_data.append({
            "Pipeline": p["name"],
            "Target SLA (s)": p["sla_seconds"],
            "Avg Duration (s)": report.average_duration_seconds,
            "P95 Latency (s)": report.p95_duration_seconds,
            "Compliance %": report.compliance_percentage,
            "Grade": report.health_grade,
        })
        with sla_cols[idx]:
            score_color = "#10B981" if report.health_grade in ["A", "B"] else "#EF4444"
            badge_class = "badge-emerald" if report.health_grade in ["A", "B"] else "badge-rose"

            st.markdown(
                f"""
                <div style="background: rgba(17, 24, 39, 0.85); border: 1px solid rgba(255, 255, 255, 0.08); border-radius: 14px; padding: 18px; backdrop-filter: blur(12px); box-shadow: 0 4px 20px -2px rgba(0, 0, 0, 0.4);">
                    <div style="display:flex; justify-content:space-between; align-items:center;">
                        <span style="font-size:11px; font-weight:700; color:#06B6D4; text-transform:uppercase; letter-spacing:0.05em;">{p['source_type']} pipeline</span>
                        <span class="badge-pill {badge_class}">Grade {report.health_grade}</span>
                    </div>
                    <h4 style="margin:10px 0 4px 0; font-size:15px; color:#F9FAFB;">{p['name']}</h4>
                    <p style="margin:0 0 12px 0; color:#9CA3AF; font-size:12px;">SLA Budget: <b style="color:#E5E7EB;">{p['sla_seconds']}s</b></p>
                    <div style="display:flex; align-items:baseline; gap:6px;">
                        <span style="font-size:26px; font-weight:800; color:{score_color};">{report.compliance_percentage}%</span>
                        <span style="font-size:11px; color:#9CA3AF;">compliance</span>
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )

    st.markdown("<br>", unsafe_allow_html=True)

    # Plotly Latency vs SLA Target Chart (Figma Dark Theme)
    st.markdown("### ⏱️ Latency vs SLA Budget Comparison")
    df_sla = pd.DataFrame(sla_data)
    fig_sla = go.Figure()
    fig_sla.add_trace(go.Bar(name="Average Duration (s)", x=df_sla["Pipeline"], y=df_sla["Avg Duration (s)"], marker_color="#06B6D4"))
    fig_sla.add_trace(go.Bar(name="P95 Duration (s)", x=df_sla["Pipeline"], y=df_sla["P95 Latency (s)"], marker_color="#3B82F6"))
    fig_sla.add_trace(go.Scatter(name="SLA Budget (s)", x=df_sla["Pipeline"], y=df_sla["Target SLA (s)"], mode="lines+markers", line=dict(color="#EF4444", width=3, dash="dash")))
    fig_sla.update_layout(barmode="group", height=380)
    apply_figma_chart_theme(fig_sla)
    st.plotly_chart(fig_sla, use_container_width=True)

    # Live Run Feed
    st.subheader("📜 Recent Pipeline Execution Runs")
    if recent_runs:
        df_runs = pd.DataFrame(recent_runs)[["run_id", "pipeline_name", "status", "started_at", "duration_seconds", "row_count", "error_message"]]
        st.dataframe(df_runs, use_container_width=True, hide_index=True)
    else:
        st.info("No runs recorded yet. Head over to the **Pipeline Simulator & Fault Lab** to trigger test runs!")


# =====================================================================
# VIEW 2: PIPELINE SIMULATOR & FAULT INJECTION LAB
# =====================================================================

elif menu == "🧪 Pipeline Simulator & Fault Lab":
    st.title("🧪 Pipeline Simulator & Chaos Fault Lab")
    st.markdown("Simulate production batches and inject controlled failures to test DataGuard's detection and recovery.")

    col_sim1, col_sim2 = st.columns([1, 1])

    with col_sim1:
        st.subheader("1. Configure Pipeline Run")
        selected_pipeline_id = st.selectbox(
            "Target Pipeline",
            options=["crm_customers_etl", "billing_transactions_sync"],
            format_func=lambda x: "CRM Customer Profiles ETL (csv)" if x == "crm_customers_etl" else "Billing Transactions Sync (json)",
        )

        selected_fault = st.selectbox(
            "Fault Injection Mode",
            options=[
                "None (Clean Healthy Run)",
                "NULL_SPIKE (35% Missing Values)",
                "SCHEMA_MISMATCH (API Breaking Column Rename)",
                "ANOMALY_VALUES (Negative Balances & Outliers)",
                "SLA_BREACH (Database Lock / Latency Hang)",
                "VOLUME_DROP (Premature Connection Drop - 5 Rows)",
            ],
            index=0,
        )

        fault_key = None
        if "NULL_SPIKE" in selected_fault:
            fault_key = "NULL_SPIKE"
        elif "SCHEMA_MISMATCH" in selected_fault:
            fault_key = "SCHEMA_MISMATCH"
        elif "ANOMALY_VALUES" in selected_fault:
            fault_key = "ANOMALY_VALUES"
        elif "SLA_BREACH" in selected_fault:
            fault_key = "SLA_BREACH"
        elif "VOLUME_DROP" in selected_fault:
            fault_key = "VOLUME_DROP"

        if not current_user.can_trigger_pipeline:
            st.error("⛔ Viewers cannot trigger pipeline runs. Switch to Admin or Engineer in the sidebar.")
            trigger_button = st.button("🚀 Trigger Pipeline Run", disabled=True)
        else:
            trigger_button = st.button("🚀 Trigger Pipeline Run", type="primary")

    with col_sim2:
        st.subheader("2. Real-Time Telemetry & Diagnosis")

        if trigger_button:
            with st.spinner("Executing pipeline & evaluating contracts..."):
                pipeline_meta = repo.get_pipeline(selected_pipeline_id)
                run, df = simulator.run_pipeline(pipeline_id=selected_pipeline_id, fault_type=fault_key)

                # Quality, Drift, RCA, and Impact
                quality_report = quality_engine.evaluate(selected_pipeline_id, df)
                ref_df = simulator.generate_crm_data(250) if selected_pipeline_id == "crm_customers_etl" else simulator.generate_billing_data(250)
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

                run_status = "FAILED" if diagnosis is not None else "SUCCESS"
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
                st.success(f"✅ Pipeline executed cleanly! (Run ID: {run.run_id})")
                st.metric("Quality Health Score", f"{quality_report.quality_score}%", "100% Passed")
            else:
                st.error(f"❌ Pipeline Failure Diagnosed: {diagnosis.incident_type} (Severity: {diagnosis.severity})")
                st.warning(f"**Root Cause:** {diagnosis.root_cause_summary}")
                st.info(f"**Blast Radius:** {impact_report.impact_summary}")
                st.markdown(f"👉 Ticket **{incident.incident_code}** created and queued for recovery in **Incidents & Recovery Approvals**.")

            st.write("### Data Sample Preview (First 5 Rows):")
            st.dataframe(df.head(), use_container_width=True)


# =====================================================================
# VIEW 3: INCIDENTS, RCA & APPROVAL-GATED RECOVERY
# =====================================================================

elif menu == "🚨 Incidents & Recovery Approvals":
    st.title("🚨 Incident Triage, RCA & Approval-Gated Recovery")
    st.markdown("Diagnose active failures, inspect downstream impact graphs, and authorize self-healing actions.")

    open_incidents = repo.get_all_incidents()

    if not open_incidents:
        st.success("🎉 No active or historical incidents! All pipelines running smoothly.")
    else:
        incident_options = {
            f"[{inc['severity']}] {inc['incident_code']} - {inc['pipeline_name']} ({inc['status']})": inc
            for inc in open_incidents
        }
        selected_label = st.selectbox("Select Incident to Triage", list(incident_options.keys()))
        selected_inc = incident_options[selected_label]

        st.markdown("---")
        inc_col1, inc_col2 = st.columns([1, 1])

        with inc_col1:
            st.subheader(f"📋 Incident Details: {selected_inc['incident_code']}")
            st.write(f"**Pipeline:** `{selected_inc['pipeline_name']}` ({selected_inc['pipeline_id']})")
            st.write(f"**Severity:** `{selected_inc['severity']}`")
            st.write(f"**Failure Type:** `{selected_inc['incident_type']}`")
            st.write(f"**Status:** `{selected_inc['status']}`")
            st.write(f"**Root Cause:** {selected_inc['root_cause_summary']}")
            st.write(f"**Assigned To:** `{selected_inc['assigned_to']}`")

            # Downstream DAG Impact Graph
            st.markdown("### 🌐 Downstream DAG Blast Radius")
            impact = impact_analyzer.analyze_impact(selected_inc["pipeline_id"])
            st.info(impact.impact_summary)

            nodes = impact.graph_nodes
            fig_dag = go.Figure()
            x_pos = [0 if n["id"] == selected_inc["pipeline_id"] else 2 for n in nodes]
            y_pos = list(range(len(nodes)))
            colors = ["#EF4444" if n["status"] == "FAILED" else "#F59E0B" for n in nodes]

            fig_dag.add_trace(go.Scatter(
                x=x_pos, y=y_pos,
                mode="markers+text",
                text=[n["label"] for n in nodes],
                textposition="bottom center",
                marker=dict(size=34, color=colors, line=dict(width=2, color="#FFFFFF")),
                hoverinfo="text",
            ))

            fig_dag.update_layout(
                showlegend=False,
                xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                height=260,
            )
            apply_figma_chart_theme(fig_dag)
            st.plotly_chart(fig_dag, use_container_width=True)

        with inc_col2:
            st.subheader("🛠️ Approval-Gated Self-Healing Recovery")
            recovery_actions = repo.get_recovery_actions_for_incident(selected_inc["incident_code"])

            if not recovery_actions:
                st.info("No recovery action proposed yet.")
            else:
                action = recovery_actions[0]
                action_id = action["id"]
                action_status = action["status"]

                st.write(f"**Action ID:** `#{action_id}`")
                st.write(f"**Remediation Type:** `{action['action_type']}`")
                st.write(f"**Current Status:** `{action_status}`")
                st.write(f"**Requested By:** `{action['requested_by']}`")

                if action_status == "PENDING_APPROVAL":
                    st.warning("⚠️ Action requires human approval before execution can begin.")

                    if not current_user.can_approve_recovery:
                        st.error("⛔ Viewers cannot approve recovery actions. Switch to Admin or Engineer.")
                        st.button("Authorize & Execute Recovery", disabled=True)
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
                                        st.success(f"🎉 Recovery Verified & Completed! Quality Score: {v_rep.quality_score}%")
                                        st.rerun()
                                    else:
                                        st.error(f"❌ Recovery Verification Failed! Quality Score: {v_rep.quality_score}%")
                                else:
                                    st.error(f"Execution Error: {exec_log}")

                elif action_status in ["COMPLETED", "APPROVED"]:
                    st.success("🛡️ Recovery has been executed and verified!")
                    st.write(f"**Approved By:** `{action['approved_by']}` at `{action['approved_at']}`")
                    st.write(f"**Execution Log:** {action['execution_log']}")
                    st.write(f"**Verification Badge:** {'✅ Verified Healthy' if action['is_verified'] else '❌ Unverified'}")


# =====================================================================
# VIEW 4: STATISTICAL DRIFT & ANOMALIES
# =====================================================================

elif menu == "📈 Statistical Drift & Anomalies":
    st.title("📈 Statistical Data Drift & ML Outlier Explorer")
    st.markdown("Detect distribution shifts using Population Stability Index (PSI), Kolmogorov-Smirnov test, and Isolation Forests.")

    drift_col1, drift_col2 = st.columns([1, 1])

    with drift_col1:
        st.subheader("Simulate Distribution Shift")
        drift_pipeline = st.selectbox("Pipeline", ["crm_customers_etl", "billing_transactions_sync"])
        shift_multiplier = st.slider("Distribution Shift Multiplier (1.0 = Baseline, 5.0+ = Extreme Drift)", 1.0, 8.0, 2.5, 0.5)

        np.random.seed(42)
        if drift_pipeline == "crm_customers_etl":
            ref_df = simulator.generate_crm_data(300)
            cur_df = simulator.generate_crm_data(300)
            target_col = "account_balance"
            cur_df[target_col] = cur_df[target_col] * shift_multiplier
        else:
            ref_df = simulator.generate_billing_data(300)
            cur_df = simulator.generate_billing_data(300)
            target_col = "amount"
            cur_df[target_col] = cur_df[target_col] * shift_multiplier

        report = drift_detector.evaluate(drift_pipeline, ref_df, cur_df, [target_col])
        drift_res = report.column_drifts[target_col]

    with drift_col2:
        st.subheader("Statistical Diagnostics")
        psi_val = drift_res.psi_score
        ks_p = drift_res.ks_pvalue

        m1, m2, m3 = st.columns(3)
        with m1:
            st.metric("PSI Score", psi_val, f"Threshold: {DEFAULT_PSI_DRIFT_THRESHOLD}")
        with m2:
            st.metric("KS Test p-val", f"{ks_p:.4f}", "< 0.05 = Drift")
        with m3:
            st.metric("Severity", drift_res.drift_severity)

        if drift_res.drift_severity == "CRITICAL":
            st.error(f"🚨 {drift_res.message}")
        elif drift_res.drift_severity == "MODERATE":
            st.warning(f"⚠️ {drift_res.message}")
        else:
            st.success(f"✅ {drift_res.message}")

    # Plotly Density Histogram (Figma Dark Theme)
    st.subheader(f"📊 Distribution Curves: Baseline vs Current ('{target_col}')")
    fig_dist = go.Figure()
    fig_dist.add_trace(go.Histogram(x=ref_df[target_col], name="Baseline Historical Data", opacity=0.6, marker_color="#06B6D4"))
    fig_dist.add_trace(go.Histogram(x=cur_df[target_col], name="Current Incoming Batch", opacity=0.6, marker_color="#EF4444"))
    fig_dist.update_layout(barmode="overlay", height=380)
    apply_figma_chart_theme(fig_dist)
    st.plotly_chart(fig_dist, use_container_width=True)


# =====================================================================
# VIEW 5: AUDIT LEDGER & KNOWLEDGE BASE
# =====================================================================

elif menu == "🛡️ Audit Ledger & Knowledge Base":
    st.title("🛡️ Cryptographic Audit Ledger & Knowledge Base")
    st.markdown("Tamper-evident append-only ledger and searchable repository of proven failure resolutions.")

    tab_audit, tab_kb = st.tabs(["🔒 Cryptographic Audit Ledger", "📚 Failure Knowledge Base"])

    with tab_audit:
        st.subheader("1. SHA-256 Hash Chain Integrity Verification")
        integrity = audit_service.verify_integrity()

        if integrity["is_valid"]:
            st.success(f"🟢 **AUDIT INTEGRITY VERIFIED**: All {integrity['total_checked']} records form an unbroken SHA-256 chain. Zero tampering detected.")
        else:
            st.error(f"🔴 **TAMPERING DETECTED**: {integrity.get('reason')}")

        st.subheader("2. Audit Log Explorer")
        filter_actor = st.text_input("Filter by Actor (e.g. 'admin', 'simulator_engine')")
        audit_records = audit_service.get_audit_trail(limit=100, actor=filter_actor if filter_actor else None)

        if audit_records:
            df_audit = pd.DataFrame(audit_records)[["id", "timestamp", "actor", "action", "entity_type", "entity_id", "record_hash"]]
            st.dataframe(df_audit, use_container_width=True, hide_index=True)

            csv = df_audit.to_csv(index=False).encode("utf-8")
            st.download_button("📥 Export Audit Trail as CSV", data=csv, file_name="dataguard_audit_trail.csv", mime="text/csv")
        else:
            st.info("No audit logs match filter.")

    with tab_kb:
        st.subheader("🔍 Institutional Knowledge Base Explorer")
        search_query = st.text_input("Search Failure Solutions (e.g. 'schema', 'null', 'timeout', 'SLA')")

        if search_query:
            solutions = kb_service.search_solutions(search_query)
        else:
            solutions = kb_service.get_all_solutions()

        for s in solutions:
            with st.expander(f"📌 {s['incident_type']} – Times Successfully Applied: {s['times_used']}"):
                st.write(f"**Error Pattern:** `{s['error_pattern']}`")
                st.write(f"**Root Cause:** {s['root_cause']}")
                st.write(f"**Recommended Action:** `{s['recommended_action']}`")
                st.markdown(f"**Resolution Steps:**\n{s['resolution_steps']}")
