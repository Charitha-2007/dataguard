"""
DataGuard ─ Intelligent Pipeline Reliability & Recovery Platform
Enterprise Streamlit Command Center:
- Native Dark-Mode Design System & Plotly Dark Theme
- Dynamic Dataset Upload (.csv, .xlsx, .xls, .json) & Processing Engine
- Deep Data Quality Profiling (Missing Values, Duplicates, Outliers, Schema Types)
- Dataset Lifecycle Management (Catalog, Reprocess, Replace, Delete)
- 5-Stage Observable Pipeline Execution with Automated RCA & Incident Gating
- Interactive Chaos Simulator & Fault Lab
- Incident Triage, DAG Blast Radius & RBAC Self-Healing Recovery
- Statistical Drift Explorer (PSI, KS-Test, Isolation Forest)
- Cryptographic SHA-256 Audit Ledger & Solution Knowledge Base
"""

import io
import json
import os
import sys
from datetime import datetime
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import numpy as np
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from config.settings import DEFAULT_NULL_THRESHOLD_PCT, DEFAULT_PSI_DRIFT_THRESHOLD
from src.core.drift_detector import DriftAnomalyDetector
from src.core.impact_analyzer import DependencyImpactAnalyzer
from src.core.quality_engine import DataQualityEngine
from src.core.rca_engine import RootCauseAnalysisEngine
from src.core.simulator import PipelineSimulator
from src.core.sla_monitor import SLAMonitor
from src.database.models import init_db
from src.database.repository import DataGuardRepository
from src.recovery.approval_workflow import ApprovalWorkflowManager
from src.recovery.recommendation import RecoveryRecommendationEngine
from src.recovery.recovery_executor import RecoveryExecutor
from src.recovery.verifier import RecoveryVerifier
from src.services.audit_service import AuditService
from src.services.auth import AuthService, UserSession
from src.services.dataset_service import DatasetService
from src.services.incident_manager import IncidentManager
from src.services.knowledge_base import KnowledgeBaseService
from src.services.notifier import NotificationDispatcher

# ─────────────────────────────────────────────────────────────────────────────
# PAGE CONFIGURATION & THEME STYLING
# ─────────────────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="DataGuard | Pipeline Observability Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
<style>
/* Animated top header bar */
header[data-testid="stHeader"] {
    background: linear-gradient(90deg, #0A0F1E 0%, #0d1e3d 50%, #0A0F1E 100%) !important;
    border-bottom: 1px solid rgba(0, 201, 255, 0.15) !important;
}
/* Enhanced metric cards with smooth hover lift */
div[data-testid="metric-container"] {
    background: rgba(17, 24, 39, 0.75) !important;
    border-radius: 12px !important;
    padding: 16px !important;
    border: 1px solid rgba(0, 201, 255, 0.12) !important;
    transition: transform 0.2s ease, box-shadow 0.2s ease, border-color 0.2s ease;
}
div[data-testid="metric-container"]:hover {
    transform: translateY(-2px);
    box-shadow: 0 6px 28px rgba(0, 201, 255, 0.2);
    border-color: rgba(0, 201, 255, 0.35) !important;
}
/* Gradient progress bar */
.stProgress > div > div {
    background: linear-gradient(90deg, #00C9FF 0%, #7C3AED 100%) !important;
}
/* Sidebar adjustments */
[data-testid="stSidebar"] > div:first-child {
    padding-top: 1rem !important;
}
/* Tab styling */
button[data-baseweb="tab"][aria-selected="true"] {
    color: #00C9FF !important;
    border-bottom: 2px solid #00C9FF !important;
}
/* Clean up expander borders */
details[data-testid="stExpander"] {
    border-color: rgba(255, 255, 255, 0.08) !important;
    background: rgba(17, 24, 39, 0.4) !important;
    border-radius: 10px !important;
}
footer { visibility: hidden; }
</style>
""",
    unsafe_allow_html=True,
)

# ── Chart helper function ─────────────────────────────────────────────────────
CHART_COLORS = ["#00C9FF", "#7C3AED", "#10B981", "#F59E0B", "#F43F5E", "#8B5CF6"]


def styled_chart(fig, height=360, title=""):
    fig.update_layout(
        template="plotly_dark",
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(255,255,255,0.02)",
        height=height,
        title=dict(text=title, font=dict(size=14, color="#94A3B8"), x=0, pad=dict(l=4)),
        margin=dict(l=20, r=20, t=40 if title else 20, b=20),
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
        "OPEN": "🔥",
        "IN_REVIEW": "🔍",
        "RECOVERED": "✅",
        "CLOSED": "🔒",
        "SUCCESS": "✅",
        "FAILED": "❌",
        "RUNNING": "⚡",
        "UPLOADED": "📦",
        "PROCESSED": "✨",
    }.get(status, "❓")


# ─────────────────────────────────────────────────────────────────────────────
# INITIALIZATION & SERVICES
# ─────────────────────────────────────────────────────────────────────────────
init_db()
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
recommender = RecoveryRecommendationEngine(repo=repo)
workflow = ApprovalWorkflowManager(repo=repo)
executor = RecoveryExecutor(repo=repo, simulator=simulator)
verifier = RecoveryVerifier(repo=repo, quality_engine=quality_engine)

dataset_service = DatasetService(
    repo=repo,
    incident_manager=incident_manager,
    rca_engine=rca_engine,
    drift_detector=drift_detector,
    recommender=recommender,
    workflow=workflow,
)

# ─────────────────────────────────────────────────────────────────────────────
# SIDEBAR: AUTHENTICATION & NAVIGATION
# ─────────────────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("## 🛡️ DataGuard")
    st.caption("Intelligent Pipeline Reliability & Recovery")
    st.divider()

    st.markdown("**👤 Active Profile**")
    role_map = {
        "🔑 Admin — Full Control": ("admin", "admin", "admin@dataguard.local"),
        "⚙️ Engineer — Operations": ("engineer_alice", "engineer", "alice@dataguard.local"),
        "👁️ Viewer — Read Only": ("viewer_bob", "viewer", "bob@dataguard.local"),
    }
    chosen = st.selectbox("Role", list(role_map.keys()), label_visibility="collapsed")
    uname, urole, uemail = role_map[chosen]
    current_user = UserSession(username=uname, role=urole, email=uemail)

    role_status_badges = {
        "admin": "🟢 Full Access (Upload, Trigger, Authorize)",
        "engineer": "🔵 Operations (Upload, Trigger, Authorize)",
        "viewer": "🟡 Read-Only (Inspection)",
    }
    st.caption(role_status_badges[urole])
    st.divider()

    st.markdown("**Navigation Menu**")
    page = st.radio(
        "Navigation",
        [
            "📊  Overview",
            "📁  Datasets & Ingestion",
            "🧪  Simulator Lab",
            "🚨  Incidents & Recovery",
            "📈  Drift Explorer",
            "🛡️  Audit & Knowledge",
        ],
        label_visibility="collapsed",
    )
    st.divider()

    # Live Incident Pill
    open_inc = repo.get_all_incidents(status="OPEN")
    if len(open_inc) == 0:
        st.success("✅ All Pipelines Healthy")
    else:
        st.error(f"🔥 {len(open_inc)} Active Incident(s)")

    uploaded_datasets_count = len(dataset_service.get_all_datasets())
    st.caption(f"📁 **{uploaded_datasets_count}** custom dataset(s) in catalog")
    st.caption(f"🕐 System Time: {datetime.now().strftime('%H:%M:%S')}")


# ═════════════════════════════════════════════════════════════════════════════
# VIEW 1 — OVERVIEW DASHBOARD
# ═════════════════════════════════════════════════════════════════════════════
if "Overview" in page:

    st.title("📊 Pipeline Observability & Ingestion Dashboard")
    st.caption(
        "Real-time pipeline reliability metrics, SLA tracking, and dynamic dataset upload center."
    )
    st.divider()

    pipelines = repo.get_all_pipelines()
    open_incidents = repo.get_all_incidents(status="OPEN")
    recent_runs = repo.get_recent_runs(limit=60)
    all_datasets = dataset_service.get_all_datasets()
    audit_check = audit_service.verify_integrity()

    # ── TOP KPI BANNER ────────────────────────────────────────────────────────
    k1, k2, k3, k4, k5, k6 = st.columns(6)
    k1.metric("📁 Uploaded Datasets", len(all_datasets), "Custom Files")
    k2.metric("🗂️ Monitored Pipelines", len(pipelines), "Active Catalogs")
    k3.metric("⚡ Pipeline Runs", len(recent_runs), "Total Batches")

    successful_runs = sum(1 for r in recent_runs if r.get("status") == "SUCCESS")
    failed_runs = sum(1 for r in recent_runs if r.get("status") == "FAILED")
    success_rate = round(successful_runs / len(recent_runs) * 100, 1) if recent_runs else 0

    k4.metric("✅ Success Rate", f"{success_rate}%", f"{successful_runs}/{len(recent_runs)} Runs")
    k5.metric(
        "🚨 Open Incidents",
        len(open_incidents),
        "Healthy" if len(open_incidents) == 0 else f"+{len(open_incidents)} Issues",
        delta_color="inverse",
    )
    k6.metric(
        "🔒 Audit Security",
        "SHA-256",
        "Chain Intact" if audit_check["is_valid"] else "Tampering Detected",
    )

    st.divider()

    # ── PROMINENT DATASET UPLOAD COMPONENT ────────────────────────────────────
    st.subheader("📤 Upload Dataset")
    st.caption(
        "Ingest custom production batches (.csv, .xlsx, .xls, .json) into DataGuard for automated quality profiling and pipeline processing."
    )

    with st.container(border=True):
        up_col1, up_col2 = st.columns([2, 1], gap="medium")

        with up_col1:
            uploaded_file = st.file_uploader(
                "Choose a dataset file (Drag & Drop or Browse)",
                type=["csv", "xlsx", "xls", "json"],
                help="Supports CSV, Excel spreadsheets, and JSON array records up to 100MB.",
            )
            dataset_name_input = st.text_input(
                "Dataset Display Name (Optional)",
                placeholder="e.g. Q4 Financial Ledgers Ingestion",
            )

        with up_col2:
            st.markdown("**File Requirements & Guidance**")
            st.markdown("""
            - 📑 **Supported Formats**: `.csv`, `.xlsx`, `.xls`, `.json`
            - 🔍 **Automated Profiling**: Evaluates missingness, duplicate rows, data types, statistical outliers
            - ⚡ **Pipeline Execution**: Immediately routes into DataGuard's 5-stage observable pipeline
            """)

        # Process upload when file provided
        if uploaded_file is not None:
            file_bytes = uploaded_file.getvalue()
            filename = uploaded_file.name
            size_kb = len(file_bytes) / 1024
            size_str = f"{size_kb:.1f} KB" if size_kb < 1024 else f"{(size_kb / 1024):.2f} MB"

            try:
                with st.spinner("Validating and parsing uploaded dataset..."):
                    parsed_df, meta = dataset_service.parse_file(file_bytes, filename)

                st.success(f"✅ **{filename}** successfully parsed! ({size_str})")

                # Preview container
                with st.expander("🔎 Dataset Preview & Inferred Schema", expanded=True):
                    p_c1, p_c2, p_c3, p_c4 = st.columns(4)
                    p_c1.metric("Total Rows", f"{len(parsed_df):,}")
                    p_c2.metric("Total Columns", len(parsed_df.columns))
                    p_c3.metric("Memory Usage", f"{meta['memory_mb']} MB")
                    p_c4.metric("Format", meta["file_type"].upper())

                    st.dataframe(parsed_df.head(5), use_container_width=True)

                # Save and Ingest Actions
                act_c1, act_c2 = st.columns([1, 1])
                with act_c1:
                    if st.button("💾 Save to Dataset Catalog", type="primary", use_container_width=True):
                        with st.spinner("Saving dataset and running initial profiling..."):
                            saved = dataset_service.save_dataset(
                                name=dataset_name_input or Path(filename).stem,
                                filename=filename,
                                df=parsed_df,
                                raw_bytes=file_bytes,
                                actor=current_user.username,
                            )
                            st.success(
                                f"🎉 Dataset **{saved.name}** saved to catalog (ID: `{saved.id}`)! Quality Score: **{saved.quality_score}%**"
                            )
                            st.rerun()

                with act_c2:
                    if st.button("⚡ Save & Run 5-Stage Ingestion Pipeline", use_container_width=True):
                        with st.spinner("Saving and launching 5-stage observable pipeline..."):
                            saved = dataset_service.save_dataset(
                                name=dataset_name_input or Path(filename).stem,
                                filename=filename,
                                df=parsed_df,
                                raw_bytes=file_bytes,
                                actor=current_user.username,
                            )
                            result = dataset_service.execute_pipeline_on_dataset(
                                saved.id, actor=current_user.username
                            )

                            if result["status"] == "SUCCESS":
                                st.success(
                                    f"✨ Pipeline executed successfully in {result['total_duration_seconds']}s! Run ID: `{result['run_id']}`"
                                )
                            else:
                                st.error(
                                    f"❌ Pipeline failed quality gate. Incident ticket `{result['incident_code']}` generated in Incidents & Recovery."
                                )
                            st.rerun()

            except Exception as e:
                st.error(f"❌ File Parsing Error: {str(e)}")

    st.divider()

    # ── DYNAMIC METRICS FOR SELECTED DATASET ──────────────────────────────────
    if all_datasets:
        st.subheader("🔬 Dynamic Quality Telemetry for Uploaded Datasets")
        st.caption(
            "Select an uploaded dataset to inspect real-time metrics, missing value distributions, and column types."
        )

        dataset_options = {
            f"{d['name']} ({d['filename']} · {d['row_count']} rows · Score: {d['quality_score']}%)": d
            for d in all_datasets
        }
        chosen_ds_label = st.selectbox(
            "Select Dataset for Dynamic Charts", list(dataset_options.keys())
        )
        selected_ds = dataset_options[chosen_ds_label]

        # Load dataframe for dynamic charts
        loaded_df = dataset_service.load_dataset_df(selected_ds["id"])

        if loaded_df is not None:
            profile = dataset_service.profile_dataset(loaded_df, selected_ds["name"])

            m1, m2, m3, m4, m5 = st.columns(5)
            m1.metric("Quality Score", f"{profile['quality_score']}%", f"Grade {profile['health_grade']}")
            m2.metric("Total Rows", f"{profile['total_rows']:,}")
            m3.metric("Missing Values", f"{profile['missing_total']:,}", f"{profile['missing_pct']}% of cells")
            m4.metric("Duplicate Rows", f"{profile['duplicate_total']:,}", f"{profile['duplicate_pct']}% of rows")
            m5.metric("Statistical Outliers", f"{profile['total_outliers']:,}", "IQR Method")

            # Dynamic Charts Row
            chart1, chart2 = st.columns([1, 1], gap="medium")

            with chart1:
                # Missingness by column bar chart
                missing_items = [
                    (col, data["count"], data["percentage"])
                    for col, data in profile["missing_by_column"].items()
                    if data["count"] > 0
                ]
                if missing_items:
                    df_miss = pd.DataFrame(
                        missing_items, columns=["Column", "Missing Count", "Percentage"]
                    ).sort_values("Missing Count", ascending=True)

                    fig_miss = px.bar(
                        df_miss,
                        x="Missing Count",
                        y="Column",
                        orientation="h",
                        color="Percentage",
                        color_continuous_scale=["#00C9FF", "#F43F5E"],
                        title="📉 Missing Value Count by Column",
                    )
                    styled_chart(fig_miss, 320)
                    st.plotly_chart(fig_miss, use_container_width=True)
                else:
                    st.success("🟢 Zero missing values in this dataset! 100% complete.")

            with chart2:
                # Column data types composition donut chart
                type_counts = {}
                for col in loaded_df.columns:
                    t_str = str(loaded_df[col].dtype)
                    if "int" in t_str or "float" in t_str:
                        category = "Numeric"
                    elif "datetime" in t_str:
                        category = "Datetime"
                    elif "bool" in t_str:
                        category = "Boolean"
                    else:
                        category = "Categorical / Text"
                    type_counts[category] = type_counts.get(category, 0) + 1

                fig_donut = go.Figure(
                    go.Pie(
                        labels=list(type_counts.keys()),
                        values=list(type_counts.values()),
                        hole=0.6,
                        marker=dict(colors=["#00C9FF", "#7C3AED", "#10B981", "#F59E0B"]),
                        textinfo="label+percent",
                    )
                )
                styled_chart(fig_donut, 320, "🍩 Column Data Types Composition")
                st.plotly_chart(fig_donut, use_container_width=True)

    st.divider()

    # ── PIPELINE SLA COMPLIANCE SECTION ───────────────────────────────────────
    st.subheader("⚡ Baseline Pipeline Reliability & SLA Compliance")
    sla_cols = st.columns(len(pipelines))
    sla_data = []

    for i, p in enumerate(pipelines):
        rpt = sla_monitor.get_pipeline_compliance(p["id"])
        sla_data.append({
            "Pipeline": p["name"],
            "Target SLA (s)": p["sla_seconds"],
            "Avg Duration (s)": rpt.average_duration_seconds,
            "P95 Latency (s)": rpt.p95_duration_seconds,
            "Compliance %": rpt.compliance_percentage,
            "Grade": rpt.health_grade,
        })
        with sla_cols[i]:
            with st.container(border=True):
                g_icon = grade_color(rpt.health_grade)
                st.markdown(f"**{p['name']}**")
                st.caption(f"{p['source_type'].upper()} · Budget {p['sla_seconds']}s")
                st.metric(
                    f"{g_icon} Grade {rpt.health_grade}",
                    f"{rpt.compliance_percentage}%",
                    f"P95: {rpt.p95_duration_seconds}s",
                    delta_color="normal" if rpt.health_grade in ["A", "B"] else "inverse",
                )
                st.progress(min(int(rpt.compliance_percentage), 100) / 100)

    # Recent runs table
    st.subheader("📜 Recent Pipeline Execution Runs")
    if recent_runs:
        df_runs = pd.DataFrame(recent_runs)[
            [
                "run_id",
                "pipeline_name",
                "status",
                "started_at",
                "duration_seconds",
                "row_count",
                "error_message",
            ]
        ]
        st.dataframe(df_runs, use_container_width=True, hide_index=True)
    else:
        st.info("No runs recorded yet.")


# ═════════════════════════════════════════════════════════════════════════════
# VIEW 2 — DATASETS & INGESTION MANAGEMENT
# ═════════════════════════════════════════════════════════════════════════════
elif "Datasets" in page:

    st.title("📁 Dataset Management & Quality Hub")
    st.caption(
        "Manage uploaded datasets, inspect column-level quality profiling, reprocess data, and execute the 5-stage observable pipeline."
    )
    st.divider()

    tab_catalog, tab_profile, tab_pipeline = st.tabs(
        ["🗂️  Dataset Catalog", "🔬  Quality & Schema Profiling", "🚀  Observable Pipeline Execution"]
    )

    all_datasets = dataset_service.get_all_datasets()

    # ── TAB 1: DATASET CATALOG ────────────────────────────────────────────────
    with tab_catalog:
        st.subheader("📋 Registered Datasets Catalog")

        if not all_datasets:
            st.info("No datasets uploaded yet. Head to the **Overview** dashboard to upload your first dataset!")
        else:
            # Display datasets summary table
            ds_rows = []
            for d in all_datasets:
                size_kb = d["file_size_bytes"] / 1024
                size_fmt = f"{size_kb:.1f} KB" if size_kb < 1024 else f"{(size_kb / 1024):.2f} MB"
                ds_rows.append({
                    "ID": d["id"],
                    "Name": d["name"],
                    "File": d["filename"],
                    "Type": d["file_type"].upper(),
                    "Size": size_fmt,
                    "Rows": f"{d['row_count']:,}",
                    "Columns": d["column_count"],
                    "Health Score": f"{d['quality_score']}%",
                    "Status": f"{status_icon(d['status'])} {d['status']}",
                    "Uploaded": d["uploaded_at"],
                })

            df_cat = pd.DataFrame(ds_rows)
            st.dataframe(df_cat, use_container_width=True, hide_index=True)

            st.divider()

            # Dataset Management Operations
            st.subheader("⚙️ Dataset Actions")
            ds_map = {f"{d['name']} ({d['id']})": d for d in all_datasets}
            selected_ds_name = st.selectbox("Select Target Dataset", list(ds_map.keys()))
            target_ds = ds_map[selected_ds_name]

            action_col1, action_col2 = st.columns(2, gap="medium")

            with action_col1:
                with st.container(border=True):
                    st.markdown("#### 🔄 Reprocess Dataset")
                    st.caption("Re-evaluates missing values, duplicates, outliers, and recalculates the data health score.")
                    if st.button("Run Reprocess", type="primary", use_container_width=True):
                        df_to_reprocess = dataset_service.load_dataset_df(target_ds["id"])
                        if df_to_reprocess is not None:
                            with st.spinner("Reprocessing dataset profiling..."):
                                prof = dataset_service.profile_dataset(df_to_reprocess, target_ds["name"])
                                repo.update_dataset_metrics(
                                    dataset_id=target_ds["id"],
                                    quality_score=prof["quality_score"],
                                    missing_count=prof["missing_total"],
                                    duplicate_count=prof["duplicate_total"],
                                    status="PROCESSED",
                                )
                                repo.log_audit_event(
                                    actor=current_user.username,
                                    action="DATASET_REPROCESSED",
                                    entity_type="DATASET",
                                    entity_id=target_ds["id"],
                                    details={"quality_score": prof["quality_score"]},
                                )
                            st.success(f"✅ Reprocessed! New Health Score: **{prof['quality_score']}%**")
                            st.rerun()

            with action_col2:
                with st.container(border=True):
                    st.markdown("#### 🗑️ Delete Dataset")
                    st.caption("Permanently removes the dataset file and records from DataGuard.")
                    confirm_delete = st.checkbox(f"Confirm deletion of '{target_ds['name']}'", key="del_chk")

                    if not current_user.can_manage_settings:
                        st.error("⛔ Viewers cannot delete datasets. Switch to Admin.")
                        st.button("Delete Dataset", disabled=True, use_container_width=True)
                    else:
                        if st.button("Delete Dataset", type="secondary", disabled=not confirm_delete, use_container_width=True):
                            deleted = dataset_service.delete_dataset(target_ds["id"], actor=current_user.username)
                            if deleted:
                                st.success(f"🗑️ Dataset '{target_ds['name']}' deleted.")
                                st.rerun()
                            else:
                                st.error("Failed to delete dataset.")

            # Replace Dataset
            with st.expander("🔁 Replace Dataset with New Version"):
                st.caption("Upload a new file to replace this dataset while retaining the pipeline history.")
                replacement_file = st.file_uploader(
                    "Choose replacement file",
                    type=["csv", "xlsx", "xls", "json"],
                    key="replace_uploader",
                )
                if replacement_file is not None:
                    if st.button("Confirm Replacement & Update Catalog", type="primary"):
                        rep_bytes = replacement_file.getvalue()
                        rep_df, _ = dataset_service.parse_file(rep_bytes, replacement_file.name)
                        dataset_service.replace_dataset(
                            dataset_id=target_ds["id"],
                            new_name=target_ds["name"],
                            new_filename=replacement_file.name,
                            df=rep_df,
                            raw_bytes=rep_bytes,
                            actor=current_user.username,
                        )
                        st.success(f"✅ Replaced dataset with {replacement_file.name}!")
                        st.rerun()

    # ── TAB 2: QUALITY & SCHEMA PROFILING ─────────────────────────────────────
    with tab_profile:
        st.subheader("🔬 Data Quality & Schema Deep-Dive")

        if not all_datasets:
            st.info("No datasets available. Please upload a dataset first.")
        else:
            ds_profile_map = {f"{d['name']} ({d['id']})": d for d in all_datasets}
            chosen_prof_name = st.selectbox("Select Dataset to Inspect", list(ds_profile_map.keys()), key="prof_ds_sel")
            ds_to_inspect = ds_profile_map[chosen_prof_name]

            df_inspect = dataset_service.load_dataset_df(ds_to_inspect["id"])

            if df_inspect is not None:
                profile_report = dataset_service.profile_dataset(df_inspect, ds_to_inspect["name"])

                # Top Score Indicator
                q_col1, q_col2, q_col3, q_col4 = st.columns(4)
                q_col1.metric("Health Score", f"{profile_report['quality_score']}%", f"Grade {profile_report['health_grade']}")
                q_col2.metric("Completeness", f"{round(100 - profile_report['missing_pct'], 1)}%", f"{profile_report['missing_total']} missing cells")
                q_col3.metric("Uniqueness", f"{round(100 - profile_report['duplicate_pct'], 1)}%", f"{profile_report['duplicate_total']} duplicate rows")
                q_col4.metric("Statistical Outliers", profile_report["total_outliers"], "IQR bounds")

                st.progress(min(int(profile_report["quality_score"]), 100) / 100)

                st.divider()

                # Column-by-Column Profiles Table
                st.markdown("### 📊 Column Profiles & Statistics")
                col_records = []
                for col_name, c_meta in profile_report["column_profiles"].items():
                    col_records.append({
                        "Column": col_name,
                        "Type": c_meta["dtype"],
                        "Nulls": f"{c_meta['null_count']} ({c_meta['null_pct']}%)",
                        "Unique Values": c_meta["unique_count"],
                        "Outliers": c_meta["outliers_count"],
                        "Min": c_meta.get("min", "-"),
                        "Mean": c_meta.get("mean", "-"),
                        "Max": c_meta.get("max", "-"),
                    })
                st.dataframe(pd.DataFrame(col_records), use_container_width=True, hide_index=True)

                st.divider()

                # Visualizations
                viz_col1, viz_col2 = st.columns(2, gap="medium")

                with viz_col1:
                    # Missingness by column chart
                    miss_dict = profile_report["missing_by_column"]
                    cols_with_miss = {k: v["count"] for k, v in miss_dict.items() if v["count"] > 0}
                    if cols_with_miss:
                        fig_m = px.bar(
                            x=list(cols_with_miss.values()),
                            y=list(cols_with_miss.keys()),
                            orientation="h",
                            title="Missing Values by Column",
                            labels={"x": "Missing Row Count", "y": "Column"},
                        )
                        styled_chart(fig_m, 320)
                        st.plotly_chart(fig_m, use_container_width=True)
                    else:
                        st.success("🟢 No missing values in any column!")

                with viz_col2:
                    # Numeric distribution explorer
                    num_cols = profile_report["numeric_columns"]
                    if num_cols:
                        selected_num = st.selectbox("Explore Numerical Distribution", num_cols)
                        fig_num = px.histogram(
                            df_inspect,
                            x=selected_num,
                            nbins=30,
                            marginal="box",
                            title=f"Distribution of '{selected_num}'",
                        )
                        styled_chart(fig_num, 320)
                        st.plotly_chart(fig_num, use_container_width=True)
                    else:
                        st.info("No numerical columns detected for distribution plotting.")

                # Quality Checks Summary
                with st.expander("📋 Detailed Rule Checks & Violations", expanded=False):
                    for chk in profile_report["checks"]:
                        icon_chk = "✅" if chk.status == "PASSED" else ("⚠️" if chk.status == "WARNING" else "❌")
                        st.markdown(f"**{icon_chk} {chk.check_name}** `[{chk.category}]` — {chk.message}")

    # ── TAB 3: OBSERVABLE PIPELINE EXECUTION ──────────────────────────────────
    with tab_pipeline:
        st.subheader("🚀 5-Stage Observable Pipeline Execution")
        st.caption(
            "Execute DataGuard's full observable pipeline on the uploaded dataset: Ingestion ➜ Data Quality ➜ Drift & Anomaly ➜ Root Cause Analysis ➜ Remediation Routing."
        )

        if not all_datasets:
            st.info("Please upload a dataset first.")
        else:
            ds_exec_map = {f"{d['name']} ({d['id']})": d for d in all_datasets}
            target_exec_name = st.selectbox("Select Dataset to Pipeline Ingest", list(ds_exec_map.keys()), key="exec_ds_sel")
            exec_target = ds_exec_map[target_exec_name]

            if not current_user.can_trigger_pipeline:
                st.error("⛔ Viewers cannot trigger pipeline executions. Switch to Admin or Engineer.")
                st.button("🚀 Execute Ingestion Pipeline", disabled=True)
            else:
                if st.button("🚀 Execute Ingestion Pipeline", type="primary", use_container_width=True):
                    with st.status("⚡ Executing 5-Stage Pipeline...", expanded=True) as pipe_status:
                        exec_result = dataset_service.execute_pipeline_on_dataset(
                            exec_target["id"], actor=current_user.username
                        )

                        for stg in exec_result["stages"]:
                            st.write(f"**{stg['stage']}** ({stg['duration_seconds']}s): {stg['details']}")

                        if exec_result["status"] == "SUCCESS":
                            pipe_status.update(label="✅ Ingestion Pipeline Succeeded!", state="complete")
                        else:
                            pipe_status.update(label="❌ Quality Gate Failed — Incident Created", state="error")

                    st.divider()

                    # Summary cards
                    if exec_result["status"] == "SUCCESS":
                        st.success(
                            f"🎉 **Pipeline Completed Successfully!** Run ID: `{exec_result['run_id']}` in {exec_result['total_duration_seconds']}s"
                        )
                        s1, s2, s3 = st.columns(3)
                        s1.metric("Quality Score", f"{exec_result['quality_score']}%", f"Grade {exec_result['health_grade']}")
                        s2.metric("Rows Ingested", f"{exec_result['total_rows']:,}")
                        s3.metric("Execution Latency", f"{exec_result['total_duration_seconds']}s")

                        if exec_result.get("clean_path"):
                            with open(exec_result["clean_path"], "rb") as cf:
                                st.download_button(
                                    "📥 Download Clean Output (CSV)",
                                    data=cf.read(),
                                    file_name=f"clean_{exec_target['name']}.csv",
                                    mime="text/csv",
                                )
                    else:
                        st.error(
                            f"🚨 **Pipeline Failed Quality Gate!** Root Cause: `{exec_result['diagnosis'].incident_type}` (Severity: {exec_result['diagnosis'].severity})"
                        )
                        st.warning(f"**Root Cause Diagnosis:** {exec_result['diagnosis'].root_cause_summary}")
                        st.info(f"📋 **Incident Created:** `{exec_result['incident_code']}`. Go to **Incidents & Recovery** to triage and approve recovery.")

                        if exec_result.get("quarantine_path"):
                            with open(exec_result["quarantine_path"], "rb") as qf:
                                st.download_button(
                                    "📥 Download Quarantined Corrupted Rows (CSV)",
                                    data=qf.read(),
                                    file_name=f"quarantine_{exec_target['name']}.csv",
                                    mime="text/csv",
                                )


# ═════════════════════════════════════════════════════════════════════════════
# VIEW 3 — PIPELINE SIMULATOR & CHAOS FAULT LAB
# ═════════════════════════════════════════════════════════════════════════════
elif "Simulator" in page:

    st.title("🧪 Pipeline Simulator & Chaos Fault Lab")
    st.caption(
        "Simulate production data batches and inject controlled failures to test DataGuard's detection, root cause analysis, and self-healing recovery."
    )
    st.divider()

    cfg_col, out_col = st.columns([1, 1], gap="large")

    with cfg_col:
        st.subheader("⚙️ Configure Pipeline Run")

        with st.container(border=True):
            pipeline_choice = st.selectbox(
                "🗄️ Target Pipeline",
                ["crm_customers_etl", "billing_transactions_sync"],
                format_func=lambda x: "CRM Customer Profiles ETL (csv)" if x == "crm_customers_etl" else "Billing Transactions Sync (json)",
            )

            fault_choice = st.selectbox(
                "💥 Fault Injection Mode",
                [
                    "None — Clean Healthy Run",
                    "NULL_SPIKE — 35% Missing Values",
                    "SCHEMA_MISMATCH — API Breaking Column Rename",
                    "ANOMALY_VALUES — Negative Balances & Outliers",
                    "SLA_BREACH — Latency / Lock Hang",
                    "VOLUME_DROP — Premature Drop (5 rows)",
                ],
            )

            fault_key = None
            for fk in ["NULL_SPIKE", "SCHEMA_MISMATCH", "ANOMALY_VALUES", "SLA_BREACH", "VOLUME_DROP"]:
                if fk in fault_choice:
                    fault_key = fk
                    break

            fault_info = {
                None: ("✅", "Clean run — generates realistic healthy batch conforming to data contracts."),
                "NULL_SPIKE": ("🕳️", "35% of critical columns populated with nulls to test quality thresholds."),
                "SCHEMA_MISMATCH": ("🔀", "Renames critical required column, triggering schema contract breach."),
                "ANOMALY_VALUES": ("📉", "Injects negative numbers and 10x multiplier outliers."),
                "SLA_BREACH": ("⏰", "Simulates latency hang exceeding pipeline SLA budget."),
                "VOLUME_DROP": ("📦", "Truncates batch to 5 rows, triggering volume drop anomaly."),
            }
            icon, desc = fault_info.get(fault_key, ("ℹ️", ""))
            st.info(f"{icon} **{fault_key or 'Clean Run'}** — {desc}")

            if not current_user.can_trigger_pipeline:
                st.error("⛔ Viewers cannot trigger runs. Switch to Admin or Engineer.")
                trigger = st.button("🚀 Trigger Pipeline Run", disabled=True, use_container_width=True)
                trigger = False
            else:
                trigger = st.button("🚀 Trigger Pipeline Run", type="primary", use_container_width=True)

    with out_col:
        st.subheader("📡 Real-Time Telemetry & Diagnosis")

        if trigger:
            with st.status("⚡ Executing pipeline and evaluating contracts...", expanded=True) as exec_status:
                pipeline_meta = repo.get_pipeline(pipeline_choice)
                run, df = simulator.run_pipeline(pipeline_id=pipeline_choice, fault_type=fault_key)
                quality_report = quality_engine.evaluate(pipeline_choice, df)

                ref_df = (
                    simulator.generate_crm_data(250)
                    if pipeline_choice == "crm_customers_etl"
                    else simulator.generate_billing_data(250)
                )
                num_col = "account_balance" if pipeline_choice == "crm_customers_etl" else "amount"
                drift_report = drift_detector.evaluate(pipeline_choice, ref_df, df, [num_col])

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
                    label="✅ Pipeline Completed" if run_status == "SUCCESS" else "❌ Pipeline Failure Diagnosed",
                    state="complete" if run_status == "SUCCESS" else "error",
                )

            st.divider()
            if run_status == "SUCCESS":
                st.success(f"✅ **Clean Pipeline Execution** (Run ID: `{run.run_id}`)")
                r1, r2, r3 = st.columns(3)
                r1.metric("Quality Score", f"{quality_report.quality_score}%", "100% Passed")
                r2.metric("Rows Processed", run.row_count)
                r3.metric("Duration", f"{run.duration_seconds}s", f"SLA: {pipeline_meta['sla_seconds']}s")
            else:
                sev_icon = severity_color(diagnosis.severity)
                st.error(f"{sev_icon} **{diagnosis.incident_type}** — Severity **{diagnosis.severity}**")
                st.warning(f"**Root Cause:** {diagnosis.root_cause_summary}")
                st.info(f"**Blast Radius:** {impact_report.impact_summary}")
                st.markdown(
                    f"👉 Incident ticket `{incident.incident_code}` queued in **Incidents & Recovery Approvals**."
                )

            with st.expander("🔎 Data Sample Preview (First 5 Rows)", expanded=False):
                st.dataframe(df.head(5), use_container_width=True)
        else:
            with st.container(border=True):
                st.markdown("""
                ### 👈 Select pipeline and fault mode to simulate
                - Simulates real ETL ingestion runs
                - Injects controlled chaos failures
                - Runs multi-criteria Root Cause Analysis
                - Calculates downstream blast radius
                """)


# ═════════════════════════════════════════════════════════════════════════════
# VIEW 4 — INCIDENTS & RECOVERY APPROVALS
# ═════════════════════════════════════════════════════════════════════════════
elif "Incidents" in page:

    st.title("🚨 Incident Triage, RCA & Approval-Gated Recovery")
    st.caption(
        "Diagnose active pipeline failures, inspect downstream blast radius graphs, and authorize self-healing actions."
    )
    st.divider()

    all_incidents = repo.get_all_incidents()

    if not all_incidents:
        st.success("🎉 **All Systems Healthy!** Zero active or historical incidents recorded.")
        st.balloons()
    else:
        status_counts = {}
        for inc in all_incidents:
            status_counts[inc["status"]] = status_counts.get(inc["status"], 0) + 1

        s1, s2, s3, s4 = st.columns(4)
        s1.metric("🔥 Open", status_counts.get("OPEN", 0))
        s2.metric("🔍 In Review", status_counts.get("IN_REVIEW", 0))
        s3.metric("✅ Recovered", status_counts.get("RECOVERED", 0))
        s4.metric("🔒 Closed", status_counts.get("CLOSED", 0))

        st.divider()

        inc_options = {
            f"{severity_color(i['severity'])} {i['incident_code']} — {i['pipeline_id']} [{i['status']}]": i
            for i in all_incidents
        }
        chosen_inc_label = st.selectbox("Select Incident to Triage", list(inc_options.keys()))
        selected_inc = inc_options[chosen_inc_label]

        st.divider()
        left_inc, right_inc = st.columns([1, 1], gap="large")

        with left_inc:
            st.subheader(f"📋 {selected_inc['incident_code']}")
            with st.container(border=True):
                d1, d2 = st.columns(2)
                d1.metric("Severity", selected_inc["severity"])
                d2.metric("Status", f"{status_icon(selected_inc['status'])} {selected_inc['status']}")
                st.markdown(f"**Pipeline:** `{selected_inc['pipeline_id']}`")
                st.markdown(f"**Failure Type:** `{selected_inc['incident_type']}`")
                st.markdown(f"**Assigned To:** `{selected_inc['assigned_to']}`")
                st.info(f"🧠 **Root Cause:** {selected_inc['root_cause_summary']}")

            st.subheader("🌐 Downstream DAG Blast Radius")
            impact = impact_analyzer.analyze_impact(selected_inc["pipeline_id"])
            st.caption(impact.impact_summary)

            nodes = impact.graph_nodes
            x_pos = [0.2 if n["id"] == selected_inc["pipeline_id"] else 0.8 for n in nodes]
            y_pos = list(range(len(nodes)))
            colors = ["#F43F5E" if n["status"] == "FAILED" else "#F59E0B" for n in nodes]

            fig_dag = go.Figure()
            for idx, n in enumerate(nodes):
                if n["id"] != selected_inc["pipeline_id"]:
                    src_idx = next(
                        (j for j, m in enumerate(nodes) if m["id"] == selected_inc["pipeline_id"]), 0
                    )
                    fig_dag.add_trace(
                        go.Scatter(
                            x=[x_pos[src_idx], x_pos[idx]],
                            y=[y_pos[src_idx], y_pos[idx]],
                            mode="lines",
                            line=dict(color="rgba(244,63,94,0.3)", width=2, dash="dot"),
                            showlegend=False,
                        )
                    )

            fig_dag.add_trace(
                go.Scatter(
                    x=x_pos,
                    y=y_pos,
                    mode="markers+text",
                    text=[n["label"] for n in nodes],
                    textposition="middle right",
                    textfont=dict(size=11, color="#94A3B8"),
                    marker=dict(
                        size=28,
                        color=colors,
                        line=dict(color="rgba(255,255,255,0.2)", width=2),
                    ),
                    showlegend=False,
                )
            )
            fig_dag.update_layout(
                xaxis=dict(showgrid=False, zeroline=False, showticklabels=False, range=[-0.1, 1.5]),
                yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            )
            styled_chart(fig_dag, 220)
            st.plotly_chart(fig_dag, use_container_width=True)

        with right_inc:
            st.subheader("🛠️ Approval-Gated Self-Healing Recovery")
            actions = repo.get_recovery_actions_for_incident(selected_inc["incident_code"])

            if not actions:
                st.info("No recovery action proposed yet for this incident.")
            else:
                act = actions[0]
                act_id = act["id"]
                act_status = act["status"]

                with st.container(border=True):
                    a1, a2 = st.columns(2)
                    a1.metric("Action ID", f"#{act_id}")
                    a2.metric("Status", act_status)
                    st.markdown(f"**Remediation:** `{act['action_type']}`")
                    st.markdown(f"**Requested By:** `{act['requested_by']}`")

                st.divider()

                if act_status == "PENDING_APPROVAL":
                    st.warning("⚠️ Action requires human approval before execution can proceed.")

                    if not current_user.can_approve_recovery:
                        st.error("⛔ Viewers cannot approve recovery. Switch to Admin or Engineer.")
                        st.button("Authorize & Execute Recovery", disabled=True, use_container_width=True)
                    else:
                        st.markdown(f"**Approver:** `{current_user.username}` ({current_user.role})")
                        if st.button("✅ Authorize & Execute Recovery", type="primary", use_container_width=True):
                            with st.status("Authorizing and executing recovery...", expanded=True) as rec_status:
                                workflow.approve_recovery(
                                    act_id, approved_by=current_user.username, user_role=current_user.role
                                )
                                success, exec_log, recovered_df = executor.execute(act_id)

                                if success and recovered_df is not None:
                                    is_verified, v_rep = verifier.verify(
                                        action_id=act_id,
                                        pipeline_id=selected_inc["pipeline_id"],
                                        recovered_df=recovered_df,
                                        execution_log=exec_log,
                                        actor=current_user.username,
                                    )
                                    if is_verified:
                                        rec_status.update(label="✅ Recovery Verified & Healthy!", state="complete")
                                        st.success(f"🎉 Recovery Verified! Quality Score: **{v_rep.quality_score}%**")
                                        st.rerun()
                                    else:
                                        rec_status.update(label="❌ Quality Verification Failed", state="error")
                                        st.error(f"Quality score low: {v_rep.quality_score}%")
                                else:
                                    rec_status.update(label="❌ Recovery Execution Failed", state="error")
                                    st.error(f"Execution Error: {exec_log}")

                elif act_status in ["COMPLETED", "APPROVED"]:
                    st.success("🛡️ Recovery action has been executed and verified!")
                    with st.container(border=True):
                        st.markdown(f"**Approved By:** `{act['approved_by']}` at `{act['approved_at']}`")
                        st.markdown(f"**Verification:** {'✅ Verified Healthy' if act['is_verified'] else '❌ Unverified'}")
                        with st.expander("📋 Execution Log"):
                            st.code(act["execution_log"])


# ═════════════════════════════════════════════════════════════════════════════
# VIEW 5 — STATISTICAL DRIFT & ANOMALY EXPLORER
# ═════════════════════════════════════════════════════════════════════════════
elif "Drift" in page:

    st.title("📈 Statistical Drift & ML Anomaly Explorer")
    st.caption(
        "Detect distribution shifts using Population Stability Index (PSI), Kolmogorov-Smirnov test, and Isolation Forest ML anomaly detection."
    )
    st.divider()

    ctrl1, ctrl2, ctrl3 = st.columns([2, 2, 1])
    with ctrl1:
        drift_pipe = st.selectbox(
            "Target Pipeline",
            ["crm_customers_etl", "billing_transactions_sync"],
            format_func=lambda x: "CRM Customer Profiles ETL" if x == "crm_customers_etl" else "Billing Transactions Sync",
        )
    with ctrl2:
        shift_mult = st.slider("Distribution Shift Multiplier", 1.0, 8.0, 2.5, 0.25)
    with ctrl3:
        st.markdown("<br>", unsafe_allow_html=True)
        st.button("🔍 Analyze", type="primary", use_container_width=True)

    np.random.seed(42)
    if drift_pipe == "crm_customers_etl":
        ref_df = simulator.generate_crm_data(400)
        cur_df = simulator.generate_crm_data(400)
        target_col = "account_balance"
    else:
        ref_df = simulator.generate_billing_data(400)
        cur_df = simulator.generate_billing_data(400)
        target_col = "amount"

    cur_df[target_col] = cur_df[target_col] * shift_mult

    drift_report = drift_detector.evaluate(drift_pipe, ref_df, cur_df, [target_col])
    drift_res = drift_report.column_drifts[target_col]
    psi = drift_res.psi_score
    ks_p = drift_res.ks_pvalue
    sev = drift_res.drift_severity

    r1, r2, r3, r4 = st.columns(4)
    r1.metric("PSI Score", f"{psi:.4f}", f"Threshold >{DEFAULT_PSI_DRIFT_THRESHOLD}")
    r2.metric("KS p-value", f"{ks_p:.4f}", "< 0.05 = Drift")
    r3.metric("Severity", sev)
    r4.metric("Shift Multiplier", f"{shift_mult}x", f"Column: {target_col}")

    if sev == "CRITICAL":
        st.error(f"🚨 {drift_res.message}")
    elif sev == "MODERATE":
        st.warning(f"⚠️ {drift_res.message}")
    else:
        st.success(f"✅ {drift_res.message}")

    st.divider()

    ch1, ch2 = st.columns([3, 2], gap="medium")
    with ch1:
        fig_hist = go.Figure()
        fig_hist.add_trace(
            go.Histogram(
                x=ref_df[target_col],
                name="Baseline (Historical)",
                nbinsx=50,
                marker_color="#00C9FF",
                opacity=0.6,
            )
        )
        fig_hist.add_trace(
            go.Histogram(
                x=cur_df[target_col],
                name="Current Batch",
                nbinsx=50,
                marker_color="#F43F5E",
                opacity=0.6,
            )
        )
        fig_hist.update_layout(barmode="overlay")
        styled_chart(fig_hist, 360, f"Distribution Overlay — '{target_col}'")
        st.plotly_chart(fig_hist, use_container_width=True)

    with ch2:
        gauge_color = "#10B981" if psi < 0.1 else ("#F59E0B" if psi < 0.2 else "#F43F5E")
        fig_gauge = go.Figure(
            go.Indicator(
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
                        dict(range=[0, 0.1], color="rgba(16,185,129,0.1)"),
                        dict(range=[0.1, 0.2], color="rgba(245,158,11,0.1)"),
                        dict(range=[0.2, 0.5], color="rgba(244,63,94,0.1)"),
                    ],
                    threshold=dict(
                        line=dict(color="#F43F5E", width=2),
                        value=DEFAULT_PSI_DRIFT_THRESHOLD,
                        thickness=0.8,
                    ),
                ),
            )
        )
        fig_gauge.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            font_color="#94A3B8",
            height=360,
            margin=dict(l=30, r=30, t=50, b=20),
        )
        st.plotly_chart(fig_gauge, use_container_width=True)


# ═════════════════════════════════════════════════════════════════════════════
# VIEW 6 — AUDIT LEDGER & KNOWLEDGE BASE
# ═════════════════════════════════════════════════════════════════════════════
elif "Audit" in page:

    st.title("🛡️ Cryptographic Audit Ledger & Knowledge Base")
    st.caption(
        "Tamper-evident append-only ledger secured by SHA-256 hash chains, plus institutional failure resolution catalog."
    )
    st.divider()

    tab_audit, tab_kb, tab_integrity = st.tabs(
        ["🔒  Audit Log Trail", "📚  Failure Knowledge Base", "🔑  Cryptographic Chain Verification"]
    )

    with tab_audit:
        st.subheader("📋 Audit Trail Explorer")
        f1, f2 = st.columns([2, 1])
        with f1:
            actor_f = st.text_input("Filter by Actor", placeholder="e.g. admin, engineer_alice")
        with f2:
            limit_f = st.number_input("Max Rows", min_value=10, max_value=500, value=100, step=10)

        records = audit_service.get_audit_trail(limit=int(limit_f), actor=actor_f or None)

        if records:
            df_audit = pd.DataFrame(records)[
                ["id", "timestamp", "actor", "action", "entity_type", "entity_id", "record_hash"]
            ]
            st.dataframe(df_audit, use_container_width=True, hide_index=True)
            csv_data = df_audit.to_csv(index=False).encode("utf-8")
            st.download_button(
                "📥 Export Audit Trail as CSV",
                data=csv_data,
                file_name="dataguard_audit.csv",
                mime="text/csv",
            )
        else:
            st.info("No audit logs found matching filter.")

    with tab_kb:
        st.subheader("📚 Failure Resolution Knowledge Base")
        search_query = st.text_input("Search Solutions", placeholder="schema, null, timeout, SLA, drift, volume")
        solutions = kb_service.search_solutions(search_query) if search_query else kb_service.get_all_solutions()

        if not solutions:
            st.warning("No solutions found.")
        else:
            st.caption(f"Found **{len(solutions)}** solution(s)")
            for sol in solutions:
                with st.expander(f"📌 {sol['incident_type']} — Applied {sol['times_used']}x"):
                    col_k1, col_k2 = st.columns(2)
                    with col_k1:
                        st.markdown("**Error Pattern**")
                        st.code(sol["error_pattern"], language="text")
                        st.markdown("**Recommended Action**")
                        st.code(sol["recommended_action"], language="text")
                    with col_k2:
                        st.markdown("**Root Cause**")
                        st.info(sol["root_cause"])
                        st.markdown("**Resolution Steps**")
                        st.markdown(sol["resolution_steps"])

    with tab_integrity:
        st.subheader("🔑 SHA-256 Hash Chain Integrity Verification")
        st.caption("Every event log is cryptographically chained to its predecessor. Any database tampering breaks the hash.")

        with st.spinner("Verifying cryptographic hash chain..."):
            integrity = audit_service.verify_integrity()

        if integrity["is_valid"]:
            st.success(
                f"✅ **AUDIT CHAIN VERIFIED**: All {integrity['total_checked']} records form an unbroken cryptographic chain. Zero tampering detected."
            )
            st.metric("Records Verified", integrity["total_checked"], "100% Authentic")
            st.progress(1.0)
        else:
            st.error(f"🔴 **TAMPERING DETECTED**: {integrity.get('reason')}")
            st.metric("Chain Integrity", "COMPROMISED", delta_color="inverse")
