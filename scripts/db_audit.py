"""Quick DB state audit script."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.database.connection import get_connection

with get_connection() as conn:
    cur = conn.cursor()

    cur.execute("SELECT COUNT(*) FROM pipelines WHERE is_active=1")
    active_pipelines = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM pipeline_runs")
    total_runs = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM pipeline_runs WHERE status='SUCCESS'")
    success_runs = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM pipeline_runs WHERE status='FAILED'")
    failed_runs = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM incidents WHERE status='OPEN'")
    open_incidents = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM uploaded_datasets")
    datasets = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM audit_logs")
    audit_logs = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM knowledge_base")
    kb_entries = cur.fetchone()[0]

    cur.execute("SELECT id, name, status, quality_score, row_count FROM uploaded_datasets ORDER BY uploaded_at DESC LIMIT 5")
    recent_datasets = cur.fetchall()

    cur.execute("SELECT run_id, pipeline_id, status, started_at, row_count FROM pipeline_runs ORDER BY started_at DESC LIMIT 5")
    recent_runs = cur.fetchall()

    cur.execute("SELECT incident_code, pipeline_id, incident_type, severity, status FROM incidents ORDER BY created_at DESC LIMIT 5")
    recent_incidents = cur.fetchall()

print("=" * 55)
print("  DATAGUARD DATABASE AUDIT — LIVE STATE")
print("=" * 55)
print(f"  Active Pipelines    : {active_pipelines}")
print(f"  Total Pipeline Runs : {total_runs}  (✅ {success_runs} success, ❌ {failed_runs} failed)")
success_rate = round(success_runs / total_runs * 100, 1) if total_runs else 0
print(f"  Success Rate        : {success_rate}%")
print(f"  Open Incidents      : {open_incidents}")
print(f"  Uploaded Datasets   : {datasets}")
print(f"  Audit Log Entries   : {audit_logs}")
print(f"  Knowledge Base      : {kb_entries} entries")
print()
print("  RECENT DATASETS:")
for d in recent_datasets:
    print(f"    [{d[0]}] {d[1]} | {d[2]} | Score: {d[3]}% | {d[4]} rows")
if not recent_datasets:
    print("    (none)")
print()
print("  RECENT PIPELINE RUNS:")
for r in recent_runs:
    print(f"    {r[0]} | {r[1]} | {r[2]} | {r[3]} | {r[4]} rows")
if not recent_runs:
    print("    (none)")
print()
print("  RECENT INCIDENTS:")
for i in recent_incidents:
    print(f"    {i[0]} | {i[1]} | {i[2]} | {i[3]} | {i[4]}")
if not recent_incidents:
    print("    (none)")
print("=" * 55)
