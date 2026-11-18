# DataGuard 🛡️
### Intelligent Data Pipeline Monitoring, Failure Diagnosis, Automated Recovery and Audit Management Platform

DataGuard is an end-to-end Data Observability and Recovery Platform designed to monitor multi-source data pipelines, detect quality and drift anomalies, perform automated root cause analysis (RCA), track SLAs, require human approval for recovery actions, and maintain an immutable audit trail.

---

## 🚀 Key Features

1. **Multiple Pipeline Monitoring** – Live telemetry, latency, and status tracking across diverse data pipelines.
2. **Automated Quality & Failure Detection** – Schema changes, null spikes, value boundary violations, and duplicate record checks.
3. **Statistical & ML Anomaly Detection** – Population Stability Index (PSI), Kolmogorov-Smirnov (KS) drift tests, and Scikit-Learn Isolation Forests.
4. **Root Cause Analysis (RCA)** – Automated inference of failure triggers (network, schema mismatch, corrupt records, volume surge).
5. **Downstream Dependency Impact (DAG)** – Visualizing affected downstream consumer systems and data marts.
6. **Incident Management & SLA Tracking** – Severity classification (P1–P4), SLA burn-down monitoring, and alerts.
7. **Approval-Gated Recovery & Verification** – Re-runs, backfills, and fallback actions with strict approval gates and post-recovery health checks.
8. **Tamper-Evident Audit Logs** – Cryptographically linked audit logs for governance and compliance.
9. **Historical Knowledge Repository** – Searchable failure solutions to accelerate resolution.
10. **Role-Based Access Control (RBAC)** – Fine-grained roles for Admin, Data Engineer, and Viewer.

---

## 🛠️ Tech Stack

- **Backend:** Python 3.14+, SQLite (with PostgreSQL migration path)
- **Data & ML:** Pandas, NumPy, Scikit-learn, SciPy
- **Dashboard:** Streamlit, Plotly
- **DevOps:** Git, GitHub Actions, Docker, Pytest
