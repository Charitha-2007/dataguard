# DataGuard 🛡️

[![DataGuard CI/CD Pipeline](https://github.com/Charitha-2007/dataguard/actions/workflows/ci.yml/badge.svg)](https://github.com/Charitha-2007/dataguard/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Docker](https://img.shields.io/badge/docker-ready-blue.svg)](https://www.docker.com/)
[![Tests](https://img.shields.io/badge/tests-40%20passed-brightgreen.svg)](tests/)
[![Security](https://img.shields.io/badge/audit-SHA--256%20verified-success.svg)](src/services/audit_service.py)

> **Intelligent Data Pipeline Monitoring, Failure Diagnosis, Automated Recovery and Audit Management Platform.**

DataGuard is an end-to-end Data Observability, Reliability Engineering, and Automated Remediation Platform. It continuously inspects multi-source batch data pipelines, detects schema and data quality anomalies, catches statistical data drift (PSI, KS-Test, Isolation Forests), traces downstream DAG impact, enforces human-in-the-loop approval gates for self-healing recovery, and maintains an immutable cryptographic audit ledger.

---

## 🌟 Key Capabilities

```text
┌───────────────────────┐     ┌────────────────────────┐     ┌────────────────────────┐
│ 1. Continuous Monitor │ ──> │ 2. Quality & ML Drift  │ ──> │ 3. Root Cause Analysis │
│ Multi-source batches  │     │ Schema, PSI, Isolation │     │ Error Classification   │
└───────────────────────┘     └────────────────────────┘     └────────────────────────┘
                                                                         │
┌───────────────────────┐     ┌────────────────────────┐                 ▼
│ 6. Cryptographic Log  │ <── │ 5. Post-Verification   │ <── ┌────────────────────────┐
│ Immutable SHA-256     │     │ Asserts clean recovery │     │ 4. Approval-Gated Fix  │
└───────────────────────┘     └────────────────────────┘     │ RBAC Human-in-the-Loop │
                                                             └────────────────────────┘
```

1. **Multi-Pipeline Observability:** Real-time health monitoring, duration tracking, and P95 latency tracking across CRM, Billing, and Analytics pipelines.
2. **Automated Data Quality Contracts:** Evaluates schema conformance, missingness thresholds, uniqueness, range boundaries, and domain rules.
3. **Statistical Drift & ML Anomaly Detection:**
   - **Population Stability Index (PSI):** Quantile-based divergence measurement.
   - **Two-Sample Kolmogorov-Smirnov (KS) Test:** Non-parametric continuous distribution test ($p < 0.05$).
   - **Scikit-Learn Isolation Forest:** Unsupervised multi-dimensional outlier detection.
4. **Automated Root Cause Analysis (RCA):** Diagnoses whether failures are caused by breaking schema changes, null spikes, database locks, or volume truncations.
5. **Downstream DAG Blast Radius:** Breadth-First Search (BFS) graph traversal mapping blocked downstream consumers (e.g. Finance Data Marts).
6. **Incident Management & SLA Monitoring:** Automatic deduplication, incident grouping, on-call assignment, and SLA health grades (**A through F**).
7. **Human-in-the-Loop (HITL) Self-Healing:**
   - Recommends remediations (`DROP_CORRUPTED`, `RETRY`, `SCHEMA_PATCH`, `APPLY_FALLBACK`).
   - Role-Based Access Control (RBAC): Viewers are read-only; only Engineers and Admins can authorize recovery.
   - Quarantines invalid records into dead-letter storage while passing clean subsets downstream.
8. **Post-Recovery Verification:** Re-evaluates remediated datasets through the Quality Engine before declaring the incident `RECOVERED`.
9. **Tamper-Evident Audit Ledger:** Cryptographically linked hash chain (SHA-256) where any manual database modification breaks the chain.
10. **Historical Knowledge Repository:** Searchable index of proven failure resolutions with frequency tracking.

---

## 🛠️ Technology Stack

- **Backend:** Python 3.11+, SQLite (with WAL mode & foreign keys), PostgreSQL 15 upgrade
- **Data & Machine Learning:** Pandas, NumPy, Scikit-learn (Isolation Forest), SciPy (KS-Test)
- **Frontend Command Center:** Streamlit, Plotly Interactive Graphs
- **DevOps & Testing:** Docker, Docker Compose, GitHub Actions (CI/CD), Pytest (40 automated tests), Git

---

## 🚀 Quickstart Guide

### Option 1: Run with Docker Compose (Recommended)

```bash
# Clone the repository
git clone https://github.com/Charitha-2007/dataguard.git
cd dataguard

# Launch the platform and PostgreSQL database
docker-compose up --build
```
Open **[http://localhost:8501](http://localhost:8501)** in your browser.

---

### Option 2: Run Locally with Python Virtual Environment

```bash
# Clone and enter directory
git clone https://github.com/Charitha-2007/dataguard.git
cd dataguard

# Create and activate virtual environment
python -m venv .venv
source .venv/bin/activate   # On Windows: .\.venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt

# Run all 40 automated tests
pytest tests/ -v

# Launch the Streamlit command center
streamlit run src/ui/app.py
```

---

## 🧪 Running Automated Tests

DataGuard is built with strict Test-Driven Development (TDD) containing **40 unit and integration tests**:

```bash
pytest tests/ -v
```

```text
tests/test_database.py .................. [5 passed]
tests/test_simulator.py ................. [5 passed]
tests/test_quality_engine.py ............ [5 passed]
tests/test_drift_detector.py ............ [4 passed]
tests/test_rca_and_impact.py ............ [7 passed]
tests/test_incidents_and_sla.py ......... [6 passed]
tests/test_recovery.py .................. [3 passed]
tests/test_audit_and_kb.py .............. [5 passed]
==================== 40 passed in ~3.5s ====================
```

---

## 👥 Role-Based Access Control (RBAC) Accounts

| Username | Role | Permissions |
| :--- | :--- | :--- |
| `admin` | **Admin** | Full access: trigger runs, approve recovery, configure settings |
| `engineer_alice` | **Engineer** | Operational access: trigger runs, triage incidents, approve recovery |
| `viewer_bob` | **Viewer** | Read-only access: view dashboards, inspect telemetry (cannot approve recovery) |

---

## 📄 License

This project is licensed under the MIT License.
