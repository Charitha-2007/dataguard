# DataGuard 🛡️

[![DataGuard CI/CD Pipeline](https://github.com/Charitha-2007/dataguard/actions/workflows/ci.yml/badge.svg)](https://github.com/Charitha-2007/dataguard/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Docker](https://img.shields.io/badge/docker-ready-blue.svg)](https://www.docker.com/)
[![Tests](https://img.shields.io/badge/tests-82%20passed-brightgreen.svg)](tests/)
[![Security](https://img.shields.io/badge/audit-SHA--256%20verified-success.svg)](src/services/audit_service.py)

> **Intelligent Data Pipeline Monitoring, Failure Diagnosis, Automated Recovery, Alerting and Audit Management Platform.**

DataGuard is an end-to-end Data Observability, Reliability Engineering, Automated Remediation, and Team Notification Platform. It continuously inspects multi-source batch data pipelines, detects schema and data quality anomalies, catches statistical data drift (PSI, KS-Test, Isolation Forests), traces downstream DAG impact, enforces human-in-the-loop approval gates for self-healing recovery, dispatches automated email alerts to team members, sanitizes corrupted datasets for instant CSV/XLSX export, and maintains an immutable cryptographic audit ledger.

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
                                                                         │
                                                                         ▼
                                                             ┌────────────────────────┐
                                                             │ 7. Team Alert Dispatch │
                                                             │ SMTP / Mock 5-Team Hub │
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
8. **Automated Multi-Recipient Email Alerting (Feature 1):**
   - Dispatches dark-themed responsive HTML + text alerts to all 5 team roles on critical pipeline incidents, SLA breaches, and quality degradations.
   - Intelligent duplicate suppression with configurable cooldown window (default: 30 minutes).
   - Severity filtering (`ALL`, `CRITICAL_HIGH`, `CRITICAL_ONLY`).
   - Built-in Sandbox/Mock mode for safe local testing and development without live SMTP credentials.
   - Full delivery audit logging in SQLite `notification_logs`.
9. **Interactive Dataset Cleaning, Sanitization & Dual Export (Feature 2):**
   - Ingests from catalog or raw user uploads (CSV, JSON, XLSX).
   - Smart missing value imputation (median for numeric, mode for categorical) or row dropping.
   - Interquartile Range (IQR) outlier detection with clipping or removal.
   - Whitespace trimming and column name sanitization.
   - Before/after data health quality scores and KPI gain telemetry.
   - Direct downloads of cleaned data as **CSV** and **XLSX (Excel)**.
   - Quarantined invalid rows inspection tab.
10. **Post-Recovery Verification:** Re-evaluates remediated datasets through the Quality Engine before declaring the incident `RECOVERED`.
11. **Tamper-Evident Audit Ledger:** Cryptographically linked hash chain (SHA-256) where any manual database modification breaks the chain.
12. **Historical Knowledge Repository:** Searchable index of proven failure resolutions with frequency tracking.

---

## 🖥️ Command Center Modules

The DataGuard Streamlit Dashboard (`http://localhost:8501`) contains 8 integrated modules:

| Module | Purpose |
| :--- | :--- |
| **📊 Overview** | Pipeline health matrix, P95 latencies, global KPI cards, recent runs table |
| **📁 Datasets & Ingestion** | Dynamic file upload (CSV, JSON, Excel), schema profiling, and 5-stage observable pipeline execution |
| **🧹 Dataset Cleaning & Export** | In-browser data sanitization, IQR clipping, smart imputation, and CSV/XLSX download |
| **🧪 Simulator Lab** | Fault injection testbed (schema break, null spike, value corruption) to simulate real-world crashes |
| **🚨 Incidents & Recovery** | Incident triage, RCA breakdown, DAG blast radius, and RBAC-gated recovery execution |
| **📧 Email Alerts & Notifications** | SMTP settings management, 5-member recipient configuration, test email trigger, delivery logs |
| **📈 Drift Explorer** | PSI divergence, KS-test distributions, and Isolation Forest ML anomaly scatter plots |
| **🛡️ Audit & Knowledge** | SHA-256 cryptographic hash chain verification, audit trail, and searchable failure resolution knowledge base |

---

## 🛠️ Technology Stack

- **Backend:** Python 3.11+, SQLite (with WAL mode & foreign keys), PostgreSQL 15 upgrade
- **Data & Machine Learning:** Pandas, NumPy, Scikit-learn (Isolation Forest), SciPy (KS-Test), OpenPyXL
- **Frontend Command Center:** Streamlit, Plotly Interactive Visualizations
- **Alerting & Transport:** Python SMTP / STARTTLS / SSL with MIME Multipart HTML templates
- **DevOps & Testing:** Docker, Docker Compose, GitHub Actions (CI/CD), Pytest (**77 automated tests**), Git

---

## ⚙️ Environment Configuration

DataGuard supports environment variables for production secrets and automated deployments. An example template is provided in [`.env.example`](.env.example):

```bash
# Copy template to .env
cp .env.example .env
```

| Variable | Description | Default |
| :--- | :--- | :--- |
| `DATAGUARD_SMTP_HOST` | Outgoing SMTP host (e.g. `smtp.gmail.com`) | `smtp.gmail.com` |
| `DATAGUARD_SMTP_PORT` | SMTP port (e.g. `587` for STARTTLS, `465` for SSL) | `587` |
| `DATAGUARD_SENDER_EMAIL` | From address for outgoing alerts | `alerts@dataguard.local` |
| `DATAGUARD_SMTP_USER` | SMTP authentication username / email | `""` |
| `DATAGUARD_SMTP_PASSWORD` | App Password or secure SMTP token | `""` |

> **Note:** If no credentials are provided, DataGuard automatically defaults to **Mock / Sandbox Mode**, simulating and logging all alerts safely into the database without connecting to external SMTP servers.

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

# Run all 77 automated tests
pytest tests/ -v

# Launch the Streamlit command center
streamlit run src/ui/app.py
```

---

## 🧪 Running Automated Tests

DataGuard is built with strict Test-Driven Development (TDD) containing **82 unit and integration tests**:

```bash
pytest tests/ -v
```

```text
tests/test_audit_and_kb.py .............. [5 passed]
tests/test_audit_dataset_scenarios.py ... [7 passed]
tests/test_data_cleaner.py .............. [7 passed]
tests/test_database.py .................. [5 passed]
tests/test_dataset_extended.py .......... [10 passed]
tests/test_dataset_service.py ........... [7 passed]
tests/test_drift_detector.py ............ [4 passed]
tests/test_email_service.py ............. [11 passed]
tests/test_incidents_and_sla.py ......... [6 passed]
tests/test_quality_engine.py ............ [5 passed]
tests/test_rca_and_impact.py ............ [7 passed]
tests/test_recovery.py .................. [3 passed]
tests/test_simulator.py ................. [5 passed]
==================== 82 passed in ~7.0s ====================
```

---

## 👥 Role-Based Access Control (RBAC) Accounts

| Username | Role | Permissions |
| :--- | :--- | :--- |
| `admin` | **Admin** | Full access: trigger runs, approve recovery, configure email/SMTP settings |
| `engineer_alice` | **Engineer** | Operational access: trigger runs, triage incidents, approve recovery, trigger test alerts |
| `viewer_bob` | **Viewer** | Read-only access: view dashboards, inspect telemetry (cannot approve recovery or edit settings) |

---

## 📄 License

This project is licensed under the MIT License.
