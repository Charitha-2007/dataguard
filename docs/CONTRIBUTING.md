# DataGuard Team Contribution Guidelines

Welcome to the DataGuard engineering team. To ensure seamless collaboration among our five team members, please adhere to these Git and code quality standards.

## 👥 Team Roles & Modules

1. **Member 1 – DevOps & Platform:** Repos, CI/CD (`.github/`), Docker (`docker-compose.yml`, `Dockerfile`), configs (`config/`).
2. **Member 2 – Data Engineering & Backend:** Ingestion (`src/services/dataset_service.py`), cleaner (`data_cleaner.py`), simulator (`simulator.py`).
3. **Member 3 – Frontend & UI/UX:** Presentation views, interactive widgets, Plotly telemetry (`src/ui/`).
4. **Member 4 – Quality & Detection:** Quality engine (`quality_engine.py`), drift detector (`drift_detector.py`), SLA monitor (`sla_monitor.py`), recovery (`src/recovery/`).
5. **Member 5 – Database, Security & QA:** DB models/DAO (`src/database/`), audit ledger (`audit_service.py`), RBAC (`auth.py`), contract tests (`tests/`).

---

## 🌿 Git Branching Strategy

- **`main`**: Production-ready branch. Protected. Direct pushes disabled.
- **`develop`**: Integration and staging branch. All feature branches merge here via Pull Request.
- **`feature/m<N>-<short-description>`**: Dedicated branch for individual member tasks:
  - Example: `feature/m1-ci-matrix`
  - Example: `feature/m2-parquet-ingest`
  - Example: `feature/m3-psi-gauge`
  - Example: `feature/m4-ks-drift`
  - Example: `feature/m5-audit-indexes`

---

## 🔄 Pull Request Workflow

1. Branch off `develop`:
   ```bash
   git checkout develop
   git pull origin develop
   git checkout -b feature/m2-my-feature
   ```
2. Commit changes using Conventional Commits:
   - `feat(ingestion): support streaming csv chunks`
   - `fix(drift): handle zero variance in PSI calculation`
   - `test(security): add test for role escalation rejection`
3. Run test suite locally:
   ```bash
   pytest tests/
   ```
4. Push branch and open a Pull Request targeting **`develop`**:
   ```bash
   git push origin feature/m2-my-feature
   ```
5. Assign at least one peer reviewer. Ensure GitHub Actions CI passes before merging.
