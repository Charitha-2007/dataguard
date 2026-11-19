"""Central configuration settings for DataGuard.

Defines filesystem paths, database connection properties, default thresholds,
and environment parameters using standard Python libraries.
"""

import os
from pathlib import Path

# Base Paths
BASE_DIR = Path(__file__).resolve().parent.parent

# Auto-load .env file into os.environ if present
env_file = BASE_DIR / ".env"
if env_file.exists():
    try:
        with open(env_file, "r", encoding="utf-8") as _ef:
            for _line in _ef:
                _line = _line.strip()
                if _line and not _line.startswith("#") and "=" in _line:
                    _k, _v = _line.split("=", 1)
                    _k = _k.strip()
                    _v = _v.strip().strip("'\"")
                    if _k and _k not in os.environ:
                        os.environ[_k] = _v
    except Exception:
        pass
CONFIG_DIR = BASE_DIR / "config"
DATA_DIR = BASE_DIR / "data"
RAW_DATA_DIR = DATA_DIR / "raw"
PROCESSED_DATA_DIR = DATA_DIR / "processed"
MOCK_DATA_DIR = DATA_DIR / "mock_pipeline_data"
UPLOAD_DATA_DIR = DATA_DIR / "uploads"

# Ensure runtime directories exist
for directory in [DATA_DIR, RAW_DATA_DIR, PROCESSED_DATA_DIR, MOCK_DATA_DIR, UPLOAD_DATA_DIR]:
    directory.mkdir(parents=True, exist_ok=True)

# Database Configuration
DATABASE_PATH = DATA_DIR / "dataguard.db"
DATABASE_URL = f"sqlite:///{DATABASE_PATH}"

# Quality & Observability Thresholds
DEFAULT_NULL_THRESHOLD_PCT = 5.0     # Alert if > 5% missing values in critical columns
DEFAULT_DUPLICATE_THRESHOLD_PCT = 2.0 # Alert if > 2% duplicate primary keys
DEFAULT_DRIFT_THRESHOLD_PVAL = 0.05  # KS-test p-value significance threshold
DEFAULT_PSI_DRIFT_THRESHOLD = 0.2    # Population Stability Index (PSI > 0.2 indicates significant drift)
DEFAULT_SLA_MAX_LATENCY_SEC = 300    # Default pipeline SLA timeout: 5 minutes (300 seconds)

# Security & Audit
SECRET_KEY = "dataguard-super-secret-key-change-in-production"
AUDIT_LOG_TAMPER_PROTECTION = True
