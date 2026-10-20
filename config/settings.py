import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

# Network Interface Settings
DEFAULT_INTERFACE = os.getenv("NIDS_IFACE", "auto")
DEFAULT_PORT = int(os.getenv("NIDS_PORT", "8050"))
DEFAULT_HOST = os.getenv("NIDS_HOST", "127.0.0.1")

# Flow Management Settings
FLOW_TIMEOUT_SECONDS = 10.0   # Inactive flow expiration
FLOW_TICK_INTERVAL = 1.0       # Feature extraction window interval (seconds)

# Database
DB_PATH = BASE_DIR / "alerts.db"

# Model Paths
MODELS_DIR = BASE_DIR / "models"
ISOLATION_FOREST_PATH = MODELS_DIR / "isolation_forest.joblib"
RANDOM_FOREST_PATH = MODELS_DIR / "random_forest.joblib"
SCALER_PATH = MODELS_DIR / "scaler.joblib"

# Rules Configuration
RULES_CONFIG_PATH = BASE_DIR / "config" / "rules.yaml"

# QoS Mitigation Settings
QOS_MODE = os.getenv("QOS_MODE", "auto")  # 'linux_tc', 'virtual', or 'auto'
QOS_COOLDOWN_SECONDS = 15.0               # Time without attack before restoring QoS tier
DEFAULT_BANDWIDTH_MBPS = 100              # Normal baseline bandwidth

# Risk Scoring Weights
FUSION_WEIGHT_SIGNATURE = 0.60
FUSION_WEIGHT_ML = 0.40

# Risk Thresholds
THRESHOLD_SUSPICIOUS = 35.0
THRESHOLD_HIGH = 65.0
THRESHOLD_CRITICAL = 80.0
