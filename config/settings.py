"""
Central configuration management for IoT Shodan project
"""

import os
import json
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Project root directory
PROJECT_ROOT = Path(__file__).parent.parent

# API Configuration
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "")
MAX_RESULTS = int(os.getenv("MAX_RESULTS", "100"))
TIMEOUT = int(os.getenv("TIMEOUT", "30"))

# Logging Configuration
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
LOGS_DIR = PROJECT_ROOT / "logs"
LOGS_DIR.mkdir(exist_ok=True)

# Output Configuration
REPORTS_DIR = Path(os.getenv("REPORTS_DIR", PROJECT_ROOT / "reports"))
REPORTS_DIR.mkdir(exist_ok=True)

# Proxy Configuration (optional)
PROXY = os.getenv("PROXY", None)
PROXY_USER = os.getenv("PROXY_USER", None)
PROXY_PASS = os.getenv("PROXY_PASS", None)

# Vulnerability Detection Patterns
VULN_PATTERNS = {
    "default_credentials": [
        r"(?i)\badmin\b",
        r"(?i)\broot\b",
        r"(?i)\bdefault\b",
        r"(?i)password.*=",
        r"(?i)\b123456\b",
        r"(?i)\badmin123\b",
    ],
    "auth_errors": [401, 403],
    "common_cves": {
        "Hikvision": ["CVE-2021-36260", "CVE-2021-36261"],
        "Dahua": ["CVE-2020-5902", "CVE-2020-5903"],
        "OpenSSH": ["CVE-2018-15473", "CVE-2020-14145"],
    },
    "risky_banners": [
        r"(?i)test",
        r"(?i)debug",
        r"(?i)temporary",
        r"(?i)experimental",
    ]
}

# Severity Scoring
RISK_SCORES = {
    "default_credentials": 8,
    "auth_error": 6,
    "known_cve": 9,
    "risky_banner": 5,
    "unencrypted_protocol": 7,
}

# Load predefined filters from config/filters.json
FILTERS_CONFIG_PATH = PROJECT_ROOT / "config" / "filters.json"
try:
    with open(FILTERS_CONFIG_PATH, "r", encoding="utf-8") as f:
        PREDEFINED_FILTERS = json.load(f)
except FileNotFoundError:
    PREDEFINED_FILTERS = {}

# Validation
def validate_config():
    """Validate critical configuration values"""
    if not SHODAN_API_KEY:
        raise ValueError(
            "SHODAN_API_KEY not set. Please copy .env.example to .env "
            "and add your API key."
        )
    return True
