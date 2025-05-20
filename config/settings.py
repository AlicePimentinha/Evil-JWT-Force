"""Configurações do EVIL_JWT_FORCE."""
from pathlib import Path
import json

CONFIG_FILE = Path(__file__).parent / "config.json"

BASE_DIR = Path(__file__).parent.parent
CONFIG = {
    "paths": {
        "data": BASE_DIR / "data",
        "output": BASE_DIR / "output",
        "logs": BASE_DIR / "logs",
        "reports": BASE_DIR / "reports"
    },
    "jwt": {
        "algorithms": ["HS256", "RS256"],
        "exp_delta": 3600
    }
}

DEFAULT_CONFIG = {
    "target_url": "",
    "threads": 10,
    "proxy": "http://127.0.0.1:8080",
    "timeout": 10,
    "user_agent": "EVIL-JWT-FORCE/1.0",
    "wordlist": "data/wordlist.txt",
    "output_dir": "output",
    "log_level": "INFO"
}

def load_config():
    if CONFIG_FILE.exists():
        with open(CONFIG_FILE) as f:
            return {**DEFAULT_CONFIG, **json.load(f)}
    return DEFAULT_CONFIG

def save_config(config):
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=4)

config = load_config()