"""Constantes globais para o EVIL_JWT_FORCE."""
import os
from pathlib import Path

# Diretórios base
BASE_DIR = Path(__file__).parent.parent
DATA_DIR = BASE_DIR / "data"
OUTPUT_DIR = BASE_DIR / "output"
LOG_DIR = BASE_DIR / "logs"
REPORT_DIR = BASE_DIR / "reports"

# Arquivos
VALID_CREDS_FILE = OUTPUT_DIR / "valid_credentials.txt"
INVALID_CREDS_FILE = OUTPUT_DIR / "invalid_credentials.txt"
WORDLIST_FILE = DATA_DIR / "wordlist.txt"
TESTED_WORDS_FILE = DATA_DIR / "wordlist_tested.txt"
LOG_FILE = LOG_DIR / "jwt_force.log"
REPORT_FILE = REPORT_DIR / "report.html"

# Configurações HTTP
DEFAULT_TIMEOUT = 10
DEFAULT_USER_AGENT = "EVIL-JWT-FORCE/1.0"
DEFAULT_THREADS = 10
DEFAULT_PROXY = "http://127.0.0.1:8080"

# JWT Configurações
JWT_ALGORITHMS = ["HS256", "RS256", "ES256", "PS256"]
JWT_EXP_DELTA = 3600

# Headers padrão
DEFAULT_HEADERS = {
    "Content-Type": "application/json",
    "User-Agent": DEFAULT_USER_AGENT
}

# Cores para output
COLORS = {
    "success": "\033[92m",
    "error": "\033[91m",
    "warning": "\033[93m",
    "info": "\033[94m",
    "reset": "\033[0m"
}
