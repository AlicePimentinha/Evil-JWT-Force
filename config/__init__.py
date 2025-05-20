"""
EVIL_JWT_FORCE - Configuração Centralizada

Este pacote gerencia todas as configurações globais, como caminhos de diretório, parâmetros padrão,
e flags de execução. Pode ser expandido para suporte a arquivos .env, .json ou .yaml.
"""

import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

CONFIG = {
    "JWT_SECRET_WORDLIST": os.path.join(BASE_DIR, "jwt_secrets.txt"),
    "DEFAULT_ENCODING": "utf-8",
    "LOG_LEVEL": "DEBUG",
    "TIMEZONE": "UTC",
    "AES_IV": b"\x00" * 16  # Pode ser sobrescrito por config externa
}

def get_config(key, default=None):
    return CONFIG.get(key, default)

def set_config(key, value):
    CONFIG[key] = value
