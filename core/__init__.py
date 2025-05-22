"""
EVIL_JWT_FORCE Core Package
Funcionalidades principais do sistema
"""

from .auth import Authenticator
from .cli import parse_args
from .report import generate_report
from .bruteforce import JWTBruteforcer
from .sql_injector import SQLInjector

__all__ = [
    "Authenticator",
    "parse_args",
    "generate_report",
    "JWTBruteforcer",
    "SQLInjector"
]

__version__ = "1.0.0"