"""
EVIL_JWT_FORCE Modules Package
Módulos principais de funcionalidade
"""

from .crypto_utils import *
from .jwt_utils import *
from .osint_enhanced import *
from .scan_target import *
from .token_bruteforce import *
from .wordlist_engine import *

__all__ = [
    "aes_decrypt",
    "jwt_decode",
    "jwt_encode",
    "scan_target",
    "osint_scan",
    "bruteforce_token",
    "generate_wordlist"
]

__version__ = "1.0.0"