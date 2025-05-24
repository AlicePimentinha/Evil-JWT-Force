"""
EVIL_JWT_FORCE Modules Package
Módulos principais de funcionalidade e integração centralizada dos submódulos.
"""

from .aes_decrypt import *
from .auto_scanner import *
from .crypto_utils import *
from .fuzz_jwt import *
from .jwt_utils import *
from .osint_enhanced import *
from .osint_module import *
from .scan_target import *
from .token_bruteforce import *
from .wordlist_engine import *

__all__ = [
    # aes_decrypt.py
    "aes_decrypt",
    # auto_scanner.py
    "auto_scan",
    # crypto_utils.py
    "encrypt_data", "decrypt_data", "generate_key",  # Ajuste conforme funções reais do módulo
    # fuzz_jwt.py
    "fuzz_jwt",
    # jwt_utils.py
    "decode_jwt", "extract_parts", "generate_token", "generate_rsa_keypair", "generate_ec_keypair", "create_jwt",
    # osint_enhanced.py
    "OSINTEnhanced",  # Ajuste conforme classe/função real
    # osint_module.py
    "OSINTModule",    # Ajuste conforme classe/função real
    # scan_target.py
    "scan_target",
    # token_bruteforce.py
    "TokenBruteforcer",
    # wordlist_engine.py
    "generate_wordlist"
]

__version__ = "1.0.0"
__author__ = "EVIL_JWT_FORCE Team"
__license__ = "MIT"