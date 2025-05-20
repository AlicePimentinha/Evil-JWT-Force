"""
EVIL_JWT_FORCE Core Module

Este pacote contém os principais módulos de execução ofensiva:

- auth.py: Coleta e autenticação automática.
- wordlist_generator.py: Geração de wordlists com base em dados coletados.
- bruteforce.py: Quebra de JWT usando força bruta.
- aes_decrypt.py: Descriptografia de dados AES.
- sql_injector.py: Exploração SQLi de endpoints.
- sentry_simulator.py: Simulação de tráfego legítimo/ilegítimo.

Todos os módulos podem ser chamados diretamente a partir do cli.py.
"""

__version__ = "1.0.0"
__author__ = "EVIL_JWT_FORCE Team"
__license__ = "MIT"

from . import (
    auth,
    wordlist_generator,
    bruteforce,
    aes_decrypt,
    sql_injector,
    sentry_simulator
)

__all__ = [
    "auth",
    "wordlist_generator",
    "bruteforce",
    "aes_decrypt",
    "sql_injector",
    "sentry_simulator"
]
