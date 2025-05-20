"""
EVIL_JWT_FORCE Utils Module

Este pacote contém funções e classes utilitárias auxiliares utilizadas em diversos módulos do sistema:

- helpers.py: Funções auxiliares gerais.
- proxy_rotator.py: Gerenciador de rotação de proxies para requests.
- osint_scraper.py: Scraper de dados para coleta OSINT.
- request_builder.py: Construtor de requisições personalizadas.
"""

__version__ = "1.0.0"
__author__ = "EVIL_JWT_FORCE Team"
__license__ = "MIT"

from . import (
    helpers,
    proxy_rotator,
    osint_scraper,
    request_builder
)

__all__ = [
    "helpers",
    "proxy_rotator",
    "osint_scraper",
    "request_builder"
]
