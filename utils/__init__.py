"""
EVIL_JWT_FORCE Utils Module
Este pacote contém funções e classes utilitárias auxiliares.
"""

from .helpers import (
    save_to_file,
    read_lines,
    write_lines,
    generate_nonce,
    get_current_timestamp,
    formatted_time,
    log_format
)
from .proxy_rotator import ProxyRotator
from .osint_scraper import OSINTScraper
from .request_builder import RequestBuilder
from .logger import setup_logger

__all__ = [
    "save_to_file",
    "read_lines",
    "write_lines",
    "generate_nonce",
    "get_current_timestamp",
    "formatted_time",
    "log_format",
    "ProxyRotator",
    "OSINTScraper",
    "RequestBuilder",
    "setup_logger"
]

__version__ = "1.0.0"
__author__ = "EVIL_JWT_FORCE Team"
__license__ = "MIT"