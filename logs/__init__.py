"""
EVIL_JWT_FORCE - Log Package

Este pacote é usado para centralizar logs da aplicação.
Cada execução pode gerar arquivos individuais de log.
"""

import logging
import os
from datetime import datetime

LOG_DIR = os.path.dirname(os.path.abspath(__file__))

def get_logger(name="EVIL_JWT_FORCE"):
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)

    log_filename = os.path.join(LOG_DIR, f"{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.log")
    file_handler = logging.FileHandler(log_filename)
    formatter = logging.Formatter('[%(asctime)s] %(levelname)s: %(message)s')
    file_handler.setFormatter(formatter)

    if not logger.hasHandlers():
        logger.addHandler(file_handler)

    return logger
