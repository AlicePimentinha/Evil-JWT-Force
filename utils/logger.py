import logging
from datetime import datetime
from pathlib import Path
from config.constants import LOG_DIR, COLORS

class CustomFormatter(logging.Formatter):
    def __init__(self):
        super().__init__(
            fmt="%(asctime)s - %(levelname)s - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        
    def format(self, record):
        if record.levelno == logging.INFO:
            record.msg = f"{COLORS['info']}{record.msg}{COLORS['reset']}"
        elif record.levelno == logging.WARNING:
            record.msg = f"{COLORS['warning']}{record.msg}{COLORS['reset']}"
        elif record.levelno == logging.ERROR:
            record.msg = f"{COLORS['error']}{record.msg}{COLORS['reset']}"
        elif record.levelno == logging.CRITICAL:
            record.msg = f"{COLORS['error']}[CRÍTICO] {record.msg}{COLORS['reset']}"
        return super().format(record)

def setup_logger(name="evil_jwt_force"):
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    
    # Criar diretório de logs se não existir
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    
    # Handler para arquivo
    file_handler = logging.FileHandler(LOG_DIR / f"{name}_{datetime.now():%Y%m%d}.log")
    file_handler.setFormatter(logging.Formatter(
        "%(asctime)s - %(levelname)s - %(message)s"
    ))
    
    # Handler para console
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(CustomFormatter())
    
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    return logger

logger = setup_logger()