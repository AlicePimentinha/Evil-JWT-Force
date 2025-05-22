"""
Módulo de logging customizado
"""

import os
import logging
from pathlib import Path
from datetime import datetime

# Configurações de cores
COLORS = {
    'SUCCESS': '\033[92m',
    'WARNING': '\033[93m',
    'ERROR': '\033[91m',
    'INFO': '\033[94m',
    'RESET': '\033[0m'
}

# Configuração do diretório de logs
LOG_DIR = Path(__file__).resolve().parent.parent / "logs"

def setup_logger(name: str = "EVIL_JWT_FORCE") -> logging.Logger:
    """
    Configura e retorna um logger customizado
    
    Args:
        name: Nome do logger
        
    Returns:
        Logger configurado
    """
    # Criar diretório de logs se não existir
    os.makedirs(LOG_DIR, exist_ok=True)
    
    # Configurar logger
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    
    # Evitar handlers duplicados
    if not logger.handlers:
        # Handler para arquivo
        log_file = LOG_DIR / f"{name}_{datetime.now().strftime('%Y%m%d')}.log"
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setLevel(logging.INFO)
        
        # Handler para console
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        
        # Formatação
        formatter = logging.Formatter(
            '[%(asctime)s] [%(levelname)s] %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)
        
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)
    
    return logger

# Criar logger global
logger = setup_logger()