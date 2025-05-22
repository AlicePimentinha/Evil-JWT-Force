#!/usr/bin/env python3
"""
EVIL_JWT_FORCE - JWT Security Testing Tool
"""

import sys
from pathlib import Path
from core.auth import Authenticator
from core.cli import parse_args
from utils.logger import setup_logger

def setup_environment():
    """Configura o ambiente inicial"""
    for directory in ['logs', 'output', 'reports']:
        Path(directory).mkdir(exist_ok=True)

def main():
    # Configurar logger
    logger = setup_logger()
    
    try:
        # Configurar ambiente
        setup_environment()
        
        # Parsear argumentos
        args = parse_args()
        
        # Inicializar autenticador
        auth = Authenticator(args.target_url)
        
        # Executar ações baseadas nos argumentos
        if args.mode == 'auto':
            auth.auto_attack()
        else:
            auth.manual_attack()
            
    except Exception as e:
        logger.error(f"Erro: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()