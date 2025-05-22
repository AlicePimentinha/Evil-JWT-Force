#!/usr/bin/env python3
"""
EVIL_JWT_FORCE - JWT Security Testing Tool
"""

import sys
from pathlib import Path
project_root = Path(__file__).resolve().parent
sys.path.insert(0, str(project_root))
sys.path.insert(0, str(project_root / "core"))
sys.path.insert(0, str(project_root / "utils"))
try:
    from core.auth import Authenticator
    from core.cli import parse_args
    from utils.logger import setup_logger
except ImportError as e:
    print(f"[FATAL] Falha ao importar módulos essenciais: {e}")
    sys.exit(2)
import argparse
import subprocess
import os

def setup_environment():
    """Configura o ambiente inicial"""
    for directory in ['logs', 'output', 'reports']:
        Path(directory).mkdir(exist_ok=True)

def main():
    logger = setup_logger()
    try:
        setup_environment()
        parser = argparse.ArgumentParser(description="EVIL_JWT_FORCE - CLI e GUI")
        parser.add_argument('--gui', action='store_true', help='Iniciar interface gráfica')
        # Adicione outros argumentos conforme necessário
        args, unknown = parser.parse_known_args()

        if args.gui:
            gui_path = os.path.join(os.path.dirname(__file__), "gui", "interface.py")
            subprocess.Popen(['python', gui_path])
            return

        # Inicializar autenticador
        auth = Authenticator(args.target_url)

        # Executar ações baseadas nos argumentos
        if hasattr(args, 'mode') and args.mode == 'auto':
            auth.auto_attack()
        else:
            auth.manual_attack()

    except Exception as e:
        logger.error(f"Erro: {e}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    main()
    # O restante do main permanece igual, rodando o modo CLI normalmente
    # ... existing code ...