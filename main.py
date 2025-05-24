#!/usr/bin/env python3
"""
EVIL_JWT_FORCE - Entry Point Avançado
Orquestrador central para CLI, GUI e integração dinâmica de módulos/scripts.
"""

import sys
import os
import subprocess
import importlib
from pathlib import Path

# Garante que todos os diretórios essenciais estão no sys.path
PROJECT_ROOT = Path(__file__).resolve().parent
for subdir in ["core", "utils", "modules", "config", "scripts"]:
    sys.path.insert(0, str(PROJECT_ROOT / subdir))
sys.path.insert(0, str(PROJECT_ROOT))

# Logging avançado
try:
    from utils.logger import setup_logger
except ImportError:
    import logging
    def setup_logger(*args, **kwargs):
        logging.basicConfig(level=logging.INFO)
        return logging.getLogger("EVIL_JWT_FORCE_Fallback")
logger = setup_logger("EVIL_JWT_FORCE.main")

# Importação dinâmica dos módulos principais
def import_module_safe(module_path, symbol=None):
    try:
        mod = importlib.import_module(module_path)
        if symbol:
            return getattr(mod, symbol)
        return mod
    except Exception as e:
        logger.error(f"Erro ao importar {module_path}: {e}")
        return None

# Função para iniciar a interface gráfica
def start_gui():
    gui_path = PROJECT_ROOT / "gui" / "interface.py"
    if not gui_path.exists():
        logger.error("interface.py não encontrado em gui/")
        sys.exit(3)
    logger.info("Iniciando interface gráfica...")
    if os.name == "nt":
        subprocess.Popen(f'start "" python "{gui_path}"', shell=True)
    else:
        subprocess.Popen([sys.executable, str(gui_path)])
    sys.exit(0)

# Função para executar scripts utilitários
def run_script(script_name, *args):
    script_path = PROJECT_ROOT / "scripts" / script_name
    if not script_path.exists():
        logger.error(f"Script não encontrado: {script_name}")
        return
    logger.info(f"Executando script: {script_name}")
    subprocess.run([sys.executable, str(script_path)] + list(args), check=True)

# Função para executar módulos core dinamicamente
def run_core_module(module_key, **kwargs):
    modules = {
        "auth":      ("core.auth", "Authenticator"),
        "wordlist":  ("core.wordlist_generator", "run"),
        "bruteforce":("core.bruteforce", "JWTBruteforcer"),
        "aes":       ("core.aes_decrypt", "run"),
        "sql":       ("core.sql_injector", "SQLInjector"),
        "sentry":    ("core.sentry_simulator", "run"),
        "report":    ("core.report", "generate_html_report")
    }
    if module_key not in modules:
        logger.error(f"Módulo '{module_key}' não encontrado.")
        return
    module_path, symbol = modules[module_key]
    obj = import_module_safe(module_path, symbol)
    if obj is None:
        logger.error(f"Falha ao carregar {module_path}.{symbol}")
        return
    try:
        if callable(obj):
            obj(**kwargs)
        else:
            if hasattr(obj, "run"):
                obj.run(**kwargs)
            else:
                logger.warning(f"Módulo {module_key} não possui método executável padrão.")
    except Exception as e:
        logger.error(f"Erro ao executar módulo {module_key}: {e}", exc_info=True)

# Função principal de orquestração
def main():
    import argparse
    parser = argparse.ArgumentParser(description="EVIL_JWT_FORCE - Orquestrador CLI/GUI")
    parser.add_argument('--cli', action='store_true', help='Iniciar interface de linha de comando')
    parser.add_argument('--auto', action='store_true', help='Executar modo automático completo')
    parser.add_argument('--manual', action='store_true', help='Executar modo manual')
    parser.add_argument('--module', type=str, help='Executar módulo específico (ex: auth, wordlist, bruteforce, aes, sql, sentry, report)')
    parser.add_argument('--script', type=str, help='Executar script utilitário da pasta scripts/')
    parser.add_argument('--config', type=str, help='Arquivo de configuração customizado')
    parser.add_argument('--args', nargs=argparse.REMAINDER, help='Argumentos adicionais para módulos/scripts')
    args = parser.parse_args()

    logger.info("Inicializando EVIL_JWT_FORCE...")

    # GUI padrão (se --cli não for passado)
    if not args.cli:
        start_gui()

    # Execução de script utilitário
    if args.script:
        run_script(args.script, *(args.args or []))
        return

    # Execução de módulo core específico
    if args.module:
        run_core_module(args.module, config=args.config, extra_args=args.args)
        return

    # CLI Automático
    if args.auto:
        logger.info("Executando modo automático completo (CLI)...")
        cli_main = import_module_safe("core.cli", "run_automatic_mode")
        if cli_main:
            cli_main()
        else:
            logger.error("Falha ao iniciar modo automático.")
        return

    # CLI Manual
    if args.manual:
        logger.info("Executando modo manual (CLI)...")
        cli_manual = import_module_safe("core.cli", "run_manual_mode")
        if cli_manual:
            cli_manual()
        else:
            logger.error("Falha ao iniciar modo manual.")
        return

    # CLI Interativo padrão
    cli_entry = import_module_safe("core.cli", "main")
    if cli_entry:
        cli_entry()
    else:
        logger.error("Falha ao iniciar CLI principal.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.warning("Execução interrompida pelo usuário.")
        sys.exit(130)
    except Exception as e:
        logger.error(f"Erro fatal: {e}", exc_info=True)
        sys.exit(1)