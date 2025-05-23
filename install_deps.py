import os
import subprocess
import sys
import venv
from pathlib import Path
import logging

def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s"
    )

def create_venv(venv_dir):
    if not venv_dir.exists():
        logging.info(f"Criando ambiente virtual em: {venv_dir}")
        venv.create(venv_dir, with_pip=True)
    else:
        logging.info(f"Ambiente virtual já existe em: {venv_dir}")

def get_pip_executable(venv_dir):
    if os.name == "nt":
        pip_executable = venv_dir / "Scripts" / "pip.exe"
    else:
        pip_executable = venv_dir / "bin" / "pip"
    if not pip_executable.exists():
        raise RuntimeError("pip não encontrado no ambiente virtual!")
    return pip_executable

def install_requirements(venv_dir, requirements_file):
    pip_executable = get_pip_executable(venv_dir)
    if not requirements_file.exists():
        raise FileNotFoundError(f"Arquivo de dependências não encontrado: {requirements_file}")
    logging.info(f"Instalando dependências do {requirements_file}...")
    try:
        subprocess.check_call([str(pip_executable), "install", "--upgrade", "pip"])
        subprocess.check_call([str(pip_executable), "install", "-r", str(requirements_file)])
        logging.info("Dependências instaladas com sucesso no ambiente virtual!")
    except subprocess.CalledProcessError as e:
        logging.error(f"Erro ao instalar dependências: {e}")
        sys.exit(1)

def main():
    setup_logging()
    base_dir = Path(__file__).parent.resolve()
    venv_dir = base_dir / "venv"
    requirements_file = base_dir / "requirements.txt"

    try:
        create_venv(venv_dir)
        install_requirements(venv_dir, requirements_file)
    except Exception as e:
        logging.error(f"Falha na instalação das dependências: {e}")
        sys.exit(2)

if __name__ == "__main__":
    main()