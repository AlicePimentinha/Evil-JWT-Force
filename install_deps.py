import os
import subprocess
import sys
import venv
from pathlib import Path

def create_venv(venv_dir):
    if not venv_dir.exists():
        print(f"Criando ambiente virtual em: {venv_dir}")
        venv.create(venv_dir, with_pip=True)
    else:
        print(f"Ambiente virtual já existe em: {venv_dir}")

def install_requirements(venv_dir, requirements_file):
    pip_executable = venv_dir / "Scripts" / "pip.exe" if os.name == "nt" else venv_dir / "bin" / "pip"
    if not pip_executable.exists():
        raise RuntimeError("pip não encontrado no ambiente virtual!")
    print(f"Instalando dependências do {requirements_file}...")
    subprocess.check_call([str(pip_executable), "install", "-r", str(requirements_file)])
    print("Dependências instaladas com sucesso no ambiente virtual!")

def main():
    base_dir = Path(__file__).parent.resolve()
    venv_dir = base_dir / "venv"
    requirements_file = base_dir / "requirements.txt"

    create_venv(venv_dir)
    install_requirements(venv_dir, requirements_file)

if __name__ == "__main__":
    main()