"""
EVIL_JWT_FORCE Scripts Package
Scripts utilitários para tarefas específicas
"""

import os
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

def list_available_scripts():
    """Lista os scripts disponíveis no pacote"""
    return [f for f in os.listdir(BASE_DIR) if f.endswith(".py") and f != "__init__.py"]

__version__ = "1.0.0"