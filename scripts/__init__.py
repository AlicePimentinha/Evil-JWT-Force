"""
EVIL_JWT_FORCE - Scripts Package

Scripts utilitários que podem ser usados de forma independente para tarefas específicas,
como análise offline, conversão de tokens, scraping autônomo, entre outros.
"""

import os
import sys

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

def list_available_scripts():
    """Lista os scripts disponíveis no pacote."""
    return [f for f in os.listdir(BASE_DIR) if f.endswith(".py") and f != "__init__.py"]

if __name__ == "__main__":
    print("Scripts disponíveis:")
    for script in list_available_scripts():
        print(f"- {script}")