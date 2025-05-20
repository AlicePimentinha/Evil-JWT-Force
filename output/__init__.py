"""
EVIL_JWT_FORCE - Reports Package

Responsável pela manipulação e estruturação dos relatórios gerados.
Relatórios HTML e JSON podem ser salvos e exportados a partir deste diretório.
"""

import os

REPORT_DIR = os.path.dirname(os.path.abspath(__file__))

def get_report_path(filename="report.html"):
    return os.path.join(REPORT_DIR, filename)

def list_existing_reports():
    return [f for f in os.listdir(REPORT_DIR) if f.endswith(".html") or f.endswith(".json")]
