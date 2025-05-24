"""
Motor avançado para integração, geração e manipulação de wordlists dinâmicas.
"""

import os
import threading
from termcolor import cprint
from datetime import datetime
from core.wordlist_generator import WordlistGenerator

WORDLIST_DATA_DIR = os.path.join("output", "data", "wordlist")
DEFAULT_WORDLIST_FILE = os.path.join(WORDLIST_DATA_DIR, "wordlist_final.txt")

def save_wordlist(words, filename=DEFAULT_WORDLIST_FILE):
    try:
        os.makedirs(os.path.dirname(filename), exist_ok=True)
        with open(filename, 'w', encoding='utf-8') as f:
            for word in words:
                f.write(f"{word}\n")
        cprint(f"[✓] Wordlist salva em {filename}", "green")
    except Exception as e:
        cprint(f"[x] Erro ao salvar wordlist: {e}", "red")

def generate_common_passwords():
    # Lista ampliada de senhas comuns
    return [
        "admin", "123456", "password", "jwt123", "letmein", "eviljwt", "secretkey",
        "tokenforce", "bruteforce", "senha", "qwerty", "abc123", "betadmin", "bet333",
        "user", "root", "passw0rd", "12345678", "welcome", "master", "superuser"
    ]

def gerar_wordlist_avancada(dump_file='dump_users.txt', tested_file='wordlist_tested.txt', target_url=None, domain=None, output_file=DEFAULT_WORDLIST_FILE):
    """
    Orquestra a geração de uma wordlist avançada integrando múltiplas fontes.
    """
    cprint("[*] Iniciando geração avançada de wordlist...", "cyan")
    generator = WordlistGenerator(dump_file=dump_file, tested_file=tested_file)
    generator.generate_wordlist(output_file=output_file, target_url=target_url, domain=domain)
    cprint(f"[✓] Wordlist final gerada em {output_file}", "green")

def atualizar_wordlists_periodicamente(intervalo=3600, dump_file='dump_users.txt', tested_file='wordlist_tested.txt', target_url=None, domain=None):
    """
    Atualiza periodicamente as wordlists com scraping e enriquecimento.
    """
    def atualizar():
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = os.path.join(WORDLIST_DATA_DIR, f"wordlist_{timestamp}.txt")
        gerar_wordlist_avancada(dump_file, tested_file, target_url, domain, output_file)
        threading.Timer(intervalo, atualizar).start()
    atualizar()

def carregar_wordlist(filename=DEFAULT_WORDLIST_FILE):
    """
    Carrega uma wordlist de um arquivo .txt.
    """
    if not os.path.exists(filename):
        return []
    with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
        return [line.strip() for line in f if line.strip()]

def integrar_com_generator(dump_file='dump_users.txt', tested_file='wordlist_tested.txt', target_url=None, domain=None):
    """
    Interface inteligente para comunicação com o WordlistGenerator.
    """
    cprint("[*] Integrando com WordlistGenerator...", "cyan")
    gerar_wordlist_avancada(dump_file, tested_file, target_url, domain)
    return carregar_wordlist()
