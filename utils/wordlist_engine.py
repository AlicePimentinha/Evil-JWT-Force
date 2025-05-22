"""
Geração e manipulação de wordlists dinâmicas.
"""

import os
from termcolor import cprint
import threading

def save_wordlist(words, filename="output/wordlist.txt"):
    try:
        os.makedirs(os.path.dirname(filename), exist_ok=True)
        with open(filename, 'w') as f:
            for word in words:
                f.write(f"{word}\n")
        cprint(f"[✓] Wordlist salva em {filename}", "green")
    except Exception as e:
        cprint(f"[x] Erro ao salvar wordlist: {e}", "red")

def generate_common_passwords():
    return [
        "admin", "123456", "password", "jwt123", "letmein",
        "eviljwt", "secretkey", "tokenforce", "bruteforce"
    ]

def atualizar_wordlists_periodicamente(intervalo=3600):
    from core.wordlist_generator import scrape_public_sites, save_wordlist
    def atualizar():
        scrape_public_sites()
        save_wordlist()
        threading.Timer(intervalo, atualizar).start()
    atualizar()

