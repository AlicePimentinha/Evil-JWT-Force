#!/usr/bin/env python3
"""
Script de fuzzing para testar tokens JWT em um endpoint.
"""

import requests
import sys
from utils.helpers import generate_jwt_list
from termcolor import cprint
from utils.request_builder import build_headers

def fuzz_token(endpoint, tokens):
    for token in tokens:
        headers = build_headers(jwt=token)
        try:
            response = requests.get(endpoint, headers=headers)
            status = response.status_code
            if status == 200:
                cprint(f"[+] Token aceito: {token}", "green")
            elif status == 403:
                cprint(f"[-] Token rejeitado: {token}", "red")
            else:
                cprint(f"[?] Resposta {status} para token: {token}", "yellow")
        except Exception as e:
            cprint(f"[x] Erro durante o fuzzing: {e}", "red")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        cprint("Uso: python3 fuzz_jwt.py http://alvo.com/endpoint path/para/wordlist.txt", "red")
        sys.exit(1)

    endpoint = sys.argv[1]
    wordlist_path = sys.argv[2]

    try:
        with open(wordlist_path, "r") as f:
            tokens = [line.strip() for line in f.readlines()]
    except Exception as e:
        cprint(f"[x] Erro ao ler wordlist: {e}", "red")
        sys.exit(1)

    fuzz_token(endpoint, tokens)
