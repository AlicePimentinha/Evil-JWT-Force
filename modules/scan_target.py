#!/usr/bin/env python3
"""
Script de varredura de endpoints para encontrar pontos vulneráveis a JWT ou SQLi.
"""

import requests
from utils.request_builder import build_headers
from termcolor import cprint
import sys

def scan_url(base_url):
    endpoints = [
        "/auth/login", "/auth/validate", "/api/user/info",
        "/admin/panel", "/api/token", "/jwt/verify", "/login/check"
    ]
    vulnerable = []

    cprint(f"[*] Escaneando: {base_url}", "cyan")
    for endpoint in endpoints:
        url = base_url.rstrip("/") + endpoint
        try:
            resp = requests.get(url, headers=build_headers())
            if resp.status_code in [200, 401, 403] and 'jwt' in resp.text.lower():
                cprint(f"[+] Potencial endpoint JWT encontrado: {url}", "yellow")
                vulnerable.append(url)
        except Exception as e:
            cprint(f"[x] Erro ao conectar em {url}: {e}", "red")

    return vulnerable

if __name__ == "__main__":
    if len(sys.argv) < 2:
        cprint("Uso: python3 scan_target.py http://alvo.com", "red")
        sys.exit(1)

    base_url = sys.argv[1]
    results = scan_url(base_url)
    cprint(f"[✓] Total de possíveis alvos encontrados: {len(results)}", "green")
