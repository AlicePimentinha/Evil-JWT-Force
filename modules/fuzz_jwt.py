#!/usr/bin/env python3
"""
Fuzzing avançado de tokens JWT em endpoints.
Inclui mutação de tokens, análise de respostas, detecção de WAF, paralelização e integração com wordlists.
"""

import requests
import sys
import threading
import queue
import time
import random
import logging
from termcolor import cprint
from utils.helpers import generate_jwt_list, mutate_jwt, analyze_jwt_response
from utils.request_builder import build_headers

logging.basicConfig(filename='logs/fuzz_jwt.log', level=logging.INFO, format='[%(asctime)s] %(message)s')

def detect_waf(response):
    waf_signatures = [
        "cloudflare", "sucuri", "incapsula", "akamai", "mod_security", "access denied", "blocked", "waf"
    ]
    text = response.text.lower()
    return any(sig in text for sig in waf_signatures) or response.status_code in [403, 406, 429]

def advanced_fuzz_token(endpoint, tokens, threads=10, delay=0.01):
    q = queue.Queue()
    results = []
    for token in tokens:
        q.put(token)

    def worker():
        while not q.empty():
            token = q.get()
            mutated_tokens = mutate_jwt(token)
            for mtoken in mutated_tokens:
                headers = build_headers(jwt=mtoken)
                try:
                    response = requests.get(endpoint, headers=headers, timeout=10)
                    status = response.status_code
                    if detect_waf(response):
                        cprint(f"[!] WAF detectado para token: {mtoken}", "magenta")
                        logging.warning(f"WAF detectado para token: {mtoken}")
                        continue
                    analysis = analyze_jwt_response(response)
                    if analysis.get("accepted"):
                        cprint(f"[+] Token aceito: {mtoken}", "green")
                        logging.info(f"Token aceito: {mtoken}")
                        results.append({"token": mtoken, "status": status, "analysis": analysis})
                    elif analysis.get("interesting"):
                        cprint(f"[?] Resposta interessante ({status}) para token: {mtoken}", "yellow")
                        logging.info(f"Resposta interessante para token: {mtoken} - {analysis}")
                    else:
                        cprint(f"[-] Token rejeitado: {mtoken}", "red")
                        logging.info(f"Token rejeitado: {mtoken}")
                except Exception as e:
                    cprint(f"[x] Erro durante o fuzzing: {e}", "red")
                    logging.error(f"Erro durante o fuzzing: {e}")
                time.sleep(delay)
            q.task_done()

    thread_list = []
    for _ in range(threads):
        t = threading.Thread(target=worker)
        t.daemon = True
        t.start()
        thread_list.append(t)

    q.join()
    return results

if __name__ == "__main__":
    if len(sys.argv) < 3:
        cprint("Uso: python3 fuzz_jwt.py http://alvo.com/endpoint path/para/wordlist.txt", "red")
        sys.exit(1)

    endpoint = sys.argv[1]
    wordlist_path = sys.argv[2]

    try:
        with open(wordlist_path, "r") as f:
            tokens = [line.strip() for line in f.readlines() if line.strip()]
    except Exception as e:
        cprint(f"[x] Erro ao ler wordlist: {e}", "red")
        sys.exit(1)

    cprint(f"[+] Iniciando fuzzing avançado em {endpoint} com {len(tokens)} tokens...", "cyan")
    results = advanced_fuzz_token(endpoint, tokens, threads=16, delay=0.005)
    cprint(f"[+] Fuzzing concluído. Tokens aceitos/interessantes: {len(results)}", "cyan")
    if results:
        with open("output/fuzz_jwt_results.json", "w", encoding="utf-8") as out:
            import json
            json.dump(results, out, indent=2)
        cprint("[+] Resultados salvos em output/fuzz_jwt_results.json", "green")