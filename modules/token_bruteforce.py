"""
Módulo para força bruta em diferentes tipos de tokens
"""

import jwt
import requests
from utils.logger import logger
from utils.request_builder import build_headers

class TokenBruteforcer:
    def __init__(self, target_url, token_type="jwt"):
        self.target_url = target_url
        self.token_type = token_type.lower()
        self.success_patterns = {
            "jwt": self._check_jwt,
            "oauth": self._check_oauth,
            "basic": self._check_basic_auth,
            "bearer": self._check_bearer,
            "verification": self._check_verification
        }
        
    def _check_jwt(self, response):
        return response.status_code == 200 and "jwt" in response.headers.get("Authorization", "").lower()
        
    def _check_oauth(self, response):
        return response.status_code == 200 and "oauth" in response.headers.get("Authorization", "").lower()
        
    def _check_basic_auth(self, response):
        return response.status_code == 200 and "basic" in response.headers.get("Authorization", "").lower()
        
    def _check_bearer(self, response):
        return response.status_code == 200 and "bearer" in response.headers.get("Authorization", "").lower()
        
    def _check_verification(self, response):
        return response.status_code == 200 and "verified" in response.text.lower()

    async def attack(self, wordlist_path, threads=10):
        logger.info(f"Iniciando ataque de força bruta em tokens do tipo: {self.token_type}")
        # Implementação do ataque