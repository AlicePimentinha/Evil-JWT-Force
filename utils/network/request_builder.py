"""
RequestBuilder - Módulo para construção de requisições HTTP
"""

import os
import sys
from pathlib import Path

# Adiciona o diretório raiz ao PYTHONPATH
root_dir = str(Path(__file__).resolve().parent.parent)
if root_dir not in sys.path:
    sys.path.append(root_dir)

import requests
import json
from typing import Dict, Optional, Union
from utils.helpers import generate_nonce, get_current_timestamp

class RequestBuilder:
    """Classe para construção de requisições HTTP com suporte a autenticação"""
    
    def __init__(self, base_url: str):
        """
        Inicializa o construtor de requisições
        
        Args:
            base_url: URL base para as requisições
        """
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        self.headers: Dict[str, str] = {}
        self.params: Dict[str, str] = {}
        self.timeout = 30
        
    def set_headers(self, headers: Dict[str, str]) -> 'RequestBuilder':
        """Adiciona headers à requisição"""
        self.headers.update(headers)
        return self
        
    def set_params(self, params: Dict[str, str]) -> 'RequestBuilder':
        """Adiciona parâmetros à requisição"""
        self.params.update(params)
        return self
        
    def set_timeout(self, timeout: int) -> 'RequestBuilder':
        """Define o timeout da requisição"""
        self.timeout = timeout
        return self
        
    def add_auth(self, auth_type: str, token: str) -> 'RequestBuilder':
        """
        Adiciona autenticação à requisição
        
        Args:
            auth_type: Tipo de autenticação (bearer, jwt, basic)
            token: Token de autenticação
        """
        auth_type = auth_type.lower()
        if auth_type in ['bearer', 'jwt', 'basic']:
            self.headers['Authorization'] = f'{auth_type.title()} {token}'
        return self
        
    def build(self) -> requests.Session:
        """
        Constrói e retorna a sessão configurada
        
        Returns:
            Session: Sessão do requests configurada
        """
        self.session.headers.update(self.headers)
        return self.session

    def request(self, method: str, endpoint: str, **kwargs) -> requests.Response:
        """
        Realiza uma requisição HTTP
        
        Args:
            method: Método HTTP (GET, POST, etc)
            endpoint: Endpoint da requisição
            **kwargs: Argumentos adicionais para a requisição
            
        Returns:
            Response: Resposta da requisição
        """
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        kwargs.setdefault('timeout', self.timeout)
        kwargs.setdefault('params', self.params)
        
        return self.session.request(method, url, **kwargs)

def build_headers(
    auth_token: Optional[str] = None,
    data_mode: str = "cipher",
    extra_headers: Optional[Dict[str, str]] = None
) -> Dict[str, str]:
    """
    Constrói os headers padrão para requisições
    
    Args:
        auth_token: Token de autenticação opcional
        data_mode: Modo de dados (cipher, plain)
        extra_headers: Headers adicionais
        
    Returns:
        Dict: Headers configurados
    """
    headers = {
        "Content-Type": "application/json",
        "x-data-mode": data_mode,
        "X-Request-Id": generate_nonce()
    }
    
    if auth_token:
        headers["Authorization"] = f"Bearer {auth_token}"
    if extra_headers:
        headers.update(extra_headers)
        
    return headers

def build_payload(
    username: str,
    password: str,
    timestamp: Optional[int] = None,
    nonce: Optional[str] = None
) -> str:
    """
    Constrói o payload para autenticação
    
    Args:
        username: Nome do usuário
        password: Senha do usuário
        timestamp: Timestamp opcional
        nonce: Nonce opcional
        
    Returns:
        str: Payload em formato JSON
    """
    data = {
        "username": username,
        "password": password,
        "timestamp": timestamp or get_current_timestamp(),
        "nonce": nonce or generate_nonce()
    }
    return json.dumps(data)