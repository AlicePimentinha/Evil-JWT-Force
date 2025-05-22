"""
Módulo para rotação e gerenciamento de proxies
"""

import requests
import random
import sys
from typing import Dict, Optional, List
from pathlib import Path

def setup_path():
    """Configura o PYTHONPATH para incluir o diretório raiz do projeto"""
    root = Path(__file__).resolve().parent.parent
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))

setup_path()

from utils.helpers import read_lines

class ProxyRotator:
    _instance = None
    
    def __new__(cls, proxy_file: Optional[str] = None):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance.proxy_file = proxy_file
            cls._instance.proxies = []
            cls._instance.current_index = 0
            cls._instance._initialize_proxies()
        return cls._instance
    
    def __init__(self, proxy_file: Optional[str] = None) -> None:
        """
        Inicializa o rotacionador de proxies
        
        Args:
            proxy_file: Caminho para o arquivo de proxies
        """
        self.proxy_file: str = proxy_file
        self.proxies: List[str] = []
        self.current_index: int = 0
        self._initialize_proxies()
    
    def _initialize_proxies(self) -> None:
        """Inicializa a lista de proxies se um arquivo for fornecido"""
        if self.proxy_file:
            self.load_proxies()
    
    def load_proxies(self) -> None:
        """Carrega a lista de proxies do arquivo configurado"""
        try:
            if not Path(self.proxy_file).exists():
                print(f"Arquivo de proxies não encontrado: {self.proxy_file}")
                self.proxies = []
                return
                
            self.proxies = read_lines(self.proxy_file)
            if not self.proxies:
                print("Arquivo de proxies está vazio")
        except Exception as e:
            print(f"Erro ao carregar proxies: {str(e)}")
            self.proxies = []
    
    def _format_proxy(self, proxy: str) -> Dict[str, str]:
        """
        Formata um proxy para o formato de dicionário
        
        Args:
            proxy: String contendo o endereço do proxy
            
        Returns:
            Dicionário com as URLs formatadas do proxy
        """
        return {
            "http": f"http://{proxy}",
            "https": f"https://{proxy}"
        }
    
    def get_next_proxy(self) -> Optional[Dict[str, str]]:
        """
        Retorna o próximo proxy da lista
        
        Returns:
            Dicionário com as URLs do proxy ou None se não houver proxies
        """
        if not self.proxies:
            return None
            
        proxy = self.proxies[self.current_index]
        self.current_index = (self.current_index + 1) % len(self.proxies)
        
        return self._format_proxy(proxy)
    
    def get_random_proxy(self) -> Optional[Dict[str, str]]:
        """
        Retorna um proxy aleatório da lista
        
        Returns:
            Dicionário com as URLs do proxy ou None se não houver proxies
        """
        if not self.proxies:
            return None
            
        proxy = random.choice(self.proxies)
        return self._format_proxy(proxy)