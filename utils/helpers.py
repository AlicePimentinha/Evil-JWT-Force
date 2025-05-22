"""
EVIL_JWT_FORCE Helpers Module
Funções auxiliares para manipulação de dados e operações comuns
"""

import os
import time
import random
import string
import logging
from datetime import datetime
import re
from pathlib import Path
from typing import List, Optional, Union

# Configuração do logger
logger = logging.getLogger(__name__)

def save_to_file(filepath: str, content: str) -> bool:
    """
    Salva conteúdo em um arquivo
    
    Args:
        filepath: Caminho do arquivo
        content: Conteúdo a ser salvo
        
    Returns:
        bool: True se salvou com sucesso, False caso contrário
    """
    try:
        Path(filepath).parent.mkdir(parents=True, exist_ok=True)
        with open(filepath, 'a', encoding='utf-8') as f:
            f.write(f"{content}\n")
        return True
    except Exception as e:
        logger.error(f"Erro ao salvar arquivo {filepath}: {e}")
        return False

def read_lines(filepath: str) -> List[str]:
    """
    Lê linhas de um arquivo
    
    Args:
        filepath: Caminho do arquivo
        
    Returns:
        Lista de linhas do arquivo
    """
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        logger.error(f"Erro ao ler arquivo {filepath}: {e}")
        return []

def write_lines(filepath: str, lines: List[str]) -> bool:
    """
    Escreve lista de linhas em um arquivo
    
    Args:
        filepath: Caminho do arquivo
        lines: Lista de linhas
        
    Returns:
        bool: True se salvou com sucesso, False caso contrário
    """
    try:
        Path(filepath).parent.mkdir(parents=True, exist_ok=True)
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write('\n'.join(lines))
        return True
    except Exception as e:
        logger.error(f"Erro ao escrever arquivo {filepath}: {e}")
        return False

def generate_nonce(length: int = 16) -> str:
    """
    Gera um nonce aleatório
    
    Args:
        length: Tamanho do nonce
        
    Returns:
        str: Nonce gerado
    """
    chars = string.ascii_letters + string.digits
    return ''.join(random.choice(chars) for _ in range(length))

def get_current_timestamp() -> int:
    """
    Retorna timestamp atual
    
    Returns:
        int: Timestamp atual em segundos
    """
    return int(time.time())

def formatted_time(timestamp: Optional[float] = None) -> str:
    """
    Formata timestamp em string legível
    
    Args:
        timestamp: Timestamp opcional (usa atual se None)
        
    Returns:
        str: Data/hora formatada
    """
    if timestamp is None:
        timestamp = time.time()
    return datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')

def log_format(message: str, level: str = "INFO") -> str:
    """
    Formata mensagem de log
    
    Args:
        message: Mensagem a ser formatada
        level: Nível do log
        
    Returns:
        str: Mensagem formatada
    """
    return f"[{formatted_time()}] [{level}] {message}"

def ensure_dir(directory: Union[str, Path]) -> None:
    """
    Garante que um diretório existe
    
    Args:
        directory: Caminho do diretório
    """
    Path(directory).mkdir(parents=True, exist_ok=True)

def clean_string(text: str) -> str:
    """
    Limpa uma string removendo caracteres especiais
    
    Args:
        text: Texto a ser limpo
        
    Returns:
        str: Texto limpo
    """
    return ''.join(c for c in text if c.isalnum() or c in '._-')

def is_valid_url(url: str) -> bool:
    regex = re.compile(
        r'^(?:http|https)://'  # http:// ou https://
        r'(?:\S+(?::\S*)?@)?'  # user:pass@
        r'(?:[A-Za-z0-9.-]+|\[[A-Fa-f0-9:]+\])'  # domínio
        r'(?::\d+)?'  # porta
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    return re.match(regex, url) is not None

def safe_write_file(path, content):
    try:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, "a", encoding="utf-8") as f:
            f.write(content + "\n")
    except PermissionError as e:
        from utils.logger import logger
        logger.error(f"Permissão negada ao gravar em {path}: {e}")
        raise
    except Exception as e:
        from utils.logger import logger
        logger.error(f"Erro ao gravar em {path}: {e}")
        raise