"""
EVIL_JWT_FORCE Helpers Module
Funções auxiliares avançadas para manipulação de dados, arquivos, validação e operações comuns.
"""

import os
import time
import random
import string
import logging
from datetime import datetime
import re
from pathlib import Path
from typing import List, Optional, Union, Any

logger = logging.getLogger("utils.helpers")

def save_to_file(filepath: str, content: str, mode: str = 'a', encoding: str = 'utf-8') -> bool:
    """
    Salva conteúdo em um arquivo de forma segura e atômica.
    """
    try:
        Path(filepath).parent.mkdir(parents=True, exist_ok=True)
        tmp_path = str(filepath) + ".tmp"
        with open(tmp_path, mode, encoding=encoding) as f:
            f.write(f"{content}\n")
        os.replace(tmp_path, filepath)
        return True
    except Exception as e:
        logger.error(f"Erro ao salvar arquivo {filepath}: {e}")
        return False

def read_lines(filepath: str, encoding: str = 'utf-8') -> List[str]:
    """
    Lê linhas de um arquivo, ignorando linhas vazias e espaços.
    """
    try:
        with open(filepath, 'r', encoding=encoding) as f:
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        logger.error(f"Erro ao ler arquivo {filepath}: {e}")
        return []

def write_lines(filepath: str, lines: List[str], encoding: str = 'utf-8') -> bool:
    """
    Escreve uma lista de linhas em um arquivo, sobrescrevendo o conteúdo.
    """
    try:
        Path(filepath).parent.mkdir(parents=True, exist_ok=True)
        with open(filepath, 'w', encoding=encoding) as f:
            f.write('\n'.join(lines) + '\n')
        return True
    except Exception as e:
        logger.error(f"Erro ao escrever arquivo {filepath}: {e}")
        return False

def generate_nonce(length: int = 16, charset: Optional[str] = None) -> str:
    """
    Gera um nonce aleatório seguro.
    """
    if not charset:
        charset = string.ascii_letters + string.digits
    return ''.join(random.SystemRandom().choice(charset) for _ in range(length))

def get_current_timestamp(ms: bool = False) -> int:
    """
    Retorna timestamp atual em segundos ou milissegundos.
    """
    return int(time.time() * 1000) if ms else int(time.time())

def formatted_time(timestamp: Optional[float] = None, fmt: str = '%Y-%m-%d %H:%M:%S') -> str:
    """
    Formata timestamp em string legível.
    """
    if timestamp is None:
        timestamp = time.time()
    return datetime.fromtimestamp(timestamp).strftime(fmt)

def log_format(message: str, level: str = "INFO") -> str:
    """
    Formata mensagem de log com timestamp e nível.
    """
    return f"[{formatted_time()}] [{level.upper()}] {message}"

def ensure_dir(directory: Union[str, Path]) -> None:
    """
    Garante que um diretório existe.
    """
    Path(directory).mkdir(parents=True, exist_ok=True)

def clean_string(text: str, keep: str = '._-') -> str:
    """
    Limpa uma string removendo caracteres especiais, mantendo apenas alfanuméricos e caracteres permitidos.
    """
    return ''.join(c for c in text if c.isalnum() or c in keep)

def is_valid_url(url: str) -> bool:
    """
    Valida URLs HTTP/HTTPS, incluindo IPv6, portas, autenticação e domínios internacionais.
    """
    regex = re.compile(
        r'^(https?://)'  # http:// ou https://
        r'(([\w\-\.]+(:[\w\-\.]+)?@)?'  # user:pass@
        r'((([A-Za-z0-9\-]+\.)+[A-Za-z]{2,}|localhost)|'  # domínio
        r'(\[[A-Fa-f0-9:]+\])))'  # IPv6
        r'(:\d{1,5})?'  # porta
        r'([/?#][^\s]*)?$',  # caminho, query, fragmento
        re.IGNORECASE
    )
    if not url or len(url) > 2048:
        return False
    if not re.match(regex, url):
        return False
    # Validação extra de porta
    match = re.search(r':(\d{1,5})', url)
    if match:
        port = int(match.group(1))
        if port < 1 or port > 65535:
            return False
    return True

def safe_write_file(path: Union[str, Path], content: str, encoding: str = "utf-8") -> None:
    """
    Escreve conteúdo em arquivo de forma segura, com tratamento de exceções e logging.
    """
    try:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, "a", encoding=encoding) as f:
            f.write(content + "\n")
    except PermissionError as e:
        logger.error(f"Permissão negada ao gravar em {path}: {e}")
        raise
    except Exception as e:
        logger.error(f"Erro ao gravar em {path}: {e}")
        raise

def random_string(length: int = 12, charset: Optional[str] = None) -> str:
    """
    Gera uma string aleatória segura.
    """
    if not charset:
        charset = string.ascii_letters + string.digits
    return ''.join(random.SystemRandom().choice(charset) for _ in range(length))

def slugify(text: str) -> str:
    """
    Converte texto em slug seguro para URLs e arquivos.
    """
    text = text.lower()
    text = re.sub(r'[^a-z0-9]+', '-', text)
    return text.strip('-')

def human_size(size_bytes: int) -> str:
    """
    Converte bytes em string legível (KB, MB, GB).
    """
    if size_bytes == 0:
        return "0B"
    size_name = ("B", "KB", "MB", "GB", "TB")
    i = int(min(len(size_name) - 1, (size_bytes.bit_length() - 1) // 10))
    p = 1 << (i * 10)
    s = round(size_bytes / p, 2)
    return f"{s} {size_name[i]}"

def atomic_write(filepath: str, content: str, encoding: str = "utf-8") -> bool:
    """
    Escreve arquivo de forma atômica para evitar corrupção.
    """
    try:
        tmp_path = str(filepath) + ".tmp"
        with open(tmp_path, "w", encoding=encoding) as f:
            f.write(content)
        os.replace(tmp_path, filepath)
        return True
    except Exception as e:
        logger.error(f"Erro em atomic_write para {filepath}: {e}")
        return False

def touch(filepath: Union[str, Path]) -> None:
    """
    Cria arquivo vazio se não existir, atualiza timestamp se existir.
    """
    Path(filepath).parent.mkdir(parents=True, exist_ok=True)
    Path(filepath).touch(exist_ok=True)

def remove_file(filepath: Union[str, Path]) -> bool:
    """
    Remove arquivo com segurança.
    """
    try:
        Path(filepath).unlink(missing_ok=True)
        return True
    except Exception as e:
        logger.error(f"Erro ao remover arquivo {filepath}: {e}")
        return False

def list_files(directory: Union[str, Path], pattern: str = "*") -> List[str]:
    """
    Lista arquivos em diretório com suporte a glob.
    """
    try:
        return [str(f) for f in Path(directory).glob(pattern) if f.is_file()]
    except Exception as e:
        logger.error(f"Erro ao listar arquivos em {directory}: {e}")
        return []

def merge_files(input_files: List[Union[str, Path]], output_file: Union[str, Path]) -> bool:
    """
    Mescla múltiplos arquivos em um único arquivo de saída.
    """
    try:
        with open(output_file, "w", encoding="utf-8") as outfile:
            for fname in input_files:
                with open(fname, "r", encoding="utf-8") as infile:
                    outfile.write(infile.read() + "\n")
        return True
    except Exception as e:
        logger.error(f"Erro ao mesclar arquivos em {output_file}: {e}")
        return False

def save_to_output(content: str, filename: str = "output.txt", mode: str = "a", encoding: str = "utf-8") -> bool:
    """
    Salva conteúdo no diretório 'output' de forma segura.
    """
    output_dir = Path("output")
    output_dir.mkdir(parents=True, exist_ok=True)
    file_path = output_dir / filename
    try:
        with open(file_path, mode, encoding=encoding) as f:
            f.write(content + "\n")
        return True
    except Exception as e:
        logger.error(f"Erro ao salvar no output: {e}")
        return False

def list_files(directory: Union[str, Path], pattern: str = "*") -> List[str]:
    """
    Lista arquivos em diretório com suporte a glob.
    """
    try:
        return [str(f) for f in Path(directory).glob(pattern) if f.is_file()]
    except Exception as e:
        logger.error(f"Erro ao listar arquivos em {directory}: {e}")
        return []

def merge_files(input_files: List[Union[str, Path]], output_file: Union[str, Path]) -> bool:
    """
    Mescla múltiplos arquivos em um único arquivo de saída.
    """
    try:
        with open(output_file, "w", encoding="utf-8") as outfile:
            for fname in input_files:
                with open(fname, "r", encoding="utf-8") as infile:
                    outfile.write(infile.read() + "\n")
        return True
    except Exception as e:
        logger.error(f"Erro ao mesclar arquivos em {output_file}: {e}")
        return False