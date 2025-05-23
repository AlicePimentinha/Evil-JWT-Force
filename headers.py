import os
import json
import logging
import threading
from typing import Dict, Any, Optional, List, Union

class HeadersError(Exception):
    pass

class Headers:
    _instance = None
    _lock = threading.Lock()
    _headers: Dict[str, str] = {}
    _env: str = "default"
    _headers_file: Optional[str] = None

    def __new__(cls, *args, **kwargs):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(Headers, cls).__new__(cls)
        return cls._instance

    def load(self, headers_file: Optional[str] = None, env: Optional[str] = None):
        """Carrega headers de arquivo e variáveis de ambiente."""
        self._headers_file = headers_file or os.getenv("HEADERS_FILE", "headers.json")
        self._env = env or os.getenv("HEADERS_ENV", "default")
        try:
            with open(self._headers_file, "r", encoding="utf-8") as f:
                all_headers = json.load(f)
            self._headers = all_headers.get(self._env, {})
        except Exception as e:
            logging.error(f"Erro ao carregar headers: {e}")
            raise HeadersError(f"Falha ao carregar headers: {e}")
        self._apply_env_overrides()
        self._validate()

    def _apply_env_overrides(self):
        """Sobrescreve headers com variáveis de ambiente."""
        for key in self._headers:
            env_key = f"HEADER_{key.upper()}"
            if env_key in os.environ:
                self._headers[key] = os.environ[env_key]

    def _validate(self):
        """Valida headers essenciais."""
        required = ["User-Agent", "Accept"]
        for key in required:
            if key not in self._headers or not self._headers[key]:
                raise HeadersError(f"Header obrigatório ausente: {key}")

    def get(self, key: str, default: Any = None) -> Any:
        return self._headers.get(key, default)

    def set(self, key: str, value: str):
        self._headers[key] = value

    def remove(self, key: str):
        if key in self._headers:
            del self._headers[key]

    def as_dict(self) -> Dict[str, str]:
        return dict(self._headers)

    def as_list(self) -> List[tuple]:
        return list(self._headers.items())

    def add_auth(self, token: str, scheme: str = "Bearer"):
        """Adiciona header de autenticação."""
        self._headers["Authorization"] = f"{scheme} {token}"

    def export(self, path: str, fmt: str = "json"):
        """Exporta headers para arquivo."""
        try:
            if fmt == "json":
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(self._headers, f, indent=2)
            elif fmt == "env":
                with open(path, "w", encoding="utf-8") as f:
                    for k, v in self._headers.items():
                        f.write(f"{k.upper()}={v}\n")
            else:
                raise HeadersError("Formato de exportação não suportado")
        except Exception as e:
            logging.error(f"Erro ao exportar headers: {e}")
            raise

    def import_headers(self, path: str, fmt: str = "json"):
        """Importa headers de arquivo."""
        try:
            if fmt == "json":
                with open(path, "r", encoding="utf-8") as f:
                    self._headers = json.load(f)
            elif fmt == "env":
                with open(path, "r", encoding="utf-8") as f:
                    for line in f:
                        if "=" in line:
                            k, v = line.strip().split("=", 1)
                            self._headers[k] = v
            else:
                raise HeadersError("Formato de importação não suportado")
        except Exception as e:
            logging.error(f"Erro ao importar headers: {e}")
            raise

    def reload(self):
        """Recarrega headers do arquivo."""
        self.load(self._headers_file, self._env)

    def log_current(self):
        logging.info(f"Headers atuais ({self._env}): {self._headers}")

    def generate_random(self, include_auth: bool = False) -> Dict[str, str]:
        """Gera headers aleatórios para fuzzing/testes."""
        import random
        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "curl/7.68.0",
            "python-requests/2.25.1",
            "CustomAgent/1.0"
        ]
        accept_types = [
            "application/json",
            "text/html",
            "*/*"
        ]
        headers = {
            "User-Agent": random.choice(user_agents),
            "Accept": random.choice(accept_types)
        }
        if include_auth:
            headers["Authorization"] = f"Bearer {os.urandom(16).hex()}"
        return headers

    def merge(self, extra: Union[Dict[str, str], None]):
        """Mescla headers extras."""
        if extra:
            self._headers.update(extra)

# Função global para acesso rápido
def headers(key: Optional[str] = None, default: Any = None) -> Any:
    h = Headers()
    if not h._headers:
        h.load()
    if key:
        return h.get(key, default)
    return h.as_dict()

# CLI para manipulação de headers
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Gerenciador avançado de headers HTTP")
    parser.add_argument("--env", help="Ambiente de headers")
    parser.add_argument("--file", help="Arquivo de headers")
    parser.add_argument("--get", help="Header para obter valor")
    parser.add_argument("--set", nargs=2, metavar=("KEY", "VALUE"), help="Define valor para header")
    parser.add_argument("--remove", help="Remove header")
    parser.add_argument("--export", nargs=2, metavar=("PATH", "FMT"), help="Exporta headers")
    parser.add_argument("--import", dest="import_", nargs=2, metavar=("PATH", "FMT"), help="Importa headers")
    parser.add_argument("--reload", action="store_true", help="Recarrega headers")
    parser.add_argument("--random", action="store_true", help="Gera headers aleatórios")
    parser.add_argument("--merge", help="Mescla headers extras em JSON")
    args = parser.parse_args()

    h = Headers()
    h.load(headers_file=args.file, env=args.env)
    if args.get:
        print(h.get(args.get))
    if args.set:
        h.set(args.set[0], args.set[1])
        print(f"{args.set[0]} atualizado.")
    if args.remove:
        h.remove(args.remove)
        print(f"{args.remove} removido.")
    if args.export:
        h.export(args.export[0], args.export[1])
        print(f"Exportado para {args.export[0]} em formato {args.export[1]}")
    if args.import_:
        h.import_headers(args.import_[0], args.import_[1])
        print(f"Importado de {args.import_[0]} em formato {args.import_[1]}")
    if args.reload:
        h.reload()
        print("Headers recarregados.")
    if args.random:
        print(h.generate_random(include_auth=True))
    if args.merge:
        try:
            extra = json.loads(args.merge)
            h.merge(extra)
            print("Headers mesclados.")
        except Exception as e:
            print(f"Erro ao mesclar headers: {e}")
    h.log_current()