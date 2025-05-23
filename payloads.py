import os
import json
import logging
import threading
import random
import string
from typing import Dict, Any, Optional, List, Union

class PayloadsError(Exception):
    pass

class Payloads:
    _instance = None
    _lock = threading.Lock()
    _payloads: Dict[str, Any] = {}
    _env: str = "default"
    _payloads_file: Optional[str] = None

    def __new__(cls, *args, **kwargs):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(Payloads, cls).__new__(cls)
        return cls._instance

    def load(self, payloads_file: Optional[str] = None, env: Optional[str] = None):
        """Carrega payloads de arquivo e variáveis de ambiente."""
        self._payloads_file = payloads_file or os.getenv("PAYLOADS_FILE", "payloads.json")
        self._env = env or os.getenv("PAYLOADS_ENV", "default")
        try:
            with open(self._payloads_file, "r", encoding="utf-8") as f:
                all_payloads = json.load(f)
            self._payloads = all_payloads.get(self._env, {})
        except Exception as e:
            logging.error(f"Erro ao carregar payloads: {e}")
            raise PayloadsError(f"Falha ao carregar payloads: {e}")
        self._apply_env_overrides()
        self._validate()

    def _apply_env_overrides(self):
        """Sobrescreve payloads com variáveis de ambiente."""
        for key in self._payloads:
            env_key = f"PAYLOAD_{key.upper()}"
            if env_key in os.environ:
                self._payloads[key] = os.environ[env_key]

    def _validate(self):
        """Valida payloads essenciais."""
        if not self._payloads or not isinstance(self._payloads, dict):
            raise PayloadsError("Nenhum payload carregado ou formato inválido.")

    def get(self, key: str, default: Any = None) -> Any:
        return self._payloads.get(key, default)

    def set(self, key: str, value: Any):
        self._payloads[key] = value

    def remove(self, key: str):
        if key in self._payloads:
            del self._payloads[key]

    def as_dict(self) -> Dict[str, Any]:
        return dict(self._payloads)

    def as_list(self) -> List[tuple]:
        return list(self._payloads.items())

    def export(self, path: str, fmt: str = "json"):
        """Exporta payloads para arquivo."""
        try:
            if fmt == "json":
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(self._payloads, f, indent=2)
            elif fmt == "txt":
                with open(path, "w", encoding="utf-8") as f:
                    for k, v in self._payloads.items():
                        f.write(f"{k}: {v}\n")
            else:
                raise PayloadsError("Formato de exportação não suportado")
        except Exception as e:
            logging.error(f"Erro ao exportar payloads: {e}")
            raise

    def import_payloads(self, path: str, fmt: str = "json"):
        """Importa payloads de arquivo."""
        try:
            if fmt == "json":
                with open(path, "r", encoding="utf-8") as f:
                    self._payloads = json.load(f)
            elif fmt == "txt":
                with open(path, "r", encoding="utf-8") as f:
                    for line in f:
                        if ":" in line:
                            k, v = line.strip().split(":", 1)
                            self._payloads[k.strip()] = v.strip()
            else:
                raise PayloadsError("Formato de importação não suportado")
        except Exception as e:
            logging.error(f"Erro ao importar payloads: {e}")
            raise

    def reload(self):
        """Recarrega payloads do arquivo."""
        self.load(self._payloads_file, self._env)

    def log_current(self):
        logging.info(f"Payloads atuais ({self._env}): {self._payloads}")

    def generate(self, length: int = 16, charset: str = "alphanum", prefix: str = "", suffix: str = "") -> str:
        """Gera payload dinâmico customizado."""
        if charset == "alphanum":
            chars = string.ascii_letters + string.digits
        elif charset == "hex":
            chars = string.hexdigits
        elif charset == "ascii":
            chars = string.printable
        else:
            chars = charset
        payload = ''.join(random.choice(chars) for _ in range(length))
        return f"{prefix}{payload}{suffix}"

    def mutate(self, key: str, mutation: str = "reverse") -> Any:
        """Realiza mutação avançada em um payload."""
        value = self._payloads.get(key)
        if not value:
            raise PayloadsError(f"Payload não encontrado: {key}")
        if mutation == "reverse":
            return value[::-1]
        elif mutation == "upper":
            return value.upper()
        elif mutation == "lower":
            return value.lower()
        elif mutation == "xor":
            return ''.join(chr(ord(c) ^ 0xAA) for c in value)
        else:
            raise PayloadsError("Tipo de mutação não suportado")

    def fuzz(self, key: str, count: int = 10) -> List[str]:
        """Gera variações fuzzing de um payload."""
        base = self._payloads.get(key, "")
        fuzzed = []
        for _ in range(count):
            mutated = ''.join(random.choice([c, chr(random.randint(32, 126))]) for c in base)
            fuzzed.append(mutated)
        return fuzzed

    def merge(self, extra: Union[Dict[str, Any], None]):
        """Mescla payloads extras."""
        if extra:
            self._payloads.update(extra)

# Função global para acesso rápido
def payloads(key: Optional[str] = None, default: Any = None) -> Any:
    p = Payloads()
    if not p._payloads:
        p.load()
    if key:
        return p.get(key, default)
    return p.as_dict()

# CLI para manipulação de payloads
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Gerenciador avançado de payloads para testes ofensivos/defensivos")
    parser.add_argument("--env", help="Ambiente de payloads")
    parser.add_argument("--file", help="Arquivo de payloads")
    parser.add_argument("--get", help="Payload para obter valor")
    parser.add_argument("--set", nargs=2, metavar=("KEY", "VALUE"), help="Define valor para payload")
    parser.add_argument("--remove", help="Remove payload")
    parser.add_argument("--export", nargs=2, metavar=("PATH", "FMT"), help="Exporta payloads")
    parser.add_argument("--import", dest="import_", nargs=2, metavar=("PATH", "FMT"), help="Importa payloads")
    parser.add_argument("--reload", action="store_true", help="Recarrega payloads")
    parser.add_argument("--generate", nargs="*", metavar=("LEN", "CHARSET", "PREFIX", "SUFFIX"), help="Gera payload dinâmico")
    parser.add_argument("--mutate", nargs=2, metavar=("KEY", "MUTATION"), help="Muta payload")
    parser.add_argument("--fuzz", nargs=2, metavar=("KEY", "COUNT"), help="Fuzzing de payload")
    parser.add_argument("--merge", help="Mescla payloads extras em JSON")
    args = parser.parse_args()

    p = Payloads()
    p.load(payloads_file=args.file, env=args.env)
    if args.get:
        print(p.get(args.get))
    if args.set:
        p.set(args.set[0], args.set[1])
        print(f"{args.set[0]} atualizado.")
    if args.remove:
        p.remove(args.remove)
        print(f"{args.remove} removido.")
    if args.export:
        p.export(args.export[0], args.export[1])
        print(f"Exportado para {args.export[0]} em formato {args.export[1]}")
    if args.import_:
        p.import_payloads(args.import_[0], args.import_[1])
        print(f"Importado de {args.import_[0]} em formato {args.import_[1]}")
    if args.reload:
        p.reload()
        print("Payloads recarregados.")
    if args.generate is not None:
        length = int(args.generate[0]) if len(args.generate) > 0 else 16
        charset = args.generate[1] if len(args.generate) > 1 else "alphanum"
        prefix = args.generate[2] if len(args.generate) > 2 else ""
        suffix = args.generate[3] if len(args.generate) > 3 else ""
        print(p.generate(length, charset, prefix, suffix))
    if args.mutate:
        print(p.mutate(args.mutate[0], args.mutate[1]))
    if args.fuzz:
        key = args.fuzz[0]
        count = int(args.fuzz[1])
        print(p.fuzz(key, count))
    if args.merge:
        try:
            extra = json.loads(args.merge)
            p.merge(extra)
            print("Payloads mesclados.")
        except Exception as e:
            print(f"Erro ao mesclar payloads: {e}")
    p.log_current()