import os
import json
import threading
import logging
from typing import Any, Dict, Optional

class SettingsError(Exception):
    pass

class Settings:
    _instance = None
    _lock = threading.Lock()
    _config: Dict[str, Any] = {}
    _env: str = "development"
    _config_file: Optional[str] = None

    def __new__(cls, *args, **kwargs):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(Settings, cls).__new__(cls)
        return cls._instance

    def load(self, config_file: Optional[str] = None, env: Optional[str] = None):
        """Carrega configurações do arquivo e variáveis de ambiente."""
        self._config_file = config_file or os.getenv("SETTINGS_FILE", "settings.json")
        self._env = env or os.getenv("APP_ENV", "development")
        try:
            with open(self._config_file, "r", encoding="utf-8") as f:
                all_config = json.load(f)
            self._config = all_config.get(self._env, {})
        except Exception as e:
            logging.error(f"Erro ao carregar configurações: {e}")
            raise SettingsError(f"Falha ao carregar configurações: {e}")
        self._apply_env_overrides()
        self._validate()

    def _apply_env_overrides(self):
        """Sobrescreve configurações com variáveis de ambiente."""
        for key in self._config:
            env_key = f"APP_{key.upper()}"
            if env_key in os.environ:
                self._config[key] = os.environ[env_key]

    def _validate(self):
        """Valida as configurações essenciais."""
        required = ["SECRET_KEY", "DATABASE_URL"]
        for key in required:
            if key not in self._config or not self._config[key]:
                raise SettingsError(f"Configuração obrigatória ausente: {key}")

    def get(self, key: str, default: Any = None) -> Any:
        return self._config.get(key, default)

    def set(self, key: str, value: Any):
        self._config[key] = value

    def reload(self):
        """Recarrega as configurações do arquivo."""
        self.load(self._config_file, self._env)

    def export(self, path: str, fmt: str = "json"):
        """Exporta as configurações para um arquivo."""
        try:
            if fmt == "json":
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(self._config, f, indent=2)
            elif fmt == "env":
                with open(path, "w", encoding="utf-8") as f:
                    for k, v in self._config.items():
                        f.write(f"{k.upper()}={v}\n")
            else:
                raise SettingsError("Formato de exportação não suportado")
        except Exception as e:
            logging.error(f"Erro ao exportar configurações: {e}")
            raise

    def as_dict(self) -> Dict[str, Any]:
        return dict(self._config)

    def log_current(self):
        logging.info(f"Configuração atual ({self._env}): {self._config}")

# Função global para acesso rápido
def settings(key: Optional[str] = None, default: Any = None) -> Any:
    s = Settings()
    if not s._config:
        s.load()
    if key:
        return s.get(key, default)
    return s.as_dict()

# CLI para manipulação de configurações
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Gerenciador avançado de configurações")
    parser.add_argument("--env", help="Ambiente de configuração")
    parser.add_argument("--file", help="Arquivo de configuração")
    parser.add_argument("--get", help="Chave para obter valor")
    parser.add_argument("--set", nargs=2, metavar=("KEY", "VALUE"), help="Define valor para chave")
    parser.add_argument("--export", nargs=2, metavar=("PATH", "FMT"), help="Exporta configurações")
    parser.add_argument("--reload", action="store_true", help="Recarrega configurações")
    args = parser.parse_args()

    s = Settings()
    s.load(config_file=args.file, env=args.env)
    if args.get:
        print(s.get(args.get))
    if args.set:
        s.set(args.set[0], args.set[1])
        print(f"{args.set[0]} atualizado.")
    if args.export:
        s.export(args.export[0], args.export[1])
        print(f"Exportado para {args.export[0]} em formato {args.export[1]}")
    if args.reload:
        s.reload()
        print("Configurações recarregadas.")
    s.log_current()