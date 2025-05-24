import os
import json
import threading
import hashlib
import base64
import random
import string
import time
from typing import Any, Dict, List, Optional, Union

def save_to_file(data: Union[str, bytes, dict, list], filepath: str, mode: str = "w", encoding: Optional[str] = "utf-8") -> None:
    if isinstance(data, (dict, list)):
        with open(filepath, mode, encoding=encoding) as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    elif isinstance(data, bytes):
        with open(filepath, "wb") as f:
            f.write(data)
    else:
        with open(filepath, mode, encoding=encoding) as f:
            f.write(str(data))

def read_lines(filepath: str, encoding: Optional[str] = "utf-8") -> List[str]:
    if not os.path.exists(filepath):
        return []
    with open(filepath, "r", encoding=encoding) as f:
        return [line.rstrip("\n") for line in f]

def write_lines(filepath: str, lines: list, encoding: str = "utf-8") -> None:
    with open(filepath, "w", encoding=encoding) as f:
        for line in lines:
            f.write(f"{line}\n")

def load_from_file(filepath: str, mode: str = "r", encoding: Optional[str] = "utf-8") -> Any:
    if not os.path.exists(filepath):
        return None
    if filepath.endswith(".json"):
        with open(filepath, mode, encoding=encoding) as f:
            return json.load(f)
    elif "b" in mode:
        with open(filepath, mode) as f:
            return f.read()
    else:
        with open(filepath, mode, encoding=encoding) as f:
            return f.read()

def random_string(length: int = 12, charset: str = string.ascii_letters + string.digits) -> str:
    return ''.join(random.choices(charset, k=length))

def hash_string(data: str, algorithm: str = "sha256") -> str:
    h = hashlib.new(algorithm)
    h.update(data.encode("utf-8"))
    return h.hexdigest()

def base64_encode(data: Union[str, bytes]) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return base64.b64encode(data).decode("utf-8")

def base64_decode(data: str) -> bytes:
    return base64.b64decode(data)

def thread_run(target, args=(), kwargs=None, daemon=True) -> threading.Thread:
    if kwargs is None:
        kwargs = {}
    t = threading.Thread(target=target, args=args, kwargs=kwargs, daemon=daemon)
    t.start()
    return t

def safe_mkdir(path: str) -> None:
    os.makedirs(path, exist_ok=True)

def is_json(data: str) -> bool:
    try:
        json.loads(data)
        return True
    except Exception:
        return False

def chunk_list(lst: List[Any], size: int) -> List[List[Any]]:
    return [lst[i:i+size] for i in range(0, len(lst), size)]

def retry(func, retries: int = 3, delay: float = 1.0, exceptions: tuple = (Exception,)):
    for attempt in range(retries):
        try:
            return func()
        except exceptions:
            if attempt == retries - 1:
                raise
            time.sleep(delay)