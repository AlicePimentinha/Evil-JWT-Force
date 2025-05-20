# utils/helpers.py

import uuid
import time
from datetime import datetime

def generate_nonce():
    return str(uuid.uuid4())

def get_current_timestamp():
    return int(time.time())

def formatted_time():
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')

def log_format(module, message):
    return f"[{formatted_time()}] [{module}] {message}"

def save_to_file(path, content):
    with open(path, "a", encoding="utf-8") as f:
        f.write(f"{content}\n")

def read_lines(filepath):
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            return [line.strip() for line in f.readlines()]
    except FileNotFoundError:
        return []

def write_lines(filepath, lines):
    with open(filepath, "w", encoding="utf-8") as f:
        f.writelines([line + "\n" for line in lines])
