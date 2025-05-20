"""
Funções de criptografia e descriptografia para suporte AES.
"""

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from base64 import b64decode
from termcolor import cprint

def decrypt_aes(ciphertext_b64, key, iv, mode=AES.MODE_CBC):
    try:
        ciphertext = b64decode(ciphertext_b64)
        cipher = AES.new(key, mode, iv)
        decrypted = cipher.decrypt(ciphertext)
        return decrypted.rstrip(b'\x00').decode('utf-8', errors='ignore')
    except Exception as e:
        cprint(f"[x] Falha na descriptografia AES: {e}", "red")
        return None

def derive_key(password, salt, length=32):
    try:
        return PBKDF2(password, salt, dkLen=length)
    except Exception as e:
        cprint(f"[x] Falha na derivação de chave: {e}", "red")
        return None
