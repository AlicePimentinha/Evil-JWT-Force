import base64
import os
import logging
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad, pad
from hashlib import pbkdf2_hmac, sha256, md5
from itertools import product, chain

logging.basicConfig(filename='logs/aes_decrypt.log', level=logging.INFO, format='[%(asctime)s] %(message)s')

MODES = {
    "CBC": AES.MODE_CBC,
    "CFB": AES.MODE_CFB,
    "OFB": AES.MODE_OFB,
    "ECB": AES.MODE_ECB,
    "CTR": AES.MODE_CTR
}

def mutate_passphrases(passphrases):
    mutations = set()
    for p in passphrases:
        mutations.add(p)
        mutations.add(p.lower())
        mutations.add(p.upper())
        mutations.add(p.capitalize())
        mutations.add(p[::-1])
        mutations.add(p + "123")
        mutations.add("123" + p)
        mutations.add(p + "!")
        mutations.add(p + "@")
        mutations.add(p + "#")
        mutations.add(p + "$")
        mutations.add(p + "2024")
        mutations.add(p.replace("a", "@"))
        mutations.add(p.replace("o", "0"))
        mutations.add(p.replace("i", "1"))
        mutations.add(p.replace("e", "3"))
        mutations.add(sha256(p.encode()).hexdigest())
        mutations.add(md5(p.encode()).hexdigest())
    return list(mutations)

def try_decrypt(ciphertext_b64, passphrases, salts, ivs, modes=None, key_lengths=(16, 24, 32)):
    resultados = []
    try:
        ciphertext = base64.b64decode(ciphertext_b64)
    except Exception as e:
        logging.error(f"Erro ao decodificar Base64: {e}")
        return []

    if not modes:
        modes = ["CBC", "CFB", "OFB", "ECB"]

    passphrases = mutate_passphrases(passphrases)

    for passphrase in passphrases:
        for salt in salts:
            for key_len in key_lengths:
                try:
                    key = pbkdf2_hmac('sha256', passphrase.encode(), salt, 100000, dklen=key_len)
                except Exception as e:
                    logging.debug(f"Falha ao derivar chave: {e}")
                    continue
                for mode_name in modes:
                    mode = MODES.get(mode_name)
                    if not mode:
                        continue
                    iv_iter = ivs if mode != AES.MODE_ECB else [b'']
                    for iv in iv_iter:
                        try:
                            if mode == AES.MODE_ECB:
                                cipher = AES.new(key, mode)
                            elif mode == AES.MODE_CTR:
                                cipher = AES.new(key, mode, nonce=iv[:8])
                            else:
                                cipher = AES.new(key, mode, iv=iv)
                            decrypted = cipher.decrypt(ciphertext)
                            # Tenta diferentes paddings
                            try:
                                plaintext = unpad(decrypted, AES.block_size).decode('utf-8')
                            except Exception:
                                try:
                                    plaintext = decrypted.decode('utf-8')
                                except Exception:
                                    continue
                            if is_printable(plaintext):
                                resultados.append({
                                    'passphrase': passphrase,
                                    'salt': salt.hex(),
                                    'iv': iv.hex() if iv else "",
                                    'mode': mode_name,
                                    'key_length': key_len,
                                    'plaintext': plaintext
                                })
                                logging.info(f"Sucesso: senha={passphrase}, salt={salt.hex()}, iv={iv.hex() if iv else ''}, modo={mode_name}, keylen={key_len}")
                        except Exception as e:
                            logging.debug(f"Falha com senha={passphrase}, salt={salt.hex()}, iv={iv.hex() if iv else ''}, modo={mode_name}, keylen={key_len} -> {e}")
                            continue
    return resultados

def is_printable(s):
    return all(32 <= ord(c) < 127 or c in '\r\n\t' for c in s)

def load_wordlist(filepath):
    if not os.path.exists(filepath):
        return []
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        return [line.strip() for line in f if line.strip()]

def brute_force_aes(ciphertext_b64, wordlist_files, salts, ivs, modes=None):
    all_passphrases = set()
    for file in wordlist_files:
        all_passphrases.update(load_wordlist(file))
    return try_decrypt(ciphertext_b64, list(all_passphrases), salts, ivs, modes)

def decrypt_with_known_key(ciphertext_b64, key, iv=None, mode="CBC"):
    try:
        ciphertext = base64.b64decode(ciphertext_b64)
        mode_val = MODES.get(mode, AES.MODE_CBC)
        if mode_val == AES.MODE_ECB:
            cipher = AES.new(key, mode_val)
        elif mode_val == AES.MODE_CTR:
            cipher = AES.new(key, mode_val, nonce=iv[:8])
        else:
            cipher = AES.new(key, mode_val, iv=iv)
        decrypted = cipher.decrypt(ciphertext)
        try:
            plaintext = unpad(decrypted, AES.block_size).decode('utf-8')
        except Exception:
            plaintext = decrypted.decode('utf-8')
        if is_printable(plaintext):
            return plaintext
    except Exception as e:
        logging.error(f"Erro na descriptografia direta: {e}")
    return None

def decrypt_aes(ciphertext_b64, passphrases, salts, ivs, wordlist_files=None, modes=None):
    resultados = []
    if wordlist_files:
        resultados.extend(brute_force_aes(ciphertext_b64, wordlist_files, salts, ivs, modes))
    resultados.extend(try_decrypt(ciphertext_b64, passphrases, salts, ivs, modes))
    return resultados