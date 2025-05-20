import base64
import os
import logging
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from hashlib import pbkdf2_hmac


def try_decrypt(ciphertext_b64, passphrases, salts, ivs):
    """
    Tenta descriptografar o conteúdo cifrado usando diferentes combinações de:
    - senhas (passphrases)
    - sal (salts)
    - vetor de inicialização (ivs)

    O modo AES-CBC e os paddings PKCS7 são assumidos como padrão.
    
    Parâmetros:
        ciphertext_b64 (str): Texto cifrado em base64
        passphrases (list): Lista de possíveis senhas
        salts (list): Lista de valores de sal (salt) em bytes
        ivs (list): Lista de vetores de inicialização (IVs) em bytes

    Retorna:
        Listagem de tentativas bem-sucedidas com a combinação utilizada.
    """
    resultados = []

    try:
        ciphertext = base64.b64decode(ciphertext_b64)
    except Exception as e:
        logging.error(f"Erro ao decodificar Base64: {e}")
        return []

    for passphrase in passphrases:
        for salt in salts:
            key = pbkdf2_hmac('sha256', passphrase.encode(), salt, 100000, dklen=32)
            for iv in ivs:
                try:
                    cipher = AES.new(key, AES.MODE_CBC, iv)
                    decrypted = cipher.decrypt(ciphertext)
                    plaintext = unpad(decrypted, AES.block_size).decode('utf-8')

                    resultados.append({
                        'passphrase': passphrase,
                        'salt': salt.hex(),
                        'iv': iv.hex(),
                        'plaintext': plaintext
                    })
                except Exception as e:
                    logging.debug(f"Falha com senha={passphrase}, salt={salt.hex()}, iv={iv.hex()} -> {e}")
                    continue

    return resultados


if __name__ == "__main__":
    # Teste com dados fictícios
    dummy_ciphertext = "b2z3reZ2p++6J+8OnvAjqQ=="  # apenas um exemplo base64
    dummy_passphrases = ["admin", "password123", "evilforce"]
    dummy_salts = [os.urandom(8) for _ in range(3)]
    dummy_ivs = [os.urandom(16) for _ in range(3)]

    results = try_decrypt(dummy_ciphertext, dummy_passphrases, dummy_salts, dummy_ivs)

    for r in results:
        print("[+] Sucesso:", r)

    if not results:
        print("[-] Nenhuma combinação obteve sucesso.")
