"""
Módulo para funções criptográficas
"""

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

def aes_decrypt(ciphertext: str, key: bytes, mode: str = 'CBC', padding: str = 'PKCS7') -> str:
    """
    Decripta texto usando AES
    
    Args:
        ciphertext: Texto cifrado em base64
        key: Chave de decriptação
        mode: Modo AES (CBC, ECB, etc)
        padding: Tipo de padding
        
    Returns:
        Texto decriptado
    """
    try:
        # Decodifica o texto cifrado de base64
        raw = base64.b64decode(ciphertext)
        
        # Configura o cipher
        if mode == 'CBC':
            iv = raw[:AES.block_size]
            cipher = AES.new(key, AES.MODE_CBC, iv)
            ciphertext = raw[AES.block_size:]
        else:
            cipher = AES.new(key, AES.MODE_ECB)
            
        # Decripta
        decrypted = cipher.decrypt(ciphertext)
        
        # Remove o padding
        if padding == 'PKCS7':
            decrypted = unpad(decrypted, AES.block_size)
            
        return decrypted.decode('utf-8')
        
    except Exception as e:
        print(f"Erro na decriptação: {e}")
        return None
    # Implementação da função
    pass