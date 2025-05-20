"""
Funções auxiliares para parsing, criação e manipulação de JWTs.
"""

import jwt
import base64
from termcolor import cprint
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from config.constants import JWT_ALGORITHMS

def decode_jwt(token: str, verify_signature=False, key=None, algorithm=None):
    try:
        if verify_signature and key:
            return jwt.decode(token, key, algorithms=[algorithm] if algorithm else JWT_ALGORITHMS)
        return jwt.decode(token, options={"verify_signature": False})
    except Exception as e:
        cprint(f"[x] Erro ao decodificar JWT: {e}", "red")
        return None

def extract_parts(token: str):
    try:
        header, payload, signature = token.split('.')
        return {
            "header": base64.urlsafe_b64decode(header + '==').decode(),
            "payload": base64.urlsafe_b64decode(payload + '==').decode(),
            "signature": signature
        }
    except Exception as e:
        cprint(f"[x] Token inválido: {e}", "red")
        return None

def generate_token(payload: dict, secret: str, algorithm: str = JWT_ALGORITHM):
    try:
        return jwt.encode(payload, secret, algorithm=algorithm)
    except Exception as e:
        cprint(f"[x] Error generating JWT: {e}", "red")
        return None

def generate_rsa_keypair():
    try:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        public_key = private_key.public_key()
        
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return private_pem, public_pem
    except Exception as e:
        cprint(f"[x] Erro ao gerar par de chaves RSA: {e}", "red")
        return None, None

def generate_ec_keypair():
    try:
        private_key = ec.generate_private_key(ec.SECP256K1())
        public_key = private_key.public_key()
        
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return private_pem, public_pem
    except Exception as e:
        cprint(f"[x] Erro ao gerar par de chaves EC: {e}", "red")
        return None, None

def create_jwt(payload, key, algorithm='HS256'):
    try:
        if algorithm in ['RS256', 'PS256']:
            if isinstance(key, tuple):
                key = key[0]  # Use private key for signing
        elif algorithm == 'ES256':
            if isinstance(key, tuple):
                key = key[0]  # Use private key for signing
                
        token = jwt.encode(payload, key, algorithm=algorithm)
        return token
    except Exception as e:
        cprint(f"[x] Erro ao criar JWT: {e}", "red")
        return None
