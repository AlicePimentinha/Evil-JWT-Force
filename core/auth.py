import jwt
import requests
import json
import sys
from pathlib import Path
from typing import List, Tuple  # Adicionando a importação necessária

# Corrigindo a importação usando caminho relativo
sys.path.append(str(Path(__file__).resolve().parent.parent))
from utils.helpers import save_to_file

class Authenticator:
    def __init__(self, target_url, credentials_file=None):
        self.target_url = target_url
        self.credentials_file = credentials_file
        self.session = requests.Session()
    
    def authenticate(self, username: str, password: str, auth_method: str = "jwt") -> bool:
        try:
            headers = build_headers()
            payload = build_payload(username, password)
            
            # Adiciona diferentes métodos de autenticação
            if auth_method == "basic":
                auth_string = base64.b64encode(f"{username}:{password}".encode()).decode()
                headers["Authorization"] = f"Basic {auth_string}"
            elif auth_method == "bearer":
                headers["Authorization"] = f"Bearer {password}"
            elif auth_method == "api_key":
                headers["X-API-Key"] = password
            elif auth_method == "oauth":
                headers["Authorization"] = f"OAuth {password}"
            elif auth_method == "digest":
                # Implementação do Digest Auth
                nonce = self._get_nonce()
                digest = self._calculate_digest(username, password, nonce)
                headers["Authorization"] = f"Digest {digest}"
            elif auth_method == "ntlm":
                # Implementação do NTLM
                ntlm_hash = self._calculate_ntlm(username, password)
                headers["Authorization"] = f"NTLM {ntlm_hash}"
            
            response = self.client.post(self.url, headers=headers, data=payload)
            
            if response.status_code == 200:
                self._save_credentials(username, password, valid=True)
                self._extract_jwt(response.text)
                return True
            else:
                self._save_credentials(username, password, valid=False)
                return False
                
        except Exception as e:
            print(f"Authentication error: {e}")
            return False
            
    def _save_credentials(self, username: str, password: str, valid: bool):
        file_path = VALID_CREDS_FILE if valid else INVALID_CREDS_FILE
        Path(file_path).parent.mkdir(parents=True, exist_ok=True)
        save_to_file(file_path, f"{username}:{password}")
        
    def _extract_jwt(self, response_text: str):
        try:
            data = json.loads(response_text)
            token = data.get('token') or data.get('jwt') or data.get('access_token')
            
            if not token:
                match = re.search(r'Bearer\s+([A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*)', response_text)
                if match:
                    token = match.group(1)
            
            if token:
                save_to_file("output/intercepted_tokens.txt", token)
                
        except json.JSONDecodeError:
            pass

def save_cred(username: str, password: str, valid: bool):
    path = VALID_CREDS_FILE if valid else INVALID_CREDS_FILE
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a") as f:
        f.write(f"{username}:{password}\n")

def parse_creds_from_response(response_text: str) -> List[Tuple[str, str]]:
    pattern_json = r'"username"\s*:\s*"?(\w+)"?.+?"password"\s*:\s*"?(\w+)"?'
    pattern_text = r"(admin|user\d{1,4})[:|=](pass\w+)"
    json_matches = re.findall(pattern_json, response_text)
    text_matches = re.findall(pattern_text, response_text)
    return json_matches + text_matches

def try_login(base_url: str, username: str, password: str) -> bool:
    login_url = f"{base_url}/api/auth/login"
    payload = {"username": username, "password": password}
    try:
        r = httpx.post(login_url, json=payload, headers=HEADERS, timeout=10)
        if r.status_code == 200 and "token" in r.text:
            save_cred(username, password, valid=True)
            return True
        else:
            save_cred(username, password, valid=False)
            return False
    except Exception as e:
        print(f"[ERROR] Failed login: {e}")
        return False

def auto_discovery(base_url: str, endpoints: List[str]) -> List[Tuple[str, str]]:
    found_creds = []
    for endpoint in endpoints:
        try:
            url = f"{base_url}/{endpoint.lstrip('/')}"
            r = httpx.get(url, headers=HEADERS, timeout=10)
            found = parse_creds_from_response(r.text)
            for u, p in found:
                if try_login(base_url, u, p):
                    found_creds.append((u, p))
        except Exception as e:
            print(f"[ERROR] Could not fetch {endpoint}: {e}")
    return found_creds

    def _calculate_digest(self, username: str, password: str, nonce: str) -> str:
        ha1 = hashlib.md5(f"{username}:{password}".encode()).hexdigest()
        ha2 = hashlib.md5(b"POST:/auth").hexdigest()
        return hashlib.md5(f"{ha1}:{nonce}:{ha2}".encode()).hexdigest()
        
    def _calculate_ntlm(self, username: str, password: str) -> str:
        return hashlib.new('md4', password.encode('utf-16le')).hexdigest()
