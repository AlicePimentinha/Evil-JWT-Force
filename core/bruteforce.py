import jwt
import requests
import json
import sys
from pathlib import Path

# Corrigindo o caminho para importação
sys.path.append(str(Path(__file__).resolve().parent.parent))
from utils.crypto import aes_decrypt
from utils.helpers import save_to_file

class JWTBruteforcer:
    def __init__(self, token, wordlist=None):
        self.token = token
        self.wordlist = wordlist
        self.success = False
        self.key = None

    def start(self):
        if not self.wordlist:
            print("No wordlist provided")
            return
        
        for word in self.wordlist:
            try:
                decoded = jwt.decode(self.token, word, algorithms=['HS256'])
                self.success = True
                self.key = word
                print(f"[+] Found valid key: {word}")
                print(f"[+] Decoded token: {decoded}")
                save_to_file('found_key.txt', word)
                break
            except jwt.InvalidTokenError:
                continue
            except Exception as e:
                print(f"[-] Error: {e}")
                continue

        if not self.success:
            print("[-] No valid key found")

if __name__ == "__main__":
    # Example usage
    token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.123"
    wordlist = ["test", "password", "secret"]
    
    bruteforcer = JWTBruteforcer(token, wordlist)
    bruteforcer.start()