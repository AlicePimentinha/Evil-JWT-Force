import pytest
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.bruteforce import JWTBruteforcer

def test_bruteforce_success():
    token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.2jmj7l5rSw0yVb/vlWAYkK/YBwk="
    wordlist = ["wrong", "123", "admin", "hello", "secret", "password", "test", ""]
    bruteforcer = JWTBruteforcer(token, wordlist)
    bruteforcer.start()
    assert bruteforcer.success
    assert bruteforcer.key == ""