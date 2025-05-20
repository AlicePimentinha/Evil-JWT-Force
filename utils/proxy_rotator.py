# utils/proxy_rotator.py

import random
from utils.helpers import read_lines

class ProxyRotator:
    def __init__(self, proxy_file="config/proxies.txt"):
        self.proxies = read_lines(proxy_file)
        self.index = 0

    def get_next_proxy(self):
        if not self.proxies:
            return None
        proxy = self.proxies[self.index]
        self.index = (self.index + 1) % len(self.proxies)
        return {
            "http://": f"http://{proxy}",
            "https://": f"http://{proxy}",
        }

    def get_random_proxy(self):
        if not self.proxies:
            return None
        proxy = random.choice(self.proxies)
        return {
            "http://": f"http://{proxy}",
            "https://": f"http://{proxy}",
        }
