# utils/osint_scraper.py

import requests
from bs4 import BeautifulSoup
import re
import random
from utils.helpers import save_to_file

class OSINTScraper:
    def __init__(self, terms, output_path="output/osint_terms.txt"):
        self.terms = terms
        self.output_path = output_path
        self.headers = {
            "User-Agent": "Mozilla/5.0"
        }

    def duckduckgo_search(self, term):
        url = f"https://html.duckduckgo.com/html/?q={term}+site:.gov+OR+site:.org+OR+facebook.com+OR+reddit.com+OR+youtube.com"
        try:
            res = requests.get(url, headers=self.headers, timeout=10)
            soup = BeautifulSoup(res.text, "html.parser")
            links = soup.find_all("a", attrs={"class": "result__a"})
            found = []
            for link in links:
                text = link.text
                found.extend(re.findall(r"[a-zA-Z0-9_.+-]{4,}@?[a-zA-Z0-9_.-]{4,}", text))
            return list(set(found))
        except Exception as e:
            print(f"[OSINT] Erro ao buscar por '{term}': {e}")
            return []

    def run(self):
        all_found = set()
        for term in self.terms:
            print(f"[OSINT] Buscando informações para: {term}")
            found = self.duckduckgo_search(term)
            for item in found:
                if 4 < len(item) < 50:
                    all_found.add(item)
        for result in sorted(all_found):
            save_to_file(self.output_path, result)
        return list(all_found)
