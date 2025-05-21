import requests
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor
from fake_useragent import UserAgent
import time
import re
from utils.logger import logger

class OSINTScraper:
    def __init__(self, target_domain=None):
        self.target_domain = target_domain
        self.ua = UserAgent()
        self.collected_data = set()
        self.social_platforms = {
            'facebook.com': 'Facebook',
            'linkedin.com': 'LinkedIn',
            'twitter.com': 'Twitter',
            'instagram.com': 'Instagram',
            'github.com': 'GitHub',
            'gitlab.com': 'GitLab',
            'reddit.com': 'Reddit',
            'youtube.com': 'YouTube',
            'tiktok.com': 'TikTok',
            'threads.net': 'Threads'
        }
        
    def search_duckduckgo(self, query, max_results=100):
        base_url = "https://html.duckduckgo.com/html/"
        params = {
            'q': query,
            'kl': 'us-en'
        }
        try:
            response = requests.get(
                base_url,
                params=params,
                headers={'User-Agent': self.ua.random}
            )
            soup = BeautifulSoup(response.text, 'html.parser')
            results = soup.find_all('div', class_='result__body')
            return [result.get_text() for result in results[:max_results]]
        except Exception as e:
            logger.error(f"Erro ao buscar no DuckDuckGo: {e}")
            return []

    def search_gov_org_sites(self, query):
        sites = [
            'site:.gov', 'site:.org', 'site:.edu',
            'site:.mil', 'site:.int', 'site:.gc.ca',
            'site:.gov.uk', 'site:.europa.eu'
        ]
        results = []
        for site in sites:
            search_query = f"{query} {site}"
            results.extend(self.search_duckduckgo(search_query))
            time.sleep(2)  # Respeitar limites de taxa
        return results

    def scrape_social_media(self, term):
        results = []
        for platform_url in self.social_platforms.keys():
            query = f"site:{platform_url} {term}"
            platform_results = self.search_duckduckgo(query, max_results=20)
            results.extend(platform_results)
            time.sleep(2)
        return results

    def extract_potential_secrets(self, text):
        patterns = {
            'emails': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            'api_keys': r'[a-zA-Z0-9_-]{20,40}',
            'jwt_patterns': r'eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*',
            'usernames': r'(?:user|username|login|admin)[=:]\s*["\']?([a-zA-Z0-9_-]+)',
            'urls': r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+'
        }
        
        findings = {}
        for pattern_name, pattern in patterns.items():
            matches = re.findall(pattern, text)
            if matches:
                findings[pattern_name] = list(set(matches))
        return findings

    def analyze_target(self, terms, output_file="output/osint_results.txt"):
        all_results = []
        
        # Busca em sites governamentais e organizacionais
        gov_org_results = self.search_gov_org_sites(terms)
        all_results.extend(gov_org_results)
        
        # Busca em redes sociais
        social_results = self.scrape_social_media(terms)
        all_results.extend(social_results)
        
        # Extrair e analisar resultados
        findings = {}
        for result in all_results:
            extracted = self.extract_potential_secrets(result)
            for key, values in extracted.items():
                if key not in findings:
                    findings[key] = set()
                findings[key].update(values)
        
        # Salvar resultados
        with open(output_file, 'w', encoding='utf-8') as f:
            for category, items in findings.items():
                f.write(f"\n=== {category.upper()} ===\n")
                for item in sorted(items):
                    f.write(f"{item}\n")
        
        return findings