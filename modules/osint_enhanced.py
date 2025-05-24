"""
Módulo OSINT Avançado: coleta massiva e paralela de dados em domínios globais, redes sociais, .org, .gov, .edu e domínios asiáticos. Adaptado para Kali Linux.
"""

import requests
import re
import json
import logging
import threading
from queue import Queue
from bs4 import BeautifulSoup
from urllib.parse import quote_plus
import platform

# Logging robusto para ambiente Linux
logging.basicConfig(filename='logs/osint_enhanced.log', level=logging.INFO, format='[%(asctime)s] %(message)s')

SOCIAL_PLATFORMS = [
    "facebook.com", "instagram.com", "twitter.com", "x.com", "linkedin.com", "youtube.com", "tiktok.com",
    "reddit.com", "pinterest.com", "tumblr.com", "medium.com", "vk.com", "weibo.com", "bilibili.com",
    "line.me", "kakao.com", "naver.com", "qq.com", "baidu.com", "douyin.com", "zhihu.com", "telegram.org"
]

GLOBAL_DOMAINS = [
    ".com", ".org", ".gov", ".edu", ".net", ".info", ".asia", ".jp", ".cn", ".kr", ".tw", ".hk", ".sg", ".in", ".ru"
]

SEARCH_ENGINES = [
    "https://www.google.com/search?q=",
    "https://www.bing.com/search?q=",
    "https://duckduckgo.com/html/?q=",
    "https://search.yahoo.com/search?p="
]

HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0 EVIL_JWT_FORCE/1.2.0"
}

def extract_emails(text):
    return re.findall(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\\.[a-zA-Z0-9-.]+", text)

def extract_domains(text):
    return re.findall(r"https?://([a-zA-Z0-9.-]+\\.[a-zA-Z]{2,})", text)

def extract_usernames(text):
    return re.findall(r"@([a-zA-Z0-9_]{3,32})", text)

def extract_keywords(text):
    words = re.findall(r"\\b[a-zA-Z0-9_-]{5,32}\\b", text)
    return list(set(words))

def search_engine_scrape(query, limit=10):
    results = []
    for engine in SEARCH_ENGINES:
        try:
            url = f"{engine}{quote_plus(query)}"
            resp = requests.get(url, headers=HEADERS, timeout=10)
            soup = BeautifulSoup(resp.text, "html.parser")
            links = [a.get("href") for a in soup.find_all("a", href=True)]
            for link in links:
                if any(domain in link for domain in GLOBAL_DOMAINS):
                    results.append(link)
            if len(results) >= limit:
                break
        except Exception as e:
            logging.warning(f"Erro ao buscar em {engine}: {e}")
    return results[:limit]

def social_media_scrape(query):
    results = []
    for platform in SOCIAL_PLATFORMS:
        try:
            url = f"https://www.google.com/search?q=site:{platform}+{quote_plus(query)}"
            resp = requests.get(url, headers=HEADERS, timeout=10)
            soup = BeautifulSoup(resp.text, "html.parser")
            links = [a.get("href") for a in soup.find_all("a", href=True)]
            for link in links:
                if platform in link:
                    results.append(link)
        except Exception as e:
            logging.warning(f"Erro ao buscar em {platform}: {e}")
    return results

def gov_org_scrape(query):
    results = []
    for tld in [".gov", ".org", ".edu"]:
        try:
            url = f"https://www.google.com/search?q=site:{tld}+{quote_plus(query)}"
            resp = requests.get(url, headers=HEADERS, timeout=10)
            soup = BeautifulSoup(resp.text, "html.parser")
            links = [a.get("href") for a in soup.find_all("a", href=True)]
            for link in links:
                if tld in link:
                    results.append(link)
        except Exception as e:
            logging.warning(f"Erro ao buscar em {tld}: {e}")
    return results

def asia_domain_scrape(query):
    results = []
    for tld in [".asia", ".jp", ".cn", ".kr", ".tw", ".hk", ".sg", ".in"]:
        try:
            url = f"https://www.google.com/search?q=site:{tld}+{quote_plus(query)}"
            resp = requests.get(url, headers=HEADERS, timeout=10)
            soup = BeautifulSoup(resp.text, "html.parser")
            links = [a.get("href") for a in soup.find_all("a", href=True)]
            for link in links:
                if tld in link:
                    results.append(link)
        except Exception as e:
            logging.warning(f"Erro ao buscar em {tld}: {e}")
    return results

def leak_check(query):
    leaks = []
    try:
        url = f"https://www.google.com/search?q={quote_plus(query)}+site:pastebin.com"
        resp = requests.get(url, headers=HEADERS, timeout=10)
        soup = BeautifulSoup(resp.text, "html.parser")
        links = [a.get("href") for a in soup.find_all("a", href=True)]
        for link in links:
            if "pastebin.com" in link:
                leaks.append(link)
    except Exception as e:
        logging.warning(f"Erro ao buscar leaks: {e}")
    return leaks

def parallel_scrape(queries, scrape_func, results, max_threads=8):
    q = Queue()
    for query in queries:
        q.put(query)
    def worker():
        while not q.empty():
            query = q.get()
            try:
                res = scrape_func(query)
                results.extend(res)
            except Exception as e:
                logging.warning(f"Erro no worker: {e}")
            q.task_done()
    threads = []
    for _ in range(max_threads):
        t = threading.Thread(target=worker)
        t.daemon = True
        t.start()
        threads.append(t)
    q.join()

def osint_collect(target, extra_queries=None):
    """
    Coleta massiva de dados OSINT sobre o alvo.
    """
    results = {
        "emails": set(),
        "domains": set(),
        "usernames": set(),
        "keywords": set(),
        "links": set(),
        "leaks": set()
    }
    queries = [target]
    if extra_queries:
        queries.extend(extra_queries)
    search_results = []
    parallel_scrape(queries, search_engine_scrape, search_results)
    social_results = []
    parallel_scrape(queries, social_media_scrape, social_results)
    gov_org_results = []
    parallel_scrape(queries, gov_org_scrape, gov_org_results)
    asia_results = []
    parallel_scrape(queries, asia_domain_scrape, asia_results)
    leak_results = []
    parallel_scrape(queries, leak_check, leak_results)
    all_text = "\n".join(search_results + social_results + gov_org_results + asia_results + leak_results)
    results["emails"].update(extract_emails(all_text))
    results["domains"].update(extract_domains(all_text))
    results["usernames"].update(extract_usernames(all_text))
    results["keywords"].update(extract_keywords(all_text))
    results["links"].update(search_results + social_results + gov_org_results + asia_results)
    results["leaks"].update(leak_results)
    for k in results:
        results[k] = list(results[k])
    logging.info(f"OSINT coletado para {target}: {json.dumps(results)}")
    return results

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Uso: python osint_enhanced.py <alvo> [consulta extra]")
        exit(1)
    alvo = sys.argv[1]
    extra = sys.argv[2:] if len(sys.argv) > 2 else []
    dados = osint_collect(alvo, extra)
    print(json.dumps(dados, indent=2, ensure_ascii=False))