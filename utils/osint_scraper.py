import threading
from queue import Queue
import logging
from modules import osint_enhanced, osint_module
from .helpers import save_to_file

class AdvancedOSINTScraper:
    """
    Scraper OSINT avançado: coleta massiva, paralela e integração com módulos externos.
    """
    def __init__(self, terms, output_path="output/osint_terms.txt", max_threads=8):
        self.terms = terms
        self.output_path = output_path
        self.max_threads = max_threads
        self.results = {
            "emails": set(),
            "domains": set(),
            "usernames": set(),
            "keywords": set(),
            "links": set(),
            "leaks": set()
        }
        logging.basicConfig(filename='logs/osint_scraper.log', level=logging.INFO, format='[%(asctime)s] %(message)s')

    def _collect_from_enhanced(self, term):
        # Usa o módulo osint_enhanced para coleta massiva e paralela
        try:
            enhanced_data = osint_enhanced.osint_collect(term)
            for k in self.results:
                self.results[k].update(enhanced_data.get(k, []))
        except Exception as e:
            logging.warning(f"Erro ao coletar com osint_enhanced: {e}")

    def _collect_from_module(self, term):
        # Usa o módulo osint_module para coleta e análise
        try:
            module_scraper = osint_module.OSINTScraper()
            module_data = module_scraper.analyze_target(term)
            for k in self.results:
                self.results[k].update(module_data.get(k, []))
        except Exception as e:
            logging.warning(f"Erro ao coletar com osint_module: {e}")

    def _worker(self, q):
        while not q.empty():
            term = q.get()
            self._collect_from_enhanced(term)
            self._collect_from_module(term)
            q.task_done()

    def run(self):
        q = Queue()
        for term in self.terms:
            q.put(term)
        threads = []
        for _ in range(self.max_threads):
            t = threading.Thread(target=self._worker, args=(q,))
            t.daemon = True
            t.start()
            threads.append(t)
        q.join()
        # Salva resultados de forma organizada
        for category, items in self.results.items():
            for item in sorted(items):
                save_to_file(self.output_path, f"[{category.upper()}] {item}")
        logging.info(f"Coleta OSINT finalizada. Resultados salvos em {self.output_path}")
        return {k: list(v) for k, v in self.results.items()}