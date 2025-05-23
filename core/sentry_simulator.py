import random
import time
import httpx
import uuid
import threading
from typing import List, Dict, Any, Optional
from utils.helpers import log_event

EVENT_LEVELS = ["info", "warning", "error", "critical", "fatal", "debug"]
ENVIRONMENTS = ["production", "staging", "development", "qa"]
USERS = ["tester", "admin", "user01", "user02", "guest", "api_bot"]

EXTRA_MESSAGES = [
    "Simulated error log",
    "Unhandled exception occurred",
    "Database connection lost",
    "User authentication failed",
    "API rate limit exceeded",
    "Resource not found",
    "Permission denied",
    "Timeout while processing request",
    "Invalid JWT token",
    "Suspicious activity detected"
]

class SentrySimulator:
    def __init__(self, endpoints: List[str], threads: int = 4, delay_range: tuple = (0.2, 1.5)):
        self.endpoints = endpoints
        self.threads = threads
        self.delay_range = delay_range
        self._stop_event = threading.Event()

    def simulate_traffic(self, count: int = 50, alternate: bool = True):
        log_event("sentry", f"Iniciando simulação com {self.threads} threads, {count} eventos, alternância: {alternate}")
        events_per_thread = count // self.threads
        threads = []
        for i in range(self.threads):
            t = threading.Thread(target=self._simulate_worker, args=(events_per_thread, alternate, i))
            t.start()
            threads.append(t)
        for t in threads:
            t.join()
        log_event("sentry", "Simulação de tráfego finalizada.")

    def _simulate_worker(self, count: int, alternate: bool, thread_id: int):
        for i in range(count):
            if self._stop_event.is_set():
                break
            endpoint = random.choice(self.endpoints)
            payload = self.generate_payload(alternate=alternate)
            try:
                response = httpx.post(endpoint, json=payload, timeout=5)
                log_event("sentry", f"[Thread {thread_id}] Payload {i+1}/{count} enviado para {endpoint} - Status {response.status_code}")
            except Exception as e:
                log_event("sentry", f"[Thread {thread_id}] Erro ao enviar payload: {e}")
            time.sleep(random.uniform(*self.delay_range))

    def generate_payload(self, alternate: bool = True) -> Dict[str, Any]:
        event_id = str(uuid.uuid4())
        timestamp = int(time.time())
        if alternate:
            level = random.choice(EVENT_LEVELS)
            env = random.choice(ENVIRONMENTS)
            user = random.choice(USERS)
            message = random.choice(EXTRA_MESSAGES)
            tags = {
                "env": env,
                "user": user,
                "module": random.choice(["auth", "bruteforce", "sql", "report", "cli"]),
                "session": str(uuid.uuid4())[:8]
            }
            extra = {
                "ip_address": f"192.168.{random.randint(0,255)}.{random.randint(0,255)}",
                "request_id": str(uuid.uuid4()),
                "details": {
                    "attempt": random.randint(1, 10),
                    "success": random.choice([True, False])
                }
            }
        else:
            level = "error"
            message = "Simulated error log"
            tags = {"env": "production", "user": "tester"}
            extra = {}
        return {
            "event_id": event_id,
            "message": message,
            "level": level,
            "timestamp": timestamp,
            "tags": tags,
            "extra": extra
        }

    def stop(self):
        self._stop_event.set()

def run():
    # Exemplo de endpoints, pode ser customizado via config
    endpoints = [
        "http://localhost:9000/sentry",
        "http://localhost:9001/sentry"
    ]
    simulator = SentrySimulator(endpoints=endpoints, threads=4, delay_range=(0.2, 1.2))
    simulator.simulate_traffic(count=40, alternate=True)

if __name__ == "__main__":
    run()