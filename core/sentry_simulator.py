# core/sentry_simulator.py

import random
import time
import httpx
import uuid
from utils.helpers import log_event

class SentrySimulator:
    def __init__(self, endpoint_url):
        self.endpoint = endpoint_url

    def simulate_traffic(self, count=10):
        for i in range(count):
            payload = self.generate_payload()
            try:
                response = httpx.post(self.endpoint, json=payload)
                log_event("sentry", f"Payload {i + 1}/{count}: Status {response.status_code}")
                time.sleep(random.uniform(0.5, 2.0))
            except Exception as e:
                log_event("sentry", f"Error sending payload: {e}")

    def generate_payload(self):
        return {
            "event_id": str(uuid.uuid4()),
            "message": "Simulated error log",
            "level": random.choice(["info", "warning", "error", "critical"]),
            "timestamp": int(time.time()),
            "tags": {"env": "production", "user": "tester"}
        }
