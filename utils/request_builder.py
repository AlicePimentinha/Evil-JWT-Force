# utils/request_builder.py

import json
from utils.helpers import generate_nonce, get_current_timestamp

def build_headers(auth_token=None, data_mode="cipher", extra_headers=None):
    headers = {
        "Content-Type": "application/json",
        "x-data-mode": data_mode,
        "X-Request-Id": generate_nonce()
    }
    if auth_token:
        headers["Authorization"] = f"Bearer {auth_token}"
    if extra_headers:
        headers.update(extra_headers)
    return headers

def build_payload(username, password, timestamp=None, nonce=None):
    if not timestamp:
        timestamp = get_current_timestamp()
    if not nonce:
        nonce = generate_nonce()
    data = {
        "username": username,
        "password": password,
        "timestamp": timestamp,
        "nonce": nonce
    }
    return json.dumps(data)
