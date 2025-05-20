"""
Headers HTTP usados para requisições automatizadas.
"""

DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (EVIL_JWT_FORCE)",
    "Accept": "application/json, text/plain, */*",
    "Content-Type": "application/json",
    "Connection": "keep-alive"
}

AJAX_HEADERS = {
    "X-Requested-With": "XMLHttpRequest",
    "User-Agent": "Mozilla/5.0 (EVIL_JWT_FORCE AJAX)",
    "Accept": "*/*"
}
