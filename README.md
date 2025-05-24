# EVIL_JWT_FORCE
Ferramenta avançada para análise, fuzzing, brute force e exploração de JWT (JSON Web Token), com suporte a múltiplos algoritmos, ataques de força bruta, fuzzing de payloads, injeção SQL, OSINT e geração de relatórios.

## Descrição Geral
O EVIL_JWT_FORCE é uma suíte ofensiva para pentesters, bug hunters e profissionais de segurança, focada em ataques e análise de tokens JWT. Permite automatizar ataques de força bruta, fuzzing de algoritmos, exploração de vulnerabilidades em endpoints autenticados via JWT, além de realizar OSINT e gerar relatórios detalhados.

## Funcionalidades
- Força Bruta de Segredos JWT: Testa listas de palavras-chave para descobrir segredos de tokens.
- Fuzzing de Algoritmos: Testa diferentes algoritmos de assinatura (HS256, RS256, none, etc) para identificar implementações inseguras.
- Injeção SQL em JWT: Explora endpoints vulneráveis a SQLi via payloads customizados.
- Interceptação e Manipulação de Tokens: Captura, decodifica, edita e reenvia tokens JWT.
- Geração de Wordlists Customizadas: Cria listas de palavras-chave baseadas em padrões comuns e informações OSINT.
- OSINT Integrado: Coleta informações públicas sobre alvos para enriquecer ataques.
- Relatórios Detalhados: Gera relatórios em HTML com resultados dos ataques, credenciais encontradas e tokens válidos.
- Interface CLI e GUI: Uso via linha de comando ou interface gráfica (Python).
- Logs e Exportação de Resultados: Salva logs, tokens interceptados, credenciais válidas e falhas para análise posterior.
- Automação de Ataques: Scripts para execução automatizada de ataques e integração com outras ferramentas.
## Instalação
### Linux
1. Extraia o projeto e acesse o diretório.
2. Instale as dependências com pip3 install -r requirements.txt ou execute python3 install_deps.py .
3. Execute a ferramenta via CLI ou GUI.

## Uso
- CLI: Permite execução de ataques, fuzzing, injeção SQL, OSINT e geração de relatórios por linha de comando.
- GUI: Interface gráfica intuitiva para configuração e execução dos módulos.
- Integração com scripts de automação, captura de tráfego em tempo real, manipulação de VPN e controle de ambiente.
## Arquitetura do Projeto
```
EVIL_JWT_FORCE/
├── core/                # Núcleo da 
ferramenta (CLI, brute force, fuzzing, 
SQLi)
├── modules/             # Módulos 
auxiliares (cripto, osint, scanner, etc)
├── config/              # Configurações, 
payloads, headers, wordlists
├── gui/                 # Interface 
gráfica (Python)
├── output/              # Resultados, 
tokens, credenciais, logs
├── reports/             # Relatórios HTML
├── utils/               # Utilitários 
(helpers, logger, network)
├── scripts/             # Scripts de 
automação e exportação
├── testes/              # Testes 
automatizados
├── requirements.txt     # Dependências 
Python
├── main.py              # Inicializador 
principal
└── EVIL_JWT_FORCE.bat   # Inicializador 
Windows
```
## Módulos Principais
- core/bruteforce.py: Ataques de força bruta em segredos JWT.
- core/fuzz_jwt.py: Fuzzing de algoritmos e payloads.
- core/sql_injector.py: Injeção SQL em endpoints autenticados.
- core/auth.py: Manipulação e validação de tokens.
- modules/osint_enhanced.py: Coleta OSINT automatizada.
- modules/crypto_utils.py: Funções criptográficas auxiliares.
- gui/interface.py: Interface gráfica.
- utils/logger.py: Sistema de logs detalhados.
- output/: Armazena resultados, tokens interceptados e credenciais.
## Requisitos
- Python 3.7+
- Bibliotecas listadas em requirements.txt
- Sistemas suportados: Linux, Windows
## Contribuição
Contribuições são bem-vindas! Abra issues ou pull requests para sugerir melhorias, reportar bugs ou adicionar funcionalidades.

## Licença
Este projeto está licenciado sob os termos da licença MIT. Veja o arquivo LICENSE para mais detalhes.
