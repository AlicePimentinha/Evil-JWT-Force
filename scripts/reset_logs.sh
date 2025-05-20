#!/bin/bash

echo "🧹 Limpando logs e arquivos de saída..."
cd "$(dirname "$0")/.."

# Limpar logs
> logs/bruteforce.log
> logs/errors.log

# Limpar outputs
> output/wordlist.txt
> output/wordlist_tested.txt
> output/found_secrets.txt
> output/valid_credentials.txt
> output/fail_credentials.txt
> output/intercepted_tokens.txt

# Remover relatórios HTML antigos
rm -f reports/report.html

echo "✅ Limpeza completa."
