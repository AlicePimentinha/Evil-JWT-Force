#!/bin/bash

echo "🔁 Iniciando modo automático do EVIL_JWT_FORCE..."
cd "$(dirname "$0")/.."

# Ativa ambiente virtual se existir
if [ -d "venv" ]; then
    echo "🔄 Ativando ambiente virtual..."
    source venv/bin/activate
fi

# Executa CLI no modo automático
python3 core/cli.py --auto

echo "✅ Execução automática concluída."
