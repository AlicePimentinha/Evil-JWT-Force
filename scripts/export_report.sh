#!/bin/bash

cd "$(dirname "$0")/.."

TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
EXPORT_DIR="exports"
FILENAME="EVIL_JWT_FORCE_REPORT_$TIMESTAMP.zip"

mkdir -p "$EXPORT_DIR"

echo "📦 Compactando logs, outputs e relatórios..."
zip -r "$EXPORT_DIR/$FILENAME" output/ logs/ reports/ config/*.txt config/*.yaml config/*.json -x "*.DS_Store"

echo "✅ Arquivo gerado: $EXPORT_DIR/$FILENAME"
