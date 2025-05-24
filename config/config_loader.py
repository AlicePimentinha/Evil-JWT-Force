import yaml
from pathlib import Path

def load_config(path="config.yaml"):
    with open(Path(__file__).parent / path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)