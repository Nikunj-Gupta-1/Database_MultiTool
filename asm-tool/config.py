import json
from pathlib import Path

VERSION = "1.1.0"
BASE_DIR = Path(__file__).parent
OUTPUT_DIR = BASE_DIR / "output"
OUTPUT_DIR.mkdir(exist_ok=True)
CONFIG_FILE = BASE_DIR / "config.json"

DEFAULT_CONFIG = {
    "lmstudio_host": "http://localhost:1234",
    "lmstudio_model": "local-model",
    "ollama_host": "http://localhost:11434",
    "ollama_model": "llama3",
    "default_ports": "80,443,8080,8443,22,21,25,3306,3389,6379,9200",
    "provider": "lmstudio"
}

def load_config():
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE) as f:
                data = json.load(f)
                return {**DEFAULT_CONFIG, **data}
        except Exception:
            return DEFAULT_CONFIG.copy()
    return DEFAULT_CONFIG.copy()

def save_config(config_data):
    try:
        with open(CONFIG_FILE, "w") as f:
            json.dump(config_data, f, indent=2)
        return True
    except Exception:
        return False

config = load_config()

def update_config(new_config):
    config.clear()
    config.update(new_config)
    save_config(config)
