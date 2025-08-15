import json
from datetime import datetime
import os

LOG_FILE = "config_history.json"

def log_config(ip: str, username: str, config: str):
    entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "ip": ip,
        "username": username,
        "config": config
    }

    # Load existing history
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r") as f:
            history = json.load(f)
    else:
        history = []

    # Append new entry
    history.append(entry)

    # Save back to file
    with open(LOG_FILE, "w") as f:
        json.dump(history, f, indent=2)
