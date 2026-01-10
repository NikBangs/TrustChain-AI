# logger.py – Advanced logging utility for TrustChain AI

import os
import json
import csv
from datetime import datetime

LOG_DIR = "logs"
JSON_LOG_FILE = os.path.join(LOG_DIR, "evaluations.log")
CSV_LOG_FILE = os.path.join(LOG_DIR, "evaluations.csv")
DEBUG_LOG_FILE = os.path.join(LOG_DIR, "debug.log")

os.makedirs(LOG_DIR, exist_ok=True)


def log_evaluation_entry(domain, score, risk, criteria):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = {
        "timestamp": timestamp,
        "domain": domain,
        "trust_score": score,
        "risk": risk,
        "criteria": criteria
    }
    
    # Append to JSON log
    with open(JSON_LOG_FILE, "a") as f:
        f.write(json.dumps(entry) + "\n")

    # Append to CSV log
    with open(CSV_LOG_FILE, "a", newline='') as f:
        writer = csv.writer(f)
        if f.tell() == 0:
            writer.writerow(["timestamp", "domain", "trust_score", "risk", "criteria"])
        writer.writerow([timestamp, domain, score, risk, json.dumps(criteria)])


def log_debug(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(DEBUG_LOG_FILE, "a") as f:
        f.write(f"[{timestamp}] {message}\n")


def get_recent_logs(n=10):
    entries = []
    if not os.path.exists(JSON_LOG_FILE):
        return entries
    with open(JSON_LOG_FILE, "r") as f:
        for line in f:
            try:
                entries.append(json.loads(line))
            except:
                continue
    return entries[-n:]
