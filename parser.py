import json
from collections import defaultdict
from datetime import datetime, timedelta


def detect_attacks(log_file):
    with open(log_file, "r") as file:
        for line in file:
            try:
                log = json.loads(line)
                # print(log)
                logs = log.get("log", "").split()
                print(logs)
                print("List by Split ''")
                referer = log.get("log", "").split('"')
                print(referer)
            except json.JSONDecodeError:
                print("Invalid JSON format in log:", line)
# Run the detection
log_file = "37_29.json"  # Replace with your log file name
detect_attacks(log_file)