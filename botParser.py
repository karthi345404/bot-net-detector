import json
from collections import defaultdict
from datetime import datetime, timedelta

# Configuration for attack thresholds
THRESHOLDS = {
    "high_volume_single_ip": 100,  # Requests per minute from a single IP
    "high_volume_multiple_ips": 500,  # Total requests per minute
    "user_agent_anomalies": ["", "curl", "wget"],  # Suspicious User-Agents
    "suspicious_paths": ["/admin", "/config", "/.env"],  # Common restricted paths
    "sql_injection_patterns": ["'", '"', "union", "select", "drop", "--"],  # Basic SQL keywords
    "slowloris_incomplete_requests": 50,  # Incomplete requests from a single IP
    "brute_force_login": 10,  # Login attempts within a minute from a single IP
    "file_inclusion_patterns": ["..", "/etc/passwd", "boot.ini"],  # Common file inclusion patterns
    "query_string_length": 300,  # Query string length threshold
    "referrer_anomalies": ["", "spam-site.com"],  # Suspicious referrers
}

# Initialize counters
ip_request_counts = defaultdict(list)
login_attempt_counts = defaultdict(list)
slowloris_counts = defaultdict(int)
suspicious_logs = []
overall_request_counts = []

# Detect attacks
def detect_attacks(log_file):
    with open(log_file, "r") as file:
        for line in file:
            try:
                log = json.loads(line)
                timestamp = datetime.strptime(log["timestamp"], "%Y-%m-%dT%H:%M:%S.%fZ")
                ip = log.get("log", "").split()[0]
                path = log.get("log", "").split()[6]
                query = path.split("?")[1] if "?" in path else ""
                user_agent = log.get("log", "").split('"')[-2] if '"' in log.get("log", "") else ""
                referer = log.get("log", "").split('"')[-4] if '"' in log.get("log", "") else ""

                # Log request by IP
                ip_request_counts[ip].append(timestamp)

                # Detect slowloris (incomplete requests)
                if "incomplete" in log.get("status", "").lower():
                    slowloris_counts[ip] += 1
                    if slowloris_counts[ip] > THRESHOLDS["slowloris_incomplete_requests"]:
                        suspicious_logs.append((log, "Slowloris Attack"))

                # Detect brute force login attempts
                if "/login" in path:
                    login_attempt_counts[ip].append(timestamp)

                # Detect unusual User-Agent
                if user_agent in THRESHOLDS["user_agent_anomalies"]:
                    suspicious_logs.append((log, "Suspicious User-Agent"))

                # Detect access to restricted paths
                if any(restricted in path for restricted in THRESHOLDS["suspicious_paths"]):
                    suspicious_logs.append((log, "Restricted Path Access"))

                # Detect SQL injection patterns
                if any(keyword in path.lower() for keyword in THRESHOLDS["sql_injection_patterns"]):
                    suspicious_logs.append((log, "Possible SQL Injection"))

                # Detect file inclusion attempts
                if any(pattern in query for pattern in THRESHOLDS["file_inclusion_patterns"]):
                    suspicious_logs.append((log, "File Inclusion Attempt"))

                # Detect long or unusual query strings
                if len(query) > THRESHOLDS["query_string_length"]:
                    suspicious_logs.append((log, "Unusual Query String Length"))

                # Detect suspicious referrer headers
                if referer in THRESHOLDS["referrer_anomalies"]:
                    suspicious_logs.append((log, "Suspicious Referrer"))

            except json.JSONDecodeError:
                print("Invalid JSON format in log:", line)

    # Analyze for high request rates
    analyze_request_rates()
    analyze_brute_force_attempts()

    # Print suspicious logs
    for log, reason in suspicious_logs:
        print(f"Suspicious activity detected: {reason} - Log: {log}")

def analyze_request_rates():
    # Detect high volume requests from a single IP
    for ip, timestamps in ip_request_counts.items():
        timestamps = sorted(timestamps)
        for i in range(len(timestamps)):
            if i + THRESHOLDS["high_volume_single_ip"] < len(timestamps):
                if (
                    timestamps[i + THRESHOLDS["high_volume_single_ip"]] 
                    - timestamps[i] 
                ) <= timedelta(minutes=1):
                    print(f"High request volume from IP {ip}")

    # Detect high volume requests overall
    overall_request_counts.sort()
    for i in range(len(overall_request_counts)):
        if i + THRESHOLDS["high_volume_multiple_ips"] < len(overall_request_counts):
            if (
                overall_request_counts[i + THRESHOLDS["high_volume_multiple_ips"]]
                - overall_request_counts[i]
            ) <= timedelta(minutes=1):
                print("High request volume from multiple IPs")

def analyze_brute_force_attempts():
    # Detect brute force login attempts
    for ip, timestamps in login_attempt_counts.items():
        timestamps = sorted(timestamps)
        for i in range(len(timestamps)):
            if i + THRESHOLDS["brute_force_login"] < len(timestamps):
                if (
                    timestamps[i + THRESHOLDS["brute_force_login"]] 
                    - timestamps[i] 
                ) <= timedelta(minutes=1):
                    print(f"Brute force login attempt detected from IP {ip}")

# Run the detection
log_file = "56_52.json"  # Replace with your log file name
detect_attacks(log_file)