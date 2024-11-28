import json
from collections import defaultdict
from datetime import datetime, timedelta
import mysql.connector
# MySQL database connection details
DB_CONFIG = {
   "host": "grafana-test.c0lyfsbxamho.us-east-1.rds.amazonaws.com",
   "user": "admin",
   "password": "MyAdminPassword",
   "database": "grafana"
}
# Thresholds configuration
THRESHOLDS = {
   "high_volume_single_ip": 100,
   "high_volume_multiple_ips": 500,
   "user_agent_anomalies": ["", "curl", "wget"],
   "suspicious_paths": ["/admin", "/config", "/.env"],
   "sql_injection_patterns": ["'", '"', "union", "select", "drop", "--"],
   "slowloris_incomplete_requests": 50,
   "brute_force_login": 10,
   "file_inclusion_patterns": ["..", "/etc/passwd", "boot.ini"],
   "query_string_length": 300,
   "referrer_anomalies": ["", "spam-site.com"]
}
# Initialize counters
ip_request_counts = defaultdict(list)
suspicious_logs = []
def detect_attacks(file):
    for line in file:
        try:
            log = json.loads(line)
            timestamp = datetime.strptime(log["timestamp"], "%Y-%m-%dT%H:%M:%S.%fZ")
            ip = log.get("log", "").split()[0]
            path = log.get("log", "").split()[6]
            query = path.split("?")[1] if "?" in path else ""
            user_agent = log.get("log", "").split('"')[-2] if '"' in log.get("log", "") else "No User Agent"
            # Extract referrer safely
            try:
                referer = log.get("log", "").split('"')[-4]
            except IndexError:
                referer = ""
            # Log request by IP
            ip_request_counts[ip].append(timestamp)
            # Detect suspicious activities
            if user_agent in THRESHOLDS["user_agent_anomalies"]:
                suspicious_logs.append((log, "Suspicious User-Agent"))
                return (log, "Suspicious User-Agent")
            elif any(restricted in path for restricted in THRESHOLDS["suspicious_paths"]):
                suspicious_logs.append((log, "Restricted Path Access"))
                return (log, "Restricted Path Access")
            elif referer in THRESHOLDS["referrer_anomalies"]:
                suspicious_logs.append((log, "Suspicious Referrer"))
                return (log, "Suspicious Referrer")
            elif any(keyword in path.lower() for keyword in THRESHOLDS["sql_injection_patterns"]):
                # Detect SQL injection patterns
                suspicious_logs.append((log, "Possible SQL Injection"))
                return (log, "Possible SQL Injection")
            # Detect file inclusion attempts
            if any(pattern in query for pattern in THRESHOLDS["file_inclusion_patterns"]):
                suspicious_logs.append((log, "File Inclusion Attempt"))
                return (log, "File Inclusion Attempt")
            # Detect long or unusual query strings
            if len(query) > THRESHOLDS["query_string_length"]:
                suspicious_logs.append((log, "Unusual Query String Length"))
                return (log, "Unusual Query String Length")

            else:
                suspicious_logs.append((log, None))
                return (log, None)

        except json.JSONDecodeError:
            print("Invalid JSON format in log:", line)
def save_to_mysql(suspicious_logs):
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()
        for log, attack_type in suspicious_logs:
            timestamp = datetime.strptime(log["timestamp"], "%Y-%m-%dT%H:%M:%S.%fZ")
            ip = log.get("log", "").split()[0]
            user_agent = log.get("log", "").split('"')[-2] if '"' in log.get("log", "") else "No User Agent Data"
            cursor.execute(
                "INSERT INTO suspicious_activity (timestamp, request_ip, user_agent, attack_type) VALUES (%s, %s, %s, %s)",
                (timestamp, ip, user_agent, attack_type)
            )
        conn.commit()
    except mysql.connector.Error as err:
        print("Error:", err)
    finally:
        if conn.is_connected():
            cursor.close()
            conn.close()
           
if(__name__ == '__main__'):
    # Run detection and save results
    log_file = "19_58.json"  # Replace with your log file
    suspicious_logs = detect_attacks(log_file)
    save_to_mysql(suspicious_logs)
    print("Suspicious activity logs saved to MySQL.")

