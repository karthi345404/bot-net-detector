import re
import json
from collections import defaultdict
from datetime import datetime, timedelta
import mysql.connector
from apachelogs import LogParser, COMBINED

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
#    "referrer_anomalies": ["", "spam-site.com"]
}
# Initialize counters
ip_request_counts = defaultdict(list)
suspicious_logs = []
def detect_attacks(file):
    for line in file:
        try:
            log = line
            if(line.get("log").find("[ssl:info]") != -1):
                continue
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
            elif any(restricted in path for restricted in THRESHOLDS["suspicious_paths"]):
                suspicious_logs.append((log, "Restricted Path Access"))
            # elif referer in THRESHOLDS["referrer_anomalies"]:
            #     suspicious_logs.append((log, "Suspicious Referrer"))
            elif any(keyword in path.lower() for keyword in THRESHOLDS["sql_injection_patterns"]):
                # Detect SQL injection patterns
                suspicious_logs.append((log, "Possible SQL Injection"))
            # Detect file inclusion attempts
            if any(pattern in query for pattern in THRESHOLDS["file_inclusion_patterns"]):
                suspicious_logs.append((log, "File Inclusion Attempt"))
            # Detect long or unusual query strings
            if len(query) > THRESHOLDS["query_string_length"]:
                suspicious_logs.append((log, "Unusual Query String Length"))

            else:
                suspicious_logs.append((log, None))
            return suspicious_logs
        except json.JSONDecodeError:
            print("Invalid JSON format in log:", line)
            
def save_suspicious_logs_to_mysql(suspicious_logs):
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()
        for log, attack_type in suspicious_logs:
            timestamp = datetime.strptime(log["timestamp"], "%Y-%m-%dT%H:%M:%S.%fZ")
            output = parse_httpd_log_2(log)
            if(output is None):
                continue
            request_line = output.request_line.split(" ")
            cursor.execute(
                "INSERT INTO suspicious_activity (timestamp, request_ip, user_agent, attack_type, http_method, path, protocol, status, size, referrer) VALUES (%s, %s, %s, %s)",
                (output.request_time_fields.timestamp, output.request_host, output.headers_in["User-Agent"], attack_type, request_line[0], request_line[1], request_line[2], )
            )
        conn.commit()
    except mysql.connector.Error as err:
        print("Error:", err)
    finally:
        if conn.is_connected():
            cursor.close()
            conn.close()
            

def parse_httpd_log(log_entry):
    # Regular expression to match the log entry fields
    log_pattern = (
        r'(?P<ip>\S+) '  # IP Address
        r'- - '  # Dash placeholders
        r'\[(?P<datetime>[^\]]+)\] '  # Datetime
        r'"(?P<method>\S+) '  # HTTP Method
        r'(?P<path>[^\s]+) '  # Path
        r'(?P<protocol>[^\"]+)" '  # Protocol
        r'(?P<status>\d{3}) '  # Status Code
        r'(?P<size>\d+|-) '  # Size of the response
        r'"(?P<referrer>[^\"]*)" '  # Referrer
        r'"(?P<user_agent>[^\"]*)"'  # User-Agent
    )
    
    # Parse the log entry
    match = re.match(log_pattern, log_entry)
    if match:
        return match.groupdict()
    else:
        raise ValueError("Log entry does not match expected format.")

def parse_httpd_log_2(log_entry):
    try: 
        parser = LogParser(COMBINED)
        output = parser.parse(log_entry)
        return output
    except: 
        return None
        

if(__name__ == '__main__'):
    # Run detection and save results
    # log_file = "19_58.json"  # Replace with your log file
    # suspicious_logs = detect_attacks(log_file)
    # save_suspicious_logs_to_mysql(suspicious_logs)
    # print("Suspicious activity logs saved to MySQL.")
    print(parse_httpd_log_2('103.16.69.193 - - [28/Nov/2024:18:27:38 +0000] "GET /app/img/bridge.svg HTTP/2.0" 200 5603'))

