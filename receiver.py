from flask import Flask, request, jsonify
from detection2 import detect_attacks, save_to_mysql


app = Flask(__name__)



@app.route('/logs', methods=['POST'])
def receive_logs():
  # Get JSON payload from Fluent Bit
  log_data = request.get_json()
#   print(f"Received log: {log_data}")
  
  # Process logs here if needed
  # For example, write to a file or a database
  suspicious_logs = detect_attacks(log_data)
  save_to_mysql(suspicious_logs)
  print(suspicious_logs)

  # Send a response back to Fluent Bit
  return jsonify({"status": "received"}), 200



if __name__ == '__main__':
  app.run(host='0.0.0.0', port=8080)
