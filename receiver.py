from flask import Flask, request, jsonify



app = Flask(__name__)



@app.route('/logs', methods=['POST'])
def receive_logs():
  # Get JSON payload from Fluent Bit
  log_data = request.get_json()
  print(f"Received log: {log_data}")
  
  # Process logs here if needed
  # For example, write to a file or a database



  # Send a response back to Fluent Bit
  return jsonify({"status": "received"}), 200



if __name__ == '__main__':
  app.run(host='0.0.0.0', port=8080)
