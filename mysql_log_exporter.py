import json
import mysql.connector
# MySQL connection details
db_config = {
   "host": "your-aws-mysql-endpoint",
   "user": "your-username",
   "password": "your-password",
   "database": "your-database"
}
# Load JSON file
json_file = "path/to/your/log.json"
# Connect to MySQL
connection = mysql.connector.connect(**db_config)
cursor = connection.cursor()
# Parse JSON file and insert into the table
with open(json_file, "r") as file:
   logs = json.load(file)
   for log in logs:  # Assuming the JSON file contains a list of log objects
       query = """
           INSERT INTO logs (log_time, log_level, message, additional_data)
           VALUES (%s, %s, %s, %s)
       """
       cursor.execute(query, (
           log.get("log_time"),
           log.get("log_level"),
           log.get("message"),
           json.dumps(log.get("additional_data"))  # Convert dictionary to JSON string
       ))
# Commit and close connection
connection.commit()
cursor.close()
connection.close()
print("Logs inserted successfully!")