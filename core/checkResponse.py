import json
import matplotlib.pyplot as plt
from datetime import datetime
import subprocess
import sys

def generate_line_graph(x, y, title, xlabel, ylabel):
    plt.plot(x, y)
    plt.xlabel(xlabel)
    plt.ylabel(ylabel)
    plt.title(title)
    plt.xticks(rotation=45)
    plt.show()

# Check if --location attribute is provided
if '--location' not in sys.argv:
    print("Please provide the --location attribute.")
    sys.exit(1)

# Get the file location from the command-line argument
location_index = sys.argv.index('--location')
if location_index + 1 >= len(sys.argv):
    print("Please provide a file path after the --location attribute.")
    sys.exit(1)

file_location = sys.argv[location_index + 1]

# Open and read the JSON file
with open(file_location, 'r') as file:
    json_data = file.read()

# Parse the JSON data
data = json.loads(json_data)

# Extract data for response time chart
timestamps = []
response_times = []

for log in data['logs']:
    timestamp = datetime.strptime(log['Timestamp'], '%Y-%m-%d %H:%M:%S')
    response_time = log['Response_time']
    timestamps.append(timestamp)
    response_times.append(response_time)

# Generate line chart for response time
generate_line_graph(timestamps, response_times, 'Response Time', 'Timestamp', 'Response Time')

# Extract data for response code chart
response_codes = []

for log in data['logs']:
    timestamp = datetime.strptime(log['Timestamp'], '%Y-%m-%d %H:%M:%S')
    response_code = log['Response_code']
    timestamps.append(timestamp)
    response_codes.append(response_code)

# Generate line chart for response code
generate_line_graph(timestamps, response_codes, 'Response Code', 'Timestamp', 'Response Code')

# Execute test.py script with --location attribute
subprocess.call(['pythonw', 'checkResponse.py', '--location', file_location])
