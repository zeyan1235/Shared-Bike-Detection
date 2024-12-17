import requests

# Replace with the actual IP address of your loudspeaker
loudspeaker_ip = "192.168.0.103"  # Example IP address
command = "mp3=00046"

# Construct the URL
url = f"http://{loudspeaker_ip}/?command={command}"

try:
    # Send the HTTP GET request
    response = requests.get(url)
    
    # Check the response
    if response.status_code == 200:
        print(f"Command sent successfully: {command}")
        print(f"Response from loudspeaker: {response.text}")
    else:
        print(f"Failed to send command. HTTP status code: {response.status_code}")
except requests.exceptions.RequestException as e:
    print(f"Error sending command: {e}")
