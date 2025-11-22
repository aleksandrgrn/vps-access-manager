
import logging
import sys
from app.services.ssh import connect_with_password, initialize_server

# Configure logging
logging.basicConfig(level=logging.DEBUG)

ip = "172.27.71.117"
port = 2233
username = "root"
password = "1CjGvKpbfkQ5$L"

print(f"Testing connection to {ip}:{port}...")

try:
    client, error = connect_with_password(ip, port, username, password)
    if client:
        print("✅ Connection successful!")
        client.close()
    else:
        print(f"❌ Connection failed: {error}")

    print("\nTesting initialize_server...")
    result = initialize_server(ip, port, username, password)
    print(f"Initialize result: {result}")

except Exception as e:
    print(f"❌ Exception: {e}")
