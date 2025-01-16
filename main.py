import logging
from discovery.discovery import NetworkDiscovery

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

def main():
    discovery = NetworkDiscovery()
    devices = discovery.discover()

    print("\nDiscovered Devices:")
    for device in devices:
        print(f"IP: {device.ip}, MAC: {device.mac}, Hostname: {device.hostname}")

if __name__ == "__main__":
    main()
